#!/usr/bin/env python3
"""
Edifice Gateway - Modbus (RTU/TCP) -> Gobardhan SCADA telemetry API

  * Reads ALL configuration (devices, tags, poll intervals, API settings) from PostgreSQL
  * One poller thread per enabled Modbus device, using that device's poll_interval_ms
  * Latest tag values are kept in `tag_values`; a publisher thread builds the flat
    JSON payload every `publish_interval_s`, signs it (HMAC-SHA256) and POSTs it
  * Every request + response is stored in `api_log`; per-device diagnostics in
    `device_diagnostics`
  * Config is re-read from the DB every cycle -> edit the tables, no restart needed

Environment (see /etc/edge-gateway/gateway.env, written by setup_db.sh):
  GW_DB_HOST GW_DB_PORT GW_DB_NAME GW_DB_USER GW_DB_PASSWORD
  GW_LOG_LEVEL     (default INFO)
  GW_CONFIG_SYNC_S (default 10)   how often to look for added/removed devices
  SCADA_SECRET_KEY (optional)     overrides api_config.secret_key
"""
import hashlib
import hmac
import inspect
import json
import logging
import math
import os
import signal
import struct
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import psycopg2.pool
import requests
from pymodbus.client import ModbusSerialClient, ModbusTcpClient
from dotenv import load_dotenv

log = logging.getLogger("gateway")

CONFIG_SYNC_S = float(os.getenv("GW_CONFIG_SYNC_S", "10"))
WRITE_FUNCTION_CODES = (5, 6, 15, 16)          # configurable per the guide, but this service only polls

env_file="/etc/edge-gateway/gateway.env"

if os.path.exists(env_file):
        load_dotenv(env_file)
else:
        print(f"configuration  file {env_file} not found")
        sys.exit(1)



# =============================================================================
# Database helper
# =============================================================================
class Db:
    def __init__(self):
        self.pool = psycopg2.pool.ThreadedConnectionPool(
            1, 12,
            host=os.getenv("GW_DB_HOST", "127.0.0.1"),
            port=int(os.getenv("GW_DB_PORT", "5432")),
            #dbname=os.getenv("GW_DB_NAME", "edge_gateway"),
            dbname=os.getenv("GW_DB_NAME", "modbus"),
            user=os.getenv("GW_DB_USER", "gateway"),
            password=os.getenv("GW_DB_PASSWORD", "gateway"),
            connect_timeout=5,
            application_name="edge-gateway",
        )

    @contextmanager
    def cursor(self):
        conn = self.pool.getconn()
        try:
            with conn:                                   # commit / rollback
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    yield cur
        finally:
            self.pool.putconn(conn, close=bool(conn.closed))

    def one(self, sql, params=None):
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def all(self, sql, params=None):
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def run(self, sql, params=None):
        with self.cursor() as cur:
            cur.execute(sql, params)


# =============================================================================
# Modbus helpers
# =============================================================================
class ModbusFailure(Exception):
    """kind: 'timeout' | 'crc' | 'device' (exception response) | 'other'"""
    def __init__(self, msg, kind="other"):
        super().__init__(msg)
        self.kind = kind


def classify_error(msg: str) -> str:
    m = msg.lower()
    if "crc" in m or "checksum" in m or "lrc" in m:
        return "crc"
    if "timeout" in m or "timed out" in m or "no response" in m:
        return "timeout"
    return "other"


_STRUCT_FMT = {"INT16": ">h", "UINT16": ">H", "INT32": ">i", "UINT32": ">I", "FLOAT": ">f",
               "INT64": ">q", "UINT64": ">Q", "DOUBLE64": ">d"}
# which device column holds the byte order for a data type
_ORDER_COLUMN = {"FLOAT": "float_byte_order", "INT32": "long_byte_order", "UINT32": "long_byte_order",
                 "DOUBLE64": "double_byte_order", "INT64": "long64_byte_order", "UINT64": "long64_byte_order"}


def decode_registers(regs, dtype, order=None):
    """16-bit register list -> Python number.
    `order` is a Niagara-style string such as 'Order3210' or 'Order76543210': the digit at position i
    is the significance (0 = least significant) of the i-th byte received on the wire.
        Order3210 = ABCD big-endian | Order1032 = CDAB word swap | Order2301 = BADC | Order0123 = DCBA
    16-bit types have no byte-order setting (always big-endian, as Modbus transmits registers)."""
    wire = b"".join(struct.pack(">H", w & 0xFFFF) for w in regs)
    if order and dtype in _ORDER_COLUMN:
        digits = [int(c) for c in order[len("Order"):]]
        if len(digits) != len(wire):
            raise ModbusFailure(f"byte order {order} does not fit {dtype}", "other")
        value_bytes = bytearray(len(wire))
        for i, sig in enumerate(digits):
            value_bytes[len(wire) - 1 - sig] = wire[i]
        wire = bytes(value_bytes)
    return struct.unpack(_STRUCT_FMT[dtype], wire)[0]


_PARITY = {"None": "N", "Even": "E", "Odd": "O"}
_port_locks = {}                                  # one lock per serial port (shared RS485 bus)
_port_locks_guard = threading.Lock()


def _port_lock(port):
    with _port_locks_guard:
        return _port_locks.setdefault(port, threading.Lock())


class ModbusLink:
    """Connection to one device. TCP = persistent connection.
    RTU = port opened per poll cycle under a per-port lock, so several slaves can share one RS485 bus."""

    def __init__(self, dev):
        self.dev = dev
        self.signature = self.make_signature(dev)
        self.client = None
        self.unit = dev["unit_id"] if dev["protocol"] == "TCP" else dev["slave_id"]
        self._unit_kw = None

    @staticmethod
    def make_signature(d):
        return tuple(d[k] for k in ("protocol", "ip_address", "port", "unit_id", "com_port", "baud_rate",
                                    "data_bits", "stop_bits", "parity", "slave_id", "timeout_ms",
                                    "wait_for_dsr", "wait_for_cts", "dtr_control", "rts_control",
                                    "rts_delay_before_ms", "rts_delay_after_ms"))

    def _new_client(self):
        d, timeout = self.dev, self.dev["timeout_ms"] / 1000.0
        if d["protocol"] == "TCP":
            return ModbusTcpClient(d["ip_address"], port=d["port"], timeout=timeout, retries=0)
        return ModbusSerialClient(d["com_port"], baudrate=d["baud_rate"], bytesize=d["data_bits"],
                                  parity=_PARITY[d["parity"]], stopbits=d["stop_bits"],
                                  timeout=timeout, retries=0)

    @property
    def connected(self):
        return self.client is not None and self.client.connected

    def connect(self):
        if self.client is None:
            self.client = self._new_client()
        if not self.client.connected and not self.client.connect():
            self.close()
            raise ModbusFailure(f"cannot connect to {self.describe()}", "other")
        if self.dev["protocol"] == "RTU":
            self._apply_serial_flow()

    def _apply_serial_flow(self):
        """Hardware flow control / RTS-DTR behaviour (the "Hardware Flow Control" box). Best effort:
        needs a real UART / USB-serial adapter; 'Toggle' uses the Linux kernel RS485 ioctl."""
        d, ser = self.dev, getattr(self.client, "socket", None)
        if ser is None:
            return
        try:
            ser.dsrdtr = bool(d["wait_for_dsr"]) or d["dtr_control"] == "Handshake"
            ser.rtscts = bool(d["wait_for_cts"]) or d["rts_control"] == "Handshake"
            if d["dtr_control"] in ("Enable", "Disable"):
                ser.dtr = d["dtr_control"] == "Enable"
            if d["rts_control"] in ("Enable", "Disable") and not ser.rtscts:
                ser.rts = d["rts_control"] == "Enable"
            if d["rts_control"] == "Toggle":
                from serial.rs485 import RS485Settings
                ser.rs485_mode = RS485Settings(rts_level_for_tx=True, rts_level_for_rx=False,
                                               delay_before_tx=d["rts_delay_before_ms"] / 1000.0,
                                               delay_before_rx=d["rts_delay_after_ms"] / 1000.0)
        except Exception as e:                                     # unsupported on this adapter/OS
            log.warning("%s: could not apply serial flow control: %s", d["device_name"], e)

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def describe(self):
        d = self.dev
        return f"{d['ip_address']}:{d['port']}" if d["protocol"] == "TCP" else f"{d['com_port']}@{d['baud_rate']}"

    @contextmanager
    def session(self):
        if self.dev["protocol"] == "RTU":
            with _port_lock(self.dev["com_port"]):
                try:
                    self.connect()
                    yield
                finally:
                    self.close()
        else:
            self.connect()
            yield

    def read(self, tag):
        """Return a list of register values (FC 3/4) or bools (FC 1/2)."""
        fc, count = tag["function_code"], tag["length"]
        fn = {1: self.client.read_coils, 2: self.client.read_discrete_inputs,
              3: self.client.read_holding_registers, 4: self.client.read_input_registers}[fc]
        if self._unit_kw is None:                  # pymodbus renamed slave= -> device_id= in 3.10
            params = inspect.signature(fn).parameters
            self._unit_kw = next((k for k in ("device_id", "slave", "unit") if k in params), "slave")
        try:
            rr = fn(tag["address"], count=count, **{self._unit_kw: self.unit})
        except Exception as e:                     # ConnectionException, ModbusIOException ...
            raise ModbusFailure(f"{type(e).__name__}: {e}", classify_error(str(e)))
        if rr.isError():
            if getattr(rr, "exception_code", None) is not None:       # device answered with an error
                raise ModbusFailure(f"Modbus exception code {rr.exception_code}", "device")
            raise ModbusFailure(str(rr), classify_error(str(rr)))
        return list(rr.bits[:count]) if fc in (1, 2) else list(rr.registers)


# =============================================================================
# Device poller (one thread per enabled device)
# =============================================================================
class DevicePoller(threading.Thread):
    def __init__(self, db, device_id, stop_evt):
        super().__init__(name=f"poller-{device_id}", daemon=True)
        self.db, self.device_id, self.stop_evt = db, device_id, stop_evt

    def run(self):
        link = None
        print(f"Poller started for device id={self.device_id}")
        log.info("poller started for device id=%s", self.device_id)
        while not self.stop_evt.is_set():
            started, interval = time.monotonic(), 5.0
            try:
                dev = self.db.one("SELECT * FROM modbus_devices WHERE id=%s", (self.device_id,))
                if not dev or not dev["enabled"]:
                    log.info("device id=%s disabled/removed - poller exiting", self.device_id)
                    break
                interval = dev["poll_interval_ms"] / 1000.0          # live-configurable
                tags = self.db.all("SELECT * FROM modbus_tags WHERE device_id=%s AND enabled ORDER BY id",
                                   (self.device_id,))
                if link is None or link.signature != ModbusLink.make_signature(dev):
                    if link:
                        link.close()
                    link = ModbusLink(dev)
                link.dev = dev                                       # pick up retry_count etc.
                self.poll_cycle(dev, tags, link)
            except Exception:
                log.exception("poller %s: unexpected error", self.device_id)
            self.stop_evt.wait(max(0.05, interval - (time.monotonic() - started)))
        if link:
            link.close()

    # ------------------------------------------------------------------
    def poll_cycle(self, dev, tags, link):
        name = dev["device_name"]
        stats = dict(ok=0, fail=0, crc=0, timeout=0, resp_ms=None, last_comm=None, err=None)
        results = []                                                  # rows for tag_values
        read_tags = [t for t in tags if t["function_code"] not in WRITE_FUNCTION_CODES]

        try:
            with link.session():
                for tag in read_tags:
                    if self.stop_evt.is_set():
                        break
                    results.append(self.read_tag(dev, tag, link, stats))
        except ModbusFailure as e:                                    # could not connect at all
            stats["fail"] += 1
            stats["err"] = str(e)
            stats["timeout"] += e.kind == "timeout"
            now = datetime.now(timezone.utc)
            results = [(t["id"], None, "BAD", now, str(e)) for t in read_tags]
            log.warning("%s: %s", name, e)

        self.save(dev, stats, results)

    def read_tag(self, dev, tag, link, stats):
        attempts = 1 + dev["retry_count"]
        last_err = "unknown"
        for attempt in range(1, attempts + 1):
            t0 = time.monotonic()
            try:
                if not link.connected:
                    link.connect()
                raw = link.read(tag)
                if tag["data_type"] == "BOOL":
                    value = 1.0 if raw[0] else 0.0
                else:
                    order = dev.get(_ORDER_COLUMN.get(tag["data_type"], ""))
                    value = float(decode_registers(raw, tag["data_type"], order))
                    value = value * tag["scale_factor"] + tag["offset_value"]
                if not math.isfinite(value):
                    raise ModbusFailure("non-finite value", "other")
                stats["ok"] += 1
                stats["resp_ms"] = int((time.monotonic() - t0) * 1000)
                stats["last_comm"] = datetime.now(timezone.utc)
                return (tag["id"], round(value, tag["decimals"]), "GOOD", stats["last_comm"], None)
            except ModbusFailure as e:
                last_err = f"{tag['tag_name']}: {e}"
                stats["fail"] += 1
                stats["crc"] += e.kind == "crc"
                stats["timeout"] += e.kind == "timeout"
                stats["err"] = last_err
                log.debug("%s attempt %d/%d failed: %s", dev["device_name"], attempt, attempts, last_err)
                if e.kind == "device":                                 # definitive answer - do not retry
                    break
                if e.kind != "crc" and dev["protocol"] == "TCP":       # force a clean reconnect
                    link.close()
                time.sleep(0.1)
        log.warning("%s: read failed after %d attempt(s): %s", dev["device_name"], attempts, last_err)
        return (tag["id"], None, "BAD", datetime.now(timezone.utc), last_err)

    def save(self, dev, s, results):
        status = "Connected" if s["ok"] else "Disconnected"
        with self.db.cursor() as cur:
            if results:
                psycopg2.extras.execute_values(cur, """
                    INSERT INTO tag_values (tag_id, value, quality, read_at, error) VALUES %s
                    ON CONFLICT (tag_id) DO UPDATE SET
                        value   = COALESCE(EXCLUDED.value, tag_values.value),
                        quality = EXCLUDED.quality, read_at = EXCLUDED.read_at, error = EXCLUDED.error
                """, results)
            cur.execute("""
                INSERT INTO device_diagnostics
                    (device_id, connection_status, last_comm_time, response_time_ms,
                     success_count, fail_count, crc_error_count, timeout_error_count, last_error, updated_at)
                VALUES (%(id)s, %(st)s, %(lc)s, %(rt)s, %(ok)s, %(fail)s, %(crc)s, %(to)s, %(err)s, now())
                ON CONFLICT (device_id) DO UPDATE SET
                    connection_status   = EXCLUDED.connection_status,
                    last_comm_time      = COALESCE(EXCLUDED.last_comm_time, device_diagnostics.last_comm_time),
                    response_time_ms    = COALESCE(EXCLUDED.response_time_ms, device_diagnostics.response_time_ms),
                    success_count       = device_diagnostics.success_count + EXCLUDED.success_count,
                    fail_count          = device_diagnostics.fail_count + EXCLUDED.fail_count,
                    crc_error_count     = device_diagnostics.crc_error_count + EXCLUDED.crc_error_count,
                    timeout_error_count = device_diagnostics.timeout_error_count + EXCLUDED.timeout_error_count,
                    last_error          = COALESCE(EXCLUDED.last_error, device_diagnostics.last_error),
                    updated_at          = now()
            """, dict(id=dev["id"], st=status, lc=s["last_comm"], rt=s["resp_ms"], ok=s["ok"],
                      fail=s["fail"], crc=s["crc"], to=s["timeout"], err=s["err"]))


# =============================================================================
# API publisher
# =============================================================================
class Publisher(threading.Thread):
    def __init__(self, db, stop_evt):
        super().__init__(name="publisher", daemon=True)
        self.db, self.stop_evt = db, stop_evt
        self._last_purge = 0.0

    def run(self):
        log.info("publisher started")
        while not self.stop_evt.is_set():
            interval = 60.0
            try:
                cfg = self.db.one("SELECT * FROM api_config WHERE id=1")
                if cfg:
                    interval = cfg["publish_interval_s"]
                    print("Publisher: API config loaded:", cfg)
                    if cfg["enabled"]:
                        self.publish_once(cfg)
                    self.purge(cfg)
                else:
                    log.warning("api_config is empty - nothing to publish")
            except Exception:
                log.exception("publisher: unexpected error")
            self.stop_evt.wait(interval)

    # ------------------------------------------------------------------
    def build_payload(self, cfg):
        rows = self.db.all("""
            SELECT c.tag_name, v.value, v.read_at
            FROM   modbus_tags t
            JOIN   modbus_devices d  ON d.id = t.device_id
            JOIN   api_tag_catalog c ON c.tag_name = t.tag_name
            JOIN   tag_values v      ON v.tag_id = t.id
            WHERE  t.enabled AND d.enabled AND v.quality = 'GOOD' AND v.value IS NOT NULL
              AND  v.read_at > now() - make_interval(secs => %s)
            ORDER  BY t.id""", (cfg["max_value_age_s"],))
        have = {r["tag_name"] for r in rows}
        missing = [r["tag_name"] for r in self.db.all(
            "SELECT tag_name FROM api_tag_catalog WHERE is_required ORDER BY tag_name") if r["tag_name"] not in have]
        if not rows:
            return None, "no fresh values available"
        if missing:
            return None, "required tag(s) without a fresh good value: " + ", ".join(missing)
        reading_at = max(r["read_at"] for r in rows).astimezone().isoformat(timespec="seconds")
        payload = {"readingAt": reading_at}
        payload.update({r["tag_name"]: r["value"] for r in rows})
        return payload, None

    def publish_once(self, cfg):
        payload, problem = self.build_payload(cfg)
        if problem:
            log.warning("not sending: %s", problem)
            self.log_api(cfg["api_url"], None, None, None, f"NOT SENT - {problem}", None, False, None)
            return

        secret = os.getenv("SCADA_SECRET_KEY") or cfg["secret_key"]
        body = json.dumps(payload, separators=(",", ":"))                 # minified JSON - exactly what is signed
        ts = str(int(time.time()))
        signature = hmac.new(secret.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
        headers = {"Content-Type": "application/json",
                   "X-SCADA-Device-Id": cfg["scada_device_id"],
                   "X-SCADA-Timestamp": ts,
                   "X-SCADA-Signature": signature}

        t0 = time.monotonic()
        status = resp_text = None
        try:
            print("Sending payload to API:", body)
            r = requests.post(cfg["api_url"], data=body.encode("utf-8"), headers=headers,
                              timeout=cfg["http_timeout_s"], verify=cfg["verify_ssl"])
            status, resp_text = r.status_code, r.text
            try:
                message = r.json().get("message") or resp_text[:500]
            except Exception:
                message = resp_text[:500]
            ok = status == 202
        except requests.RequestException as e:
            message, ok = f"{type(e).__name__}: {e}", False
        ms = int((time.monotonic() - t0) * 1000)

        (log.info if ok else log.warning)("API %s -> %s %s", cfg["api_url"], status, message)
        self.log_api(cfg["api_url"], {k: v for k, v in headers.items() if k != "Content-Type"},
                     body, status, message, resp_text, ok, ms)

    def log_api(self, url, headers, body, status, message, resp_text, ok, ms):
        self.db.run("""INSERT INTO api_log (request_url, request_headers, request_body, http_status,
                                            response_message, response_body, success, duration_ms)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (url, json.dumps(headers) if headers else None, body, status, message, resp_text, ok, ms))

    def purge(self, cfg):
        if time.time() - self._last_purge < 3600:
            return
        self._last_purge = time.time()
        self.db.run("DELETE FROM api_log WHERE logged_at < now() - make_interval(days => %s)",
                    (cfg["log_retention_days"],))


# =============================================================================
# main
# =============================================================================
def main():
    logging.basicConfig(level=os.getenv("GW_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)-7s %(threadName)s %(message)s")
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    db = None
    while db is None and not stop.is_set():                            # wait for the DB (e.g. at boot)
        try:
            db = Db()
        except psycopg2.Error as e:
            log.error("database not reachable (%s) - retrying in 5 s", str(e).strip())
            stop.wait(5)
    if db is None:
        return 0

    publisher = Publisher(db, stop)
    publisher.start()
    pollers = {}
    while not stop.is_set():
        try:
            enabled = {r["id"] for r in db.all("SELECT id FROM modbus_devices WHERE enabled")}
            for dev_id in enabled:
                if dev_id not in pollers or not pollers[dev_id].is_alive():
                    pollers[dev_id] = DevicePoller(db, dev_id, stop)
                    pollers[dev_id].start()
            for dev_id in [d for d in pollers if d not in enabled and not pollers[d].is_alive()]:
                del pollers[dev_id]
        except Exception:
            log.exception("device sync failed")
        stop.wait(CONFIG_SYNC_S)

    log.info("shutting down")
    for t in list(pollers.values()) + [publisher]:
        t.join(timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
