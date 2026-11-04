#!/usr/bin/env python3
"""
Edifice Gateway - configuration Web UI  (Flask + Jinja2, server-rendered, no CDN / no JS framework,
so it works fully offline on the edge box).

  python app.py                      serve on UI_HOST:UI_PORT (default 0.0.0.0:8088) with waitress
  python app.py reset-password USER  set a new password for USER from the terminal (lock-out recovery)

Environment: same DB_* variables as gateway.py, plus UI_SECRET_KEY, UI_HOST, UI_PORT, UI_ADMIN_PASSWORD.
  UI_THEME = bootstrap (default, Bootstrap 5 served locally) | plain (built-in CSS)

Roles:  admin (all) | engineer (devices, tags, clone, non-credential API settings) | viewer (read-only)
"""
import functools
import glob
import ipaddress
import json
import logging
import os
import secrets
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from dotenv import load_dotenv


import psycopg2
import psycopg2.errors
import psycopg2.extras
import psycopg2.pool
from flask import (Flask, abort, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger("gateway-ui")

# ----------------------------------------------------------------------------- constants
ROLES = ("admin", "engineer", "viewer")
PERMS = {"viewer": {"view"}, "engineer": {"view", "config"}, "admin": {"view", "config", "admin"}}
BAUDS = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200]
PARITIES = ["None", "Even", "Odd"]
DTR_MODES = ["Disable", "Enable", "Handshake"]
RTS_MODES = ["Disable", "Enable", "Handshake", "Toggle"]
ORD32 = ["Order3210", "Order2301", "Order1032", "Order0123"]
ORD64 = ["Order76543210", "Order67452301", "Order10325476", "Order32107654", "Order01234567"]
ORDER_HELP = {"Order3210": "ABCD (big-endian)", "Order2301": "BADC (byte swap)", "Order1032": "CDAB (word swap)",
              "Order0123": "DCBA (little-endian)", "Order76543210": "ABCDEFGH (big-endian)",
              "Order67452301": "BADCFEHG (byte swap)", "Order10325476": "GHEFCDAB (word swap)",
              "Order32107654": "EFGHABCD (32-bit halves swapped)", "Order01234567": "HGFEDCBA (little-endian)"}
DTYPES = {"BOOL": 1, "INT16": 1, "UINT16": 1, "INT32": 2, "UINT32": 2, "FLOAT": 2,
          "INT64": 4, "UINT64": 4, "DOUBLE64": 4}
FCS = {1: "01 Read Coils", 2: "02 Read Discrete Inputs", 3: "03 Read Holding Registers",
       4: "04 Read Input Registers", 5: "05 Write Single Coil (not polled)", 6: "06 Write Single Register (not polled)",
       15: "15 Write Multiple Coils (not polled)", 16: "16 Write Multiple Registers (not polled)"}
BOOL_FCS, REG_FCS = (1, 2, 5, 15), (3, 4, 6, 16)

DEVICE_DEFAULTS = dict(
    device_name="", description="", enabled=True, protocol="TCP", timeout_ms=3000, retry_count=3,
    poll_interval_ms=5000, ip_address="", port=502, unit_id=1, com_port="", baud_rate=19200, data_bits=8,
    stop_bits=1, parity="None", slave_id=1, wait_for_dsr=False, wait_for_cts=False, dtr_control="Disable",
    rts_control="Disable", rts_delay_before_ms=0, rts_delay_after_ms=235, float_byte_order="Order3210",
    long_byte_order="Order3210", double_byte_order="Order76543210", long64_byte_order="Order76543210")
DEVICE_COLS = list(DEVICE_DEFAULTS)

env_file="./.env"

if os.path.exists(env_file):
        load_dotenv(env_file)
else:
        print(f"configuration  file {env_file} not found")
        sys.exit(1)


THEME = os.getenv("UI_THEME", "bootstrap").lower()          # "bootstrap" (default) or "plain"
app = Flask(__name__, template_folder="ui/templates_bs" if THEME == "bootstrap" else "ui/templates",static_folder="ui/static")

#app = Flask(__name__)
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=1 << 20)



# ----------------------------------------------------------------------------- database
class Db:
    def __init__(self):
        self.pool = psycopg2.pool.ThreadedConnectionPool(
            1, 8, host=os.getenv("GW_DB_HOST", "127.0.0.1"), port=int(os.getenv("GW_DB_PORT", "5432")),
            dbname=os.getenv("GW_DB_NAME", "modbus"), user=os.getenv("GW_DB_USER", "gateway"),
            password=os.getenv("GW_DB_PASSWORD", "gateway"), connect_timeout=5, application_name="edge-gateway-ui")

    @contextmanager
    def cursor(self):
        conn = self.pool.getconn()
        try:
            with conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    yield cur
        finally:
            self.pool.putconn(conn, close=bool(conn.closed))

    def all(self, sql, p=None):
        with self.cursor() as c:
            c.execute(sql, p)
            return c.fetchall()

    def one(self, sql, p=None):
        with self.cursor() as c:
            c.execute(sql, p)
            return c.fetchone()

    def run(self, sql, p=None):
        with self.cursor() as c:
            c.execute(sql, p)
            return c.rowcount


_db = None


def db():
    global _db
    if _db is None:
        _db = Db()
    return _db


def audit(action, entity="", detail=""):
    try:
        db().run("INSERT INTO audit_log (username, action, entity, detail) VALUES (%s,%s,%s,%s)",
                 (session.get("username"), action, entity, detail[:2000]))
    except Exception:
        log.exception("audit write failed")


# ----------------------------------------------------------------------------- auth / RBAC / CSRF
_fail = {}                                           # (ip, user) -> [count, locked_until]


def can(perm):
    return bool(getattr(g, "user", None)) and perm in PERMS.get(g.user["role"], ())


def login_required(perm="view"):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for("login", next=request.path))
            if g.user["must_change_password"] and request.endpoint not in ("password", "logout"):
                return redirect(url_for("password"))
            if perm not in PERMS[g.user["role"]]:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


@app.before_request
def load_user():
    g.user = None
    if request.endpoint == "static":
        return
    uid = session.get("uid")
    if uid:
        u = db().one("SELECT * FROM app_users WHERE id=%s AND enabled", (uid,))
        if u:
            g.user = u
            session["role"], session["username"] = u["role"], u["username"]
        else:
            session.clear()
    if request.method == "POST":
        tok = session.get("csrf", "")
        if not tok or not secrets.compare_digest(tok, request.form.get("_csrf", "")):
            abort(400, "Invalid or missing CSRF token - reload the page and try again.")


@app.after_request
def secure_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")

    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return dict(can=can, csrf_token=session["csrf"], user=g.get("user"), FCS=FCS, DTYPES=DTYPES, ORDER_HELP=ORDER_HELP)


@app.template_filter("dt")
def fmt_dt(v):
    return v.astimezone().strftime("%Y-%m-%d %H:%M:%S") if v else "-"


@app.template_filter("age")
def fmt_age(v):
    if not v:
        return "-"
    s = int((datetime.now(v.tzinfo) - v).total_seconds())
    return f"{s}s" if s < 120 else f"{s // 60}m" if s < 7200 else f"{s // 3600}h"


@app.template_filter("pretty")
def pretty(v):
    try:
        return json.dumps(json.loads(v), indent=2) if isinstance(v, str) else json.dumps(v, indent=2)
    except Exception:
        return v or ""


@app.errorhandler(403)
def e403(_):
    return render_template("error.html", code=403, msg="Your role does not allow this action."), 403


@app.errorhandler(404)
def e404(_):
    return render_template("error.html", code=404, msg="Not found."), 404


@app.errorhandler(400)
def e400(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400


@app.route("/login", methods=["GET", "POST"])
def login():
    print("Relative path:", app.template_folder)
    absolute_templates_path = os.path.abspath(os.path.join(app.root_path, app.template_folder))
    print("Absolute path:", absolute_templates_path)

    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name, pw = request.form.get("username", "").strip(), request.form.get("password", "")
        key = (request.remote_addr, name.lower())
        cnt, until = _fail.get(key, [0, 0])
        if until > time.time():
            flash("Too many failed attempts - try again in a few minutes.", "error")
            return render_template("login.html"), 429
        u = db().one("SELECT * FROM app_users WHERE lower(username)=lower(%s) AND enabled", (name,))
        if u and check_password_hash(u["password_hash"], pw):
            _fail.pop(key, None)
            session.clear()
            session.permanent = True
            session["uid"], session["username"], session["csrf"] = u["id"], u["username"], secrets.token_hex(16)
            db().run("UPDATE app_users SET last_login_at=now() WHERE id=%s", (u["id"],))
            audit("login", "user", u["username"])
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        _fail[key] = [cnt + 1, time.time() + 300 if cnt + 1 >= 5 else 0]
        flash("Invalid username or password.", "error")
        log.warning("failed login for %r from %s", name, request.remote_addr)
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        audit("logout", "user", g.user["username"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/password", methods=["GET", "POST"])
@login_required("view")
def password():
    if request.method == "POST":
        cur, new, new2 = (request.form.get(k, "") for k in ("current", "new", "new2"))
        if not check_password_hash(g.user["password_hash"], cur):
            flash("Current password is wrong.", "error")
        elif len(new) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new != new2:
            flash("New passwords do not match.", "error")
        else:
            db().run("UPDATE app_users SET password_hash=%s, must_change_password=FALSE WHERE id=%s",
                     (generate_password_hash(new), g.user["id"]))
            audit("change_password", "user", g.user["username"])
            flash("Password changed.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("password.html")


# ----------------------------------------------------------------------------- dashboard
@app.route("/")
@login_required("view")
def dashboard():
    devices = db().all("""SELECT d.*, g.connection_status, g.last_comm_time, g.response_time_ms,
                                 g.success_count, g.fail_count, g.last_error
                          FROM modbus_devices d LEFT JOIN device_diagnostics g ON g.device_id=d.id ORDER BY d.id""")
    live = db().all("""SELECT t.tag_name, d.device_name, c.unit, c.is_required, v.value, v.quality, v.read_at, v.error
                       FROM modbus_tags t JOIN modbus_devices d ON d.id=t.device_id
                       JOIN api_tag_catalog c ON c.tag_name=t.tag_name
                       LEFT JOIN tag_values v ON v.tag_id=t.id
                       WHERE t.enabled ORDER BY t.id""")
    unmapped = db().all("""SELECT tag_name FROM api_tag_catalog c WHERE is_required AND NOT EXISTS
                           (SELECT 1 FROM modbus_tags t JOIN modbus_devices d ON d.id=t.device_id
                            WHERE t.tag_name=c.tag_name AND t.enabled AND d.enabled) ORDER BY tag_name""")
    last_api = db().one("SELECT * FROM api_log ORDER BY id DESC LIMIT 1")
    cfg = db().one("SELECT enabled, publish_interval_s FROM api_config WHERE id=1")
    return render_template("dashboard.html", devices=devices, live=live, unmapped=unmapped, last_api=last_api, cfg=cfg)


# ----------------------------------------------------------------------------- devices
def form_values(f):
    v = dict(DEVICE_DEFAULTS)
    for k in DEVICE_COLS:
        if k in f:
            v[k] = f[k]
    for k in ("enabled", "wait_for_dsr", "wait_for_cts"):
        v[k] = k in f
    return v


def parse_device(f):
    """Validate the device form -> (dict_for_db, errors)."""
    err, d = [], {}
    s = lambda n: (f.get(n) or "").strip()                                            # noqa: E731

    def num(n, label, lo, hi, default=None):
        if n not in f and default is not None:
            return default
        try:
            v = int(s(n))
        except ValueError:
            err.append(f"{label} must be a whole number")
            return None
        if not lo <= v <= hi:
            err.append(f"{label} must be between {lo} and {hi}")
            return None
        return v

    def choice(n, label, opts, default=None):
        v = s(n) or default
        if v not in opts:
            err.append(f"{label}: invalid value")
        return v

    d["device_name"] = s("device_name")
    if not d["device_name"]:
        err.append("Device name is required")
    d["description"] = s("description") or None
    d["enabled"] = "enabled" in f
    d["protocol"] = choice("protocol", "Connect using", ("RTU", "TCP"))
    d["timeout_ms"] = num("timeout_ms", "Timeout (ms)", 50, 60000)
    d["retry_count"] = num("retry_count", "Retry count", 0, 10)
    d["poll_interval_ms"] = num("poll_interval_ms", "Polling interval (ms)", 100, 86_400_000)
    for k in ("ip_address", "port", "unit_id", "com_port", "baud_rate", "data_bits", "stop_bits", "parity", "slave_id"):
        d[k] = None
    if d["protocol"] == "TCP":
        d["ip_address"] = s("ip_address")
        try:
            ipaddress.IPv4Address(d["ip_address"])
        except ValueError:
            err.append("IP address must be a valid IPv4 address")
        d["port"] = num("port", "Service port", 1, 65535)
        d["unit_id"] = num("unit_id", "Unit ID", 0, 255)
    elif d["protocol"] == "RTU":
        d["com_port"] = s("com_port")
        if not d["com_port"]:
            err.append("Serial port is required")
        try:
            d["baud_rate"] = int(s("baud_rate"))
            assert d["baud_rate"] in BAUDS
        except Exception:
            err.append("Baud rate: invalid value")
        d["data_bits"] = num("data_bits", "Word length", 7, 8)
        d["stop_bits"] = num("stop_bits", "Stop bits", 1, 2)
        d["parity"] = choice("parity", "Parity", PARITIES)
        d["slave_id"] = num("slave_id", "Slave ID", 0, 255)
    d["wait_for_dsr"], d["wait_for_cts"] = "wait_for_dsr" in f, "wait_for_cts" in f
    d["dtr_control"] = choice("dtr_control", "DTR control", DTR_MODES, "Disable")
    d["rts_control"] = choice("rts_control", "RTS control", RTS_MODES, "Disable")
    toggle = d["rts_control"] == "Toggle" and d["protocol"] == "RTU"
    d["rts_delay_before_ms"] = num("rts_delay_before_ms", "RTS delay before TX", 0, 5000) if toggle else 0
    d["rts_delay_after_ms"] = num("rts_delay_after_ms", "RTS delay after TX", 0, 5000) if toggle else 235
    d["float_byte_order"] = choice("float_byte_order", "Float byte order", ORD32, "Order3210")
    d["long_byte_order"] = choice("long_byte_order", "Long byte order", ORD32, "Order3210")
    d["double_byte_order"] = choice("double_byte_order", "Double 64-bit byte order", ORD64, "Order76543210")
    d["long64_byte_order"] = choice("long64_byte_order", "Long 64-bit byte order", ORD64, "Order76543210")
    return d, err


def db_error_text(e):
    if isinstance(e, psycopg2.errors.UniqueViolation):
        m = str(e)
        if "uq_tags_name_enabled" in m:
            return "Another ENABLED tag already uses this payload key. Disable it first or choose a different key."
        return "That name already exists."
    if isinstance(e, psycopg2.errors.CheckViolation):
        return "Value rejected by database rule: " + (getattr(e.diag, "constraint_name", "") or "check constraint")
    return "Database error: " + str(e).splitlines()[0]


def insert_device(cur, d):
    cols = list(d)
    cur.execute(f"INSERT INTO modbus_devices ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))}) RETURNING id",
                [d[c] for c in cols])
    return cur.fetchone()["id"]


def serial_ports():
    pats = ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS[0-9]*", "/dev/ttyAMA*", "/dev/ttyRS*", "/dev/serial/by-id/*"]
    return sorted({p for pat in pats for p in glob.glob(pat)})


@app.route("/devices")
@login_required("view")
def devices():
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    per = 20
    where = []
    params = []

    total = db().one(
        f"SELECT count(*) AS n FROM modbus_devices d LEFT JOIN device_diagnostics g ON g.device_id=d.id",params,
    )["n"]

    pages = max((total + per - 1) // per, 1)
    page = min(page, pages)

     # Preserve filter arguments in pagination and detail links.
    qargs = {
    }

    
    rows = db().all("""SELECT d.*, g.connection_status, g.last_comm_time, g.response_time_ms, g.success_count,
        g.fail_count, (SELECT count(*) FROM modbus_tags t WHERE t.device_id=d.id) AS tag_count,
        (SELECT count(*) FROM modbus_tags t WHERE t.device_id=d.id AND t.enabled) AS tag_enabled
        FROM modbus_devices d LEFT JOIN device_diagnostics g ON g.device_id=d.id ORDER BY d.id LIMIT %s OFFSET %s""",
        params + [per, (page - 1) * per],)
    return render_template("devices.html", devices=rows,page=page,pages=pages,total=total,qargs=qargs)


def render_device_form(dev, errors, title, action, **extra):
    return render_template("device_form.html", dev=dev, errors=errors, title=title, action=action, BAUDS=BAUDS,
                           PARITIES=PARITIES, DTR_MODES=DTR_MODES, RTS_MODES=RTS_MODES, ORD32=ORD32, ORD64=ORD64,
                           ports=serial_ports(), **extra), (400 if errors else 200)


@app.route("/devices/new", methods=["GET", "POST"])
@login_required("config")
def device_new():
    if request.method == "POST":
        d, err = parse_device(request.form)
        if not err:
            try:
                with db().cursor() as cur:
                    new_id = insert_device(cur, d)
                audit("create", "device", f"{d['device_name']} (id {new_id})")
                flash(f"Device '{d['device_name']}' created. Now add its tags.", "ok")
                return redirect(url_for("tags", device=new_id))
            except psycopg2.Error as e:
                err.append(db_error_text(e))
        return render_device_form(form_values(request.form), err, "Modbus Configuration", url_for("device_new"))
    return render_device_form(dict(DEVICE_DEFAULTS), [], "Modbus Configuration", url_for("device_new"))


@app.route("/devices/<int:did>/edit", methods=["GET", "POST"])
@login_required("config")
def device_edit(did):
    cur_dev = db().one("SELECT * FROM modbus_devices WHERE id=%s", (did,)) or abort(404)
    if request.method == "POST":
        d, err = parse_device(request.form)
        if not err:
            try:
                sets = ",".join(f"{c}=%s" for c in d)
                db().run(f"UPDATE modbus_devices SET {sets}, updated_at=now() WHERE id=%s", [*d.values(), did])
                audit("update", "device", f"{d['device_name']} (id {did})")
                flash("Device saved. The gateway applies it on its next poll cycle.", "ok")
                return redirect(url_for("devices"))
            except psycopg2.Error as e:
                err.append(db_error_text(e))
        return render_device_form(form_values(request.form), err, f"Edit device - {cur_dev['device_name']}",
                                  url_for("device_edit", did=did))
    return render_device_form(cur_dev, [], f"Edit device - {cur_dev['device_name']}", url_for("device_edit", did=did))


@app.route("/devices/<int:did>/clone", methods=["GET", "POST"])
@login_required("config")
def device_clone(did):
    src = db().one("SELECT * FROM modbus_devices WHERE id=%s", (did,)) or abort(404)
    n_tags = db().one("SELECT count(*) AS n FROM modbus_tags WHERE device_id=%s", (did,))["n"]
    extra = dict(clone=True, n_tags=n_tags, bulk=request.form.get("bulk", ""))
    title, action = f"Clone device - {src['device_name']}", url_for("device_clone", did=did)
    if request.method == "POST":
        d, err = parse_device(request.form)
        copies = [d]
        # optional bulk copies:  name,ip,unit_id (TCP)   or   name,slave_id (RTU)
        for n, line in enumerate(request.form.get("bulk", "").splitlines(), 1):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            c = dict(d)
            try:
                c["device_name"] = parts[0]
                if d["protocol"] == "TCP":
                    c["ip_address"] = parts[1]
                    ipaddress.IPv4Address(c["ip_address"])
                    c["unit_id"] = int(parts[2]) if len(parts) > 2 and parts[2] else d["unit_id"]
                else:
                    c["slave_id"] = int(parts[1])
                if not c["device_name"]:
                    raise ValueError
                copies.append(c)
            except Exception:
                err.append(f"Bulk line {n} invalid: '{line}'  (TCP: name,ip[,unit_id]   RTU: name,slave_id)")
        if not err:
            try:
                with db().cursor() as cur:
                    for c in copies:
                        new_id = insert_device(cur, c)
                        if "copy_tags" in request.form:       # copies are DISABLED: payload keys must stay unique
                            cur.execute("""INSERT INTO modbus_tags (device_id, tag_name, description, enabled, function_code,
                                           address, data_type, length, scale_factor, offset_value, decimals)
                                           SELECT %s, tag_name, description, FALSE, function_code, address, data_type,
                                                  length, scale_factor, offset_value, decimals
                                           FROM modbus_tags WHERE device_id=%s""", (new_id, did))
                audit("clone", "device", f"{src['device_name']} -> {', '.join(c['device_name'] for c in copies)}")
                flash(f"Created {len(copies)} device(s). Cloned tags are DISABLED - give each tag its own payload "
                      f"key, then enable it.", "ok")
                return redirect(url_for("devices"))
            except psycopg2.Error as e:
                err.append(db_error_text(e))
        return render_device_form(form_values(request.form), err, title, action, **extra)
    clone = dict(src, device_name=src["device_name"] + "-copy", enabled=False)
    return render_device_form(clone, [], title, action, **extra)


@app.route("/devices/<int:did>/toggle", methods=["POST"])
@login_required("config")
def device_toggle(did):
    db().run("UPDATE modbus_devices SET enabled = NOT enabled, updated_at=now() WHERE id=%s", (did,))
    audit("toggle", "device", f"id {did}")
    return redirect(request.referrer or url_for("devices"))


@app.route("/devices/<int:did>/delete", methods=["POST"])
@login_required("config")
def device_delete(did):
    row = db().one("DELETE FROM modbus_devices WHERE id=%s RETURNING device_name", (did,))
    audit("delete", "device", row["device_name"] if row else f"id {did}")
    flash("Device and its tags deleted.", "ok")
    return redirect(url_for("devices"))


# ----------------------------------------------------------------------------- tags
def parse_tag(f):
    err, t, s = [], {}, lambda n: (f.get(n) or "").strip()                            # noqa: E731
    try:
        t["device_id"] = int(s("device_id"))
    except ValueError:
        err.append("Device is required")
    t["tag_name"] = s("tag_name")
    if not db().one("SELECT 1 AS x FROM api_tag_catalog WHERE tag_name=%s", (t["tag_name"],)):
        err.append("Tag name must be one of the API payload keys")
    t["description"] = s("description") or None
    t["enabled"] = "enabled" in f
    try:
        t["function_code"] = int(s("function_code"))
        assert t["function_code"] in FCS
    except Exception:
        err.append("Function code: invalid value")
    t["data_type"] = s("data_type")
    if t["data_type"] not in DTYPES:
        err.append("Data type: invalid value")
    else:
        t["length"] = DTYPES[t["data_type"]]
        fc = t.get("function_code")
        if fc and (fc in BOOL_FCS) != (t["data_type"] == "BOOL"):
            err.append("BOOL needs a coil/discrete-input function code (01/02/05/15); other types need 03/04/06/16")
    for k, label, cast, lo, hi in (("address", "Address", int, 0, 65535), ("decimals", "Decimals", int, 0, 10),
                                   ("scale_factor", "Scale factor", float, -1e12, 1e12),
                                   ("offset_value", "Offset", float, -1e12, 1e12)):
        try:
            t[k] = cast(s(k))
            assert lo <= t[k] <= hi
        except Exception:
            err.append(f"{label} must be a number between {lo:g} and {hi:g}")
    return t, err


def tag_form(tag, errors, title, action):
    return render_template("tag_form.html", tag=tag, errors=errors, title=title, action=action,
                           device_opts=[(d["id"], d["device_name"]) for d in
                                        db().all("SELECT id, device_name FROM modbus_devices ORDER BY device_name")],
                           catalog=db().all("SELECT * FROM api_tag_catalog ORDER BY tag_name")), (400 if errors else 200)


@app.route("/tags")
@login_required("view")
def tags():
    did = request.args.get("device", type=int)

    page = max(request.args.get("page", 1, type=int) or 1, 1)
    per = 4
    where = []
    params = [did,did]
    
    total = db().one(
            f"""SELECT count(*) AS n FROM modbus_tags t JOIN modbus_devices d ON d.id=t.device_id
                JOIN api_tag_catalog c ON c.tag_name=t.tag_name LEFT JOIN tag_values v ON v.tag_id=t.id
                       WHERE (%s IS NULL OR t.device_id=%s)""",params,
        )["n"]
    
    pages = max((total + per - 1) // per, 1)
    page = min(page, pages)
    
         # Preserve filter arguments in pagination and detail links.
    qargs = {
        "device": did
    }
    
    rows = db().all("""SELECT t.*, d.device_name, d.enabled AS device_enabled, c.unit, c.is_required, v.value, v.quality,
                              v.read_at, v.error,
                              (SELECT count(*) FROM modbus_tags x WHERE x.tag_name=t.tag_name) AS name_uses
                       FROM modbus_tags t JOIN modbus_devices d ON d.id=t.device_id
                       JOIN api_tag_catalog c ON c.tag_name=t.tag_name LEFT JOIN tag_values v ON v.tag_id=t.id
                       WHERE (%s IS NULL OR t.device_id=%s) ORDER BY d.id, t.id LIMIT %s OFFSET %s""", (did, did, per, (page - 1) * per))
    
    return render_template("tags.html", tags=rows, did=did,page=page,pages=pages,qargs=qargs,
                           devices=db().all("SELECT id, device_name FROM modbus_devices ORDER BY device_name"))


@app.route("/tags/new", methods=["GET", "POST"])
@login_required("config")
def tag_new():
    if request.method == "POST":
        t, err = parse_tag(request.form)
        if not err:
            try:
                cols = list(t)
                db().run(f"INSERT INTO modbus_tags ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))})",
                         [t[c] for c in cols])
                audit("create", "tag", f"{t['tag_name']} dev {t['device_id']}")
                flash("Tag added.", "ok")
                return redirect(url_for("tags", device=t["device_id"]))
            except psycopg2.Error as e:
                err.append(db_error_text(e))
        return tag_form({**request.form.to_dict(), "enabled": "enabled" in request.form}, err, "New tag",
                        url_for("tag_new"))
    defaults = dict(device_id=request.args.get("device", type=int), tag_name="", description="", enabled=True,
                    function_code=3, address=0, data_type="FLOAT", scale_factor=1, offset_value=0, decimals=3)
    return tag_form(defaults, [], "New tag", url_for("tag_new"))


@app.route("/tags/<int:tid>/edit", methods=["GET", "POST"])
@login_required("config")
def tag_edit(tid):
    cur_tag = db().one("SELECT * FROM modbus_tags WHERE id=%s", (tid,)) or abort(404)
    if request.method == "POST":
        t, err = parse_tag(request.form)
        if not err:
            try:
                db().run(f"UPDATE modbus_tags SET {','.join(f'{c}=%s' for c in t)}, updated_at=now() WHERE id=%s",
                         [*t.values(), tid])
                audit("update", "tag", f"{t['tag_name']} (id {tid})")
                flash("Tag saved.", "ok")
                return redirect(url_for("tags", device=t["device_id"]))
            except psycopg2.Error as e:
                err.append(db_error_text(e))
        return tag_form({**request.form.to_dict(), "enabled": "enabled" in request.form}, err, "Edit tag",
                        url_for("tag_edit", tid=tid))
    return tag_form(cur_tag, [], "Edit tag", url_for("tag_edit", tid=tid))


@app.route("/tags/<int:tid>/duplicate", methods=["POST"])
@login_required("config")
def tag_duplicate(tid):
    row = db().one("""INSERT INTO modbus_tags (device_id, tag_name, description, enabled, function_code, address,
                      data_type, length, scale_factor, offset_value, decimals)
                      SELECT device_id, tag_name, description, FALSE, function_code, address, data_type, length,
                             scale_factor, offset_value, decimals FROM modbus_tags WHERE id=%s RETURNING id""", (tid,))
    if not row:
        abort(404)
    audit("duplicate", "tag", f"id {tid} -> {row['id']}")
    flash("Tag duplicated (disabled). Change the payload key / address, then enable it.", "ok")
    return redirect(url_for("tag_edit", tid=row["id"]))


@app.route("/tags/<int:tid>/toggle", methods=["POST"])
@login_required("config")
def tag_toggle(tid):
    try:
        db().run("UPDATE modbus_tags SET enabled = NOT enabled, updated_at=now() WHERE id=%s", (tid,))
        audit("toggle", "tag", f"id {tid}")
    except psycopg2.Error as e:
        flash(db_error_text(e), "error")
    return redirect(request.referrer or url_for("tags"))


@app.route("/tags/<int:tid>/delete", methods=["POST"])
@login_required("config")
def tag_delete(tid):
    row = db().one("DELETE FROM modbus_tags WHERE id=%s RETURNING device_id, tag_name", (tid,))
    audit("delete", "tag", row["tag_name"] if row else f"id {tid}")
    return redirect(url_for("tags", device=row["device_id"] if row else None))


# ----------------------------------------------------------------------------- API settings & log
@app.route("/api-settings", methods=["GET", "POST"])
@login_required("view")
def api_settings():
    cfg = db().one("SELECT * FROM api_config WHERE id=1")
    if request.method == "POST":
        if not can("config"):
            abort(403)
        f, err, s = request.form, [], lambda n: (request.form.get(n) or "").strip()      # noqa: E731
        vals = {}
        for k, label, lo, hi in (("publish_interval_s", "Publish interval", 1, 86400), ("http_timeout_s", "HTTP timeout", 1, 300),
                                 ("max_value_age_s", "Max value age", 1, 86400), ("log_retention_days", "Log retention", 1, 3650)):
            try:
                vals[k] = int(s(k))
                assert lo <= vals[k] <= hi
            except Exception:
                err.append(f"{label} must be between {lo} and {hi}")
        vals["verify_ssl"], vals["enabled"] = "verify_ssl" in f, "enabled" in f
        if can("admin"):                                                # credentials: admin only
            vals["api_url"], vals["scada_device_id"] = s("api_url"), s("scada_device_id")
            if not vals["api_url"].startswith(("http://", "https://")):
                err.append("API URL must start with http:// or https://")
            if not vals["scada_device_id"]:
                err.append("SCADA Device ID is required")
            if s("secret_key"):
                vals["secret_key"] = s("secret_key")
        if not err:
            db().run(f"UPDATE api_config SET {','.join(f'{c}=%s' for c in vals)}, updated_at=now() WHERE id=1", list(vals.values()))
            audit("update", "api_config", ", ".join(k for k in vals if k != "secret_key") + (" +secret_key" if "secret_key" in vals else ""))
            flash("API settings saved.", "ok")
            return redirect(url_for("api_settings"))
        for e in err:
            flash(e, "error")
        cfg = {**cfg, **vals}
    return render_template("api_settings.html", cfg=cfg)


@app.route("/api-log1")
@login_required("view")
def api_log1():
    show, status = request.args.get("show", "today"), request.args.get("status", "all")
    page, per = max(request.args.get("page", 1, type=int), 1), 50
    RANGES = {
        "1h": "Last hour",
        "24h": "Last 24 hours",
        "7d": "Last 7 days",
        "30d": "Last 30 days",
        "all": "All time"
    }
    range_ = request.args.get("range", "24h")


    where, p = [], []
    if show == "today":
        where.append("logged_at >= date_trunc('day', now())")
    if status == "ok":
        where.append("success")
    elif status == "failed":
        where.append("NOT success")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = db().one(f"SELECT count(*) AS n FROM api_log {w}", p)["n"]
    rows = db().all(f"SELECT id, logged_at, http_status, response_message, success, duration_ms, request_body "
                    f"FROM api_log {w} ORDER BY id DESC LIMIT %s OFFSET %s", p + [per, (page - 1) * per])
    return render_template("api_log.html", rows=rows, show=show, status=status, page=page, pages=max((total + per - 1) // per, 1), total=total,
    RANGES=RANGES,range_=range_,from_=request.args.get("from", ""), to=request.args.get("to", ""),
    status_options={"all": "All", "ok": "Success", "failed": "Failed"},window=request.args.get("window", "all"))


@app.route("/api-log")
@login_required("view")
def api_log():
    from datetime import datetime, time as dt_time

    RANGES = {
        "1h": "Last hour",
        "24h": "Last 24 hours",
        "7d": "Last 7 days",
        "30d": "Last 30 days",
        "all": "All time",
        "custom": "Custom range",
    }

    range_ = request.args.get("range", "24h")
    if range_ not in RANGES:
        range_ = "24h"

    status = request.args.get("status", "all")
    if status not in ("all", "ok", "failed"):
        status = "all"

    page = max(request.args.get("page", 1, type=int) or 1, 1)
    per = 20

    # Read optional custom date values.
    from_text = request.args.get("from", "").strip()
    to_text = request.args.get("to", "").strip()

    def parse_local_datetime(value, end_of_day=False):
        if not value:
            return None
        try:
            # datetime-local form values: YYYY-MM-DDTHH:MM
            return datetime.strptime(value, "%Y-%m-%dT%H:%M")
        except ValueError:
            return None

    start_dt = None
    end_dt = None

    # Use database time for relative ranges, keeping the filtering
    # and displayed boundaries consistent with PostgreSQL.
    if range_ == "custom":
        start_dt = parse_local_datetime(from_text)
        end_dt = parse_local_datetime(to_text)

        if from_text and start_dt is None:
            flash("Invalid start date. Please select a valid date and time.", "error")
        if to_text and end_dt is None:
            flash("Invalid end date. Please select a valid date and time.", "error")
        if start_dt and end_dt and start_dt > end_dt:
            flash("The start date must be before the end date.", "error")
            start_dt = end_dt = None
    else:
        from_text = ""
        to_text = ""

    where = []
    params = []

    if range_ == "custom":
        if start_dt:
            where.append("logged_at >= %s")
            params.append(start_dt)
        if end_dt:
            where.append("logged_at <= %s")
            params.append(end_dt)
    elif range_ != "all":
        intervals = {
            "1h": "1 hour",
            "24h": "24 hours",
            "7d": "7 days",
            "30d": "30 days",
        }
        where.append("logged_at >= now() - %s::interval")
        params.append(intervals[range_])

    if status == "ok":
        where.append("success IS TRUE")
    elif status == "failed":
        where.append("success IS NOT TRUE")

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    # Total records matching the current filters.
    total = db().one(
        f"SELECT count(*) AS n FROM api_log{where_sql}",
        params,
    )["n"]

    pages = max((total + per - 1) // per, 1)
    page = min(page, pages)

    rows = db().all(
        f"""
        SELECT id, logged_at, http_status, response_message,
               success, duration_ms, request_body
        FROM api_log
        {where_sql}
        ORDER BY logged_at DESC, id DESC
        LIMIT %s OFFSET %s
        """,
        params + [per, (page - 1) * per],
    )

    # Counts for the current date range, independent of the status
    # dropdown, so accepted + failed describes the selected period.
    count_row = db().one(
        f"""
        SELECT
            count(*) FILTER (WHERE success IS TRUE) AS n_ok,
            count(*) FILTER (WHERE success IS NOT TRUE) AS n_fail
        FROM api_log
        {(
            " WHERE " + " AND ".join(
                where_clause
                for where_clause in where
                if where_clause not in ("success IS TRUE", "success IS NOT TRUE")
            )
        ) if any(clause not in ("success IS TRUE", "success IS NOT TRUE")
                 for clause in where) else ""}
        """,
        [
            value for clause, value in zip(
                where, params
            )
        ][:sum(
            clause not in ("success IS TRUE", "success IS NOT TRUE")
            for clause in where
        )],
    )

    n_ok = count_row["n_ok"]
    n_fail = count_row["n_fail"]

    # Date boundaries for the summary displayed above the table.
    # For relative periods, these are approximate application-side
    # values; PostgreSQL remains authoritative for filtering.
    now = datetime.now()
    if range_ == "1h":
        window = (now - timedelta(hours=1), None)
    elif range_ == "24h":
        window = (now - timedelta(hours=24), None)
    elif range_ == "7d":
        window = (now - timedelta(days=7), None)
    elif range_ == "30d":
        window = (now - timedelta(days=30), None)
    elif range_ == "custom":
        window = (start_dt, end_dt)
    else:
        window = (None, None)

    # Preserve filter arguments in pagination and detail links.
    qargs = {
        "range": range_,
        "status": status,
    }
    if range_ == "custom":
        qargs["from"] = from_text
        qargs["to"] = to_text

    qs = request.query_string.decode("utf-8", errors="replace")

    return render_template(
        "api_log.html",
        rows=rows,
        show=range_,
        status=status,
        page=page,
        pages=pages,
        total=total,
        RANGES=RANGES,
        range_=range_,
        from_=from_text,
        to=to_text,
        window=window,
        n_ok=n_ok,
        n_fail=n_fail,
        qs=qs,
        qargs=qargs,
    )


@app.route("/api-log/<int:lid>")
@login_required("view")
def api_log_detail(lid):
    row = db().one("SELECT * FROM api_log WHERE id=%s", (lid,)) or abort(404)
    payload = []
    try:
        data = json.loads(row["request_body"] or "{}")
        units = {r["tag_name"]: r["unit"] for r in db().all("SELECT tag_name, unit FROM api_tag_catalog")}
        payload = [(k, v, units.get(k, "")) for k, v in data.items()]
    except Exception:
        pass
    return render_template("api_log_detail.html", r=row, payload=payload)


# ----------------------------------------------------------------------------- users & audit (admin)
@app.route("/users")
@login_required("admin")
def users():
    return render_template("users.html", users=db().all("SELECT * FROM app_users ORDER BY id"))


@app.route("/users/new", methods=["GET", "POST"])
@app.route("/users/<int:uid>/edit", methods=["GET", "POST"])
@login_required("admin")
def user_edit(uid=None):
    u = db().one("SELECT * FROM app_users WHERE id=%s", (uid,)) if uid else dict(username="", role="viewer", enabled=True)
    if uid and not u:
        abort(404)
    if request.method == "POST":
        f, err = request.form, []
        name, role, pw = f.get("username", "").strip(), f.get("role"), f.get("password", "")
        enabled = "enabled" in f
        if role not in ROLES:
            err.append("Invalid role")
        if not uid and len(pw) < 8:
            err.append("Password must be at least 8 characters")
        if uid and pw and len(pw) < 8:
            err.append("Password must be at least 8 characters")
        if uid == g.user["id"] and (role != "admin" or not enabled):
            err.append("You cannot remove your own admin role or disable yourself")
        if not err:
            try:
                if uid:
                    sets, vals = "role=%s, enabled=%s", [role, enabled]
                    if pw:
                        sets += ", password_hash=%s, must_change_password=TRUE"
                        vals.append(generate_password_hash(pw))
                    db().run(f"UPDATE app_users SET {sets} WHERE id=%s", [*vals, uid])
                    audit("update", "user", f"{u['username']} role={role} enabled={enabled}{' +password reset' if pw else ''}")
                else:
                    db().run("INSERT INTO app_users (username, password_hash, role, enabled, must_change_password) "
                             "VALUES (%s,%s,%s,%s,TRUE)", (name, generate_password_hash(pw), role, enabled))
                    audit("create", "user", f"{name} role={role}")
                flash("User saved (the user must change the password at next login).", "ok")
                return redirect(url_for("users"))
            except psycopg2.Error as e:
                err.append("Username invalid or already exists (3-64 chars: letters, digits, _ . @ -)"
                           if isinstance(e, (psycopg2.errors.UniqueViolation, psycopg2.errors.CheckViolation)) else str(e))
        for e in err:
            flash(e, "error")
        u = dict(username=name or (u or {}).get("username", ""), role=role, enabled=enabled, id=uid)
    return render_template("user_form.html", u=u, uid=uid, ROLES=ROLES)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@login_required("admin")
def user_delete(uid):
    if uid == g.user["id"]:
        flash("You cannot delete yourself.", "error")
    else:
        row = db().one("DELETE FROM app_users WHERE id=%s RETURNING username", (uid,))
        audit("delete", "user", row["username"] if row else f"id {uid}")
        flash("User deleted.", "ok")
    return redirect(url_for("users"))


@app.route("/audit")
@login_required("admin")
def audit_view():
    return render_template("audit.html", rows=db().all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300"))


# ----------------------------------------------------------------------------- start-up
def ensure_admin():
    if db().one("SELECT count(*) AS n FROM app_users")["n"] == 0:
        pw = os.getenv("UI_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
        print("First start: creating user 'admin' with password:", pw)
        db().run("INSERT INTO app_users (username, password_hash, role, must_change_password) VALUES ('admin',%s,'admin',TRUE)",
                 (generate_password_hash(pw),))
        log.warning("=" * 60)
        log.warning("First start: created user 'admin' with password: %s   (must be changed at first login)", pw)
        log.warning("=" * 60)


def secret_key():
    key = os.getenv("UI_SECRET_KEY")
    if not key:
        log.warning("UI_SECRET_KEY not set - using a random key (sessions are lost on restart)")
        key = secrets.token_hex(32)
    return key


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    if len(sys.argv) == 3 and sys.argv[1] == "reset-password":
        pw = secrets.token_urlsafe(9)
        n = db().run("UPDATE app_users SET password_hash=%s, must_change_password=TRUE, enabled=TRUE WHERE username=%s",
                     (generate_password_hash(pw), sys.argv[2]))
        print(f"New temporary password for {sys.argv[2]}: {pw}" if n else "No such user")
        return
    app.secret_key = secret_key()
    ensure_admin()
    from waitress import serve
    host, port = os.getenv("UI_HOST", "0.0.0.0"), int(os.getenv("UI_PORT", "8088"))
    log.info("Configuration UI on http://%s:%s", host, port)
    serve(app, host=host, port=port, threads=6)


if __name__ == "__main__":
    main()
