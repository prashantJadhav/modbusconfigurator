-- =============================================================================
-- Edifice Gateway - configuration, runtime and log schema  (PostgreSQL 12+)
-- Apply with:  psql -U gateway -d edge_gateway -f schema.sql
-- Safe to re-run (CREATE ... IF NOT EXISTS / ON CONFLICT DO NOTHING).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. API integration settings  (guide section 2 "API Integration" + endpoint)
--    Single-row table (id is forced to 1).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_config (
    id                  SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    api_url             TEXT        NOT NULL,                 -- full URL incl. /api/v1/public/scada/telemetry
    scada_device_id     TEXT        NOT NULL,                 -- sent as X-SCADA-Device-Id
    secret_key          TEXT        NOT NULL,                 -- HMAC shared secret (never sent / never logged)
    publish_interval_s  INTEGER     NOT NULL DEFAULT 60  CHECK (publish_interval_s >= 1),
    http_timeout_s      INTEGER     NOT NULL DEFAULT 15  CHECK (http_timeout_s >= 1),
    verify_ssl          BOOLEAN     NOT NULL DEFAULT TRUE,
    max_value_age_s     INTEGER     NOT NULL DEFAULT 120 CHECK (max_value_age_s >= 1),  -- ignore tag values older than this
    log_retention_days  INTEGER     NOT NULL DEFAULT 30  CHECK (log_retention_days >= 1),
    enabled             BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 2. Payload key catalogue  (guide section 5 - the "Tag Name" dropdown)
--    Only these keys can be mapped to Modbus tags.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_tag_catalog (
    tag_name     TEXT PRIMARY KEY,
    unit         TEXT,
    is_required  BOOLEAN NOT NULL DEFAULT FALSE,   -- "Required" in the guide: payload is not sent without it
    description  TEXT
);

INSERT INTO api_tag_catalog (tag_name, unit, is_required, description) VALUES
 ('moisture_mg_m3',                 'mg/m3',   FALSE, 'Moisture concentration (max 5.0)'),
 ('methane_mole_percent',           'mole %',  FALSE, 'CH4 measured by gas analyser AIT-101 (95.0 - 100.0)'),
 ('h2s_mg_m3',                      'mg/m3',   FALSE, 'Hydrogen sulphide (max 3.7)'),
 ('totalSulphurIncludingH2s_mg_m3', 'mg/m3',   FALSE, 'Total sulphur incl. H2S (max 10.0)'),
 ('co2N2O2_mole_percent',           'mole %',  FALSE, 'Combined CO2-N2-O2 (max 5.0)'),
 ('co2_mole_percent',               'mole %',  FALSE, 'Carbon dioxide (max 4.0)'),
 ('oxygen_mole_percent',            'mole %',  FALSE, 'Oxygen (max 0.5)'),
 ('fresh_slurry_flow_scm_hr',       'SCM/hr',  TRUE,  'Fresh slurry flow rate'),
 ('raw_biogas_flow_scm_hr',         'SCM/hr',  TRUE,  'Raw biogas flow rate'),
 ('purified_biogas_flow_scm_hr',    'SCM/hr',  TRUE,  'Purified biogas flow rate'),
 ('dispatch_flow_kg_hr',            'kg/hr',   TRUE,  'Dispatch flow rate'),
 ('slurry_FlowTotalizer_scm',       'SCM',     TRUE,  'Slurry flow totaliser'),
 ('raw_FlowTotalizer_scm',          'SCM',     TRUE,  'Raw biogas flow totaliser'),
 ('purified_FlowTotalizer_scm',     'SCM',     TRUE,  'Purified biogas flow totaliser'),
 ('dispatch_flowTotalizer_kg',      'kg',      TRUE,  'Dispatch totaliser')
ON CONFLICT (tag_name) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 3. Modbus devices  (guide section 3 - Device Configuration page)
--    Polling frequency = poll_interval_ms (per device). Edits are picked up
--    by the running service on the device's next poll cycle.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modbus_devices (
    id               SERIAL PRIMARY KEY,
    device_name      TEXT    NOT NULL UNIQUE,
    description      TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    protocol         TEXT    NOT NULL CHECK (protocol IN ('RTU','TCP')),

    -- common
    timeout_ms       INTEGER NOT NULL DEFAULT 3000 CHECK (timeout_ms > 0),
    retry_count      INTEGER NOT NULL DEFAULT 3    CHECK (retry_count >= 0),
    poll_interval_ms INTEGER NOT NULL DEFAULT 5000 CHECK (poll_interval_ms >= 100),

    -- TCP only
    ip_address       TEXT,
    port             INTEGER DEFAULT 502 CHECK (port BETWEEN 1 AND 65535),
    unit_id          INTEGER CHECK (unit_id BETWEEN 0 AND 255),

    -- RTU (RS485) only.  On Linux use /dev/ttyS0, /dev/ttyUSB0, /dev/ttyAMA0 ...
    com_port         TEXT,
    baud_rate        INTEGER CHECK (baud_rate IN (1200,2400,4800,9600,19200,38400,57600,115200)),
    data_bits        INTEGER CHECK (data_bits IN (7,8)),
    stop_bits        INTEGER CHECK (stop_bits IN (1,2)),
    parity           TEXT    CHECK (parity IN ('None','Even','Odd')),
    slave_id         INTEGER CHECK (slave_id BETWEEN 0 AND 255),

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- "Visible only when Protocol = ..." rules from the guide
    CONSTRAINT chk_tcp_fields CHECK (protocol <> 'TCP' OR
        (ip_address IS NOT NULL AND port IS NOT NULL AND unit_id IS NOT NULL)),
    CONSTRAINT chk_rtu_fields CHECK (protocol <> 'RTU' OR
        (com_port IS NOT NULL AND baud_rate IS NOT NULL AND data_bits IS NOT NULL
         AND stop_bits IS NOT NULL AND parity IS NOT NULL AND slave_id IS NOT NULL)),
    CONSTRAINT chk_ipv4 CHECK (ip_address IS NULL OR ip_address ~
        '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$')
);

-- -----------------------------------------------------------------------------
-- 4. Modbus tags / registers  (guide section 3 - Tag / Register Configuration)
--    One row maps one Modbus point to one JSON payload key.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modbus_tags (
    id            SERIAL  PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES modbus_devices(id) ON DELETE CASCADE,
    tag_name      TEXT    NOT NULL UNIQUE REFERENCES api_tag_catalog(tag_name),
    description   TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,

    function_code SMALLINT NOT NULL CHECK (function_code IN (1,2,3,4,5,6,15,16)),
    address       INTEGER  NOT NULL CHECK (address BETWEEN 0 AND 65535),   -- zero-based PDU address
    data_type     TEXT     NOT NULL CHECK (data_type IN
                      ('BOOL','INT16','UINT16','INT32','UINT32','FLOAT','DOUBLE64')),
    length        INTEGER  NOT NULL CHECK (length >= 1),                   -- register / coil count

    -- decoding & conversion extras
    byte_order    TEXT NOT NULL DEFAULT 'BIG' CHECK (byte_order IN ('BIG','LITTLE')),  -- bytes inside a register
    word_order    TEXT NOT NULL DEFAULT 'BIG' CHECK (word_order IN ('BIG','LITTLE')),  -- BIG = high word first (AB CD)
    scale_factor  DOUBLE PRECISION NOT NULL DEFAULT 1,
    offset_value  DOUBLE PRECISION NOT NULL DEFAULT 0,                     -- final = raw * scale_factor + offset_value
    decimals      SMALLINT NOT NULL DEFAULT 3 CHECK (decimals BETWEEN 0 AND 10),

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- data type <-> Modbus register usage (guide table)
    CONSTRAINT chk_len_for_type CHECK (
        (data_type IN ('BOOL','INT16','UINT16') AND length = 1) OR
        (data_type IN ('INT32','UINT32','FLOAT') AND length = 2) OR
        (data_type = 'DOUBLE64'                  AND length = 4)),
    -- BOOL -> coil / discrete input FCs, everything else -> register FCs
    CONSTRAINT chk_fc_for_type CHECK (
        (data_type = 'BOOL'  AND function_code IN (1,2,5,15)) OR
        (data_type <> 'BOOL' AND function_code IN (3,4,6,16)))
);
CREATE INDEX IF NOT EXISTS idx_tags_device ON modbus_tags(device_id);

-- -----------------------------------------------------------------------------
-- 5. Latest value per tag  (written by pollers, read by the API publisher)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tag_values (
    tag_id    INTEGER PRIMARY KEY REFERENCES modbus_tags(id) ON DELETE CASCADE,
    value     DOUBLE PRECISION,
    quality   TEXT NOT NULL DEFAULT 'BAD' CHECK (quality IN ('GOOD','BAD')),
    read_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    error     TEXT
);

-- -----------------------------------------------------------------------------
-- 6. Communication diagnostics  (guide section 3 - Diagnostics UI)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_diagnostics (
    device_id            INTEGER PRIMARY KEY REFERENCES modbus_devices(id) ON DELETE CASCADE,
    connection_status    TEXT   NOT NULL DEFAULT 'Disconnected' CHECK (connection_status IN ('Connected','Disconnected')),
    last_comm_time       TIMESTAMPTZ,
    response_time_ms     INTEGER,
    success_count        BIGINT NOT NULL DEFAULT 0,
    fail_count           BIGINT NOT NULL DEFAULT 0,
    crc_error_count      BIGINT NOT NULL DEFAULT 0,
    timeout_error_count  BIGINT NOT NULL DEFAULT 0,
    last_error           TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- 7. API request / response log  (guide section "API Response Log UI")
--    One row per publish attempt.  The secret key is NEVER stored here.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_log (
    id                BIGSERIAL PRIMARY KEY,
    logged_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_url       TEXT,
    request_headers   JSONB,          -- X-SCADA-Device-Id / Timestamp / Signature
    request_body      TEXT,           -- exact minified JSON that was signed and sent
    http_status       INTEGER,        -- NULL = nothing was sent / no HTTP response
    response_message  TEXT,           -- "message" field of the API response (or local error text)
    response_body     TEXT,           -- raw response
    success           BOOLEAN NOT NULL DEFAULT FALSE,
    duration_ms       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_log_logged_at ON api_log(logged_at DESC);

-- "Logs for Today" screen: Timestamp | Response code | Response message | Sent payload
CREATE OR REPLACE VIEW v_api_log_today AS
SELECT logged_at       AS "Timestamp",
       http_status     AS "API response code",
       response_message AS "API response message",
       request_body    AS "Sent payload"
FROM   api_log
WHERE  logged_at >= date_trunc('day', now())
ORDER  BY logged_at DESC;

-- Convenience view for the monitoring screen
CREATE OR REPLACE VIEW v_device_status AS
SELECT d.id, d.device_name, d.protocol, d.enabled, d.poll_interval_ms,
       g.connection_status, g.last_comm_time, g.response_time_ms,
       g.success_count, g.fail_count, g.crc_error_count, g.timeout_error_count, g.last_error
FROM   modbus_devices d LEFT JOIN device_diagnostics g ON g.device_id = d.id;
