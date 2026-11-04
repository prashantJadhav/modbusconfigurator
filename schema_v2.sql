-- =============================================================================
-- Schema v2 (apply AFTER schema.sql; idempotent) - adds what the Web UI needs
--   * serial hardware flow control + RTS delays   (Modbus Poll "Connection Details")
--   * per-device byte orders: Float / Long / Double 64-bit / Long 64-bit
--   * INT64 / UINT64 data types
--   * same payload key may exist on several tags, but only ONE can be enabled
--   * users / roles (RBAC) and an audit trail
-- =============================================================================

-- ---- devices: flow control + byte order -------------------------------------
ALTER TABLE modbus_devices
    ADD COLUMN IF NOT EXISTS wait_for_dsr        BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS wait_for_cts        BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dtr_control         TEXT NOT NULL DEFAULT 'Disable'
        CHECK (dtr_control IN ('Disable','Enable','Handshake')),
    ADD COLUMN IF NOT EXISTS rts_control         TEXT NOT NULL DEFAULT 'Disable'
        CHECK (rts_control IN ('Disable','Enable','Handshake','Toggle')),
    ADD COLUMN IF NOT EXISTS rts_delay_before_ms INTEGER NOT NULL DEFAULT 0   CHECK (rts_delay_before_ms >= 0),
    ADD COLUMN IF NOT EXISTS rts_delay_after_ms  INTEGER NOT NULL DEFAULT 235 CHECK (rts_delay_after_ms  >= 0),
    -- Digits = significance of each byte in the order it arrives on the wire.
    -- Order3210 = ABCD (big-endian), Order1032 = CDAB (word swap),
    -- Order2301 = BADC (byte swap),  Order0123 = DCBA (little-endian).
    ADD COLUMN IF NOT EXISTS float_byte_order    TEXT NOT NULL DEFAULT 'Order3210'
        CHECK (float_byte_order  IN ('Order3210','Order2301','Order1032','Order0123')),
    ADD COLUMN IF NOT EXISTS long_byte_order     TEXT NOT NULL DEFAULT 'Order3210'
        CHECK (long_byte_order   IN ('Order3210','Order2301','Order1032','Order0123')),
    ADD COLUMN IF NOT EXISTS double_byte_order   TEXT NOT NULL DEFAULT 'Order76543210'
        CHECK (double_byte_order IN ('Order76543210','Order67452301','Order10325476','Order32107654','Order01234567')),
    ADD COLUMN IF NOT EXISTS long64_byte_order   TEXT NOT NULL DEFAULT 'Order76543210'
        CHECK (long64_byte_order IN ('Order76543210','Order67452301','Order10325476','Order32107654','Order01234567'));

-- ---- tags: byte order now lives on the device --------------------------------
ALTER TABLE modbus_tags DROP COLUMN IF EXISTS byte_order;
ALTER TABLE modbus_tags DROP COLUMN IF EXISTS word_order;

ALTER TABLE modbus_tags DROP CONSTRAINT IF EXISTS modbus_tags_data_type_check;
ALTER TABLE modbus_tags ADD  CONSTRAINT modbus_tags_data_type_check CHECK (data_type IN
    ('BOOL','INT16','UINT16','INT32','UINT32','FLOAT','INT64','UINT64','DOUBLE64'));
ALTER TABLE modbus_tags DROP CONSTRAINT IF EXISTS chk_len_for_type;
ALTER TABLE modbus_tags ADD  CONSTRAINT chk_len_for_type CHECK (
    (data_type IN ('BOOL','INT16','UINT16')           AND length = 1) OR
    (data_type IN ('INT32','UINT32','FLOAT')          AND length = 2) OR
    (data_type IN ('INT64','UINT64','DOUBLE64')       AND length = 4));

-- A payload key may be defined on several tags (e.g. cloned devices) but only one may be ENABLED.
ALTER TABLE modbus_tags DROP CONSTRAINT IF EXISTS modbus_tags_tag_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_tags_name_enabled ON modbus_tags(tag_name) WHERE enabled;

-- ---- RBAC ---------------------------------------------------------------------
--   admin    : everything (users, API credentials, audit log)
--   engineer : devices, tags, clone, non-credential API settings
--   viewer   : read-only
CREATE TABLE IF NOT EXISTS app_users (
    id                   SERIAL PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9_.@-]{3,64}$'),
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('admin','engineer','viewer')),
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at        TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    username   TEXT,
    action     TEXT NOT NULL,
    entity     TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
