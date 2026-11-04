#!/usr/bin/env bash
# =============================================================================
# Deploy the Edge Gateway PostgreSQL database on a Linux terminal.
#   sudo ./setup_db.sh                 # random password, written to env file
#   sudo GW_DB_PASSWORD='xyz' ./setup_db.sh
# Idempotent: safe to run again (existing role/db/data are kept).
# =============================================================================
set -euo pipefail

DB_NAME="${GW_DB_NAME:-edge_gateway}"
DB_USER="${GW_DB_USER:-gateway}"
DB_PASS="${GW_DB_PASSWORD:-}"
ENV_DIR="/etc/edge-gateway"
ENV_FILE="$ENV_DIR/gateway.env"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

# 1. Install PostgreSQL --------------------------------------------------------
if ! command -v psql >/dev/null 2>&1; then
    echo ">> Installing PostgreSQL"
    if   command -v apt-get >/dev/null; then apt-get update -y && apt-get install -y postgresql postgresql-client
    elif command -v dnf     >/dev/null; then dnf install -y postgresql-server postgresql && postgresql-setup --initdb
    elif command -v yum     >/dev/null; then yum install -y postgresql-server postgresql && postgresql-setup initdb
    else echo "Unsupported distro - install PostgreSQL manually." >&2; exit 1; fi
fi

# 2. Start the service ---------------------------------------------------------
echo ">> Starting PostgreSQL"
systemctl enable --now postgresql 2>/dev/null || service postgresql start || pg_ctlcluster "$(ls /etc/postgresql | tail -1)" main start || true
for i in $(seq 1 20); do
    runuser -u postgres -- psql -qtAc "SELECT 1" >/dev/null 2>&1 && break || sleep 1
done

# 3. Role + database -----------------------------------------------------------
[ -n "$DB_PASS" ] || DB_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"

echo ">> Creating role '$DB_USER' and database '$DB_NAME'"
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v u="$DB_USER" -v p="$DB_PASS" -v d="$DB_NAME" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'u', :'p')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'u') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'u', :'p') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'d', :'u')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'d') \gexec
SQL

# 4. Schema + sample data (as the application role) ---------------------------
echo ">> Applying schema.sql, schema_v2.sql and seed.sql"
export PGPASSWORD="$DB_PASS"
psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -f "$HERE/schema.sql"
psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -f "$HERE/schema_v2.sql"
psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -f "$HERE/seed.sql"

# 5. Credentials for the gateway service --------------------------------------
install -d -m 750 "$ENV_DIR"
# keep an existing UI session secret across re-runs
UI_SECRET="$(grep -s '^UI_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2- || true)"
[ -n "$UI_SECRET" ] || UI_SECRET="$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48)"
cat > "$ENV_FILE" <<EOF
GW_DB_HOST=127.0.0.1
GW_DB_PORT=5432
GW_DB_NAME=$DB_NAME
GW_DB_USER=$DB_USER
GW_DB_PASSWORD=$DB_PASS
UI_SECRET_KEY=$UI_SECRET
UI_HOST=0.0.0.0
UI_PORT=8088
UI_ADMIN_PASSWORD=Admin#12345        # first-start admin password (UI forces a change)
GW_LOG_LEVEL=INFO
GW_CONFIG_SYNC_S=3
Write-Host=Environment set for this window.
UI_THEME=bootstrap
EOF
chmod 600 "$ENV_FILE"

echo
echo "Done. DB '$DB_NAME' ready, credentials in $ENV_FILE"
echo "Next: edit api_config / modbus_devices / modbus_tags, e.g."
echo "  psql -h 127.0.0.1 -U $DB_USER -d $DB_NAME"
