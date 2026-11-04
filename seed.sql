-- =============================================================================
-- Sample configuration - EDIT THE VALUES, then enable. Loaded once by setup_db.sh.
-- Everything here can be changed later with plain SQL; the running service
-- re-reads the tables on every cycle (no restart needed).
-- =============================================================================

-- API integration (Device ID + Secret Key come from the Gobardhan portal)
INSERT INTO api_config (id, api_url, scada_device_id, secret_key,
                        publish_interval_s, enabled)
VALUES (1, 'https://<your-domain>/api/v1/public/scada/telemetry',
        'HR_AR_0001_M_11', 'scada_sec_key_2026_test_12345',
        60, FALSE)                       -- FALSE until you set the real URL/keys
ON CONFLICT (id) DO NOTHING;

-- One sample Modbus TCP device (PLC / SCADA)
INSERT INTO modbus_devices (device_name, description, enabled, protocol,
                            ip_address, port, unit_id,
                            timeout_ms, retry_count, poll_interval_ms)
VALUES ('PLC-1', 'CBG plant main PLC', FALSE, 'TCP',
        '192.168.1.10', 502, 1,
        3000, 3, 5000)                   -- poll every 5 s
ON CONFLICT (device_name) DO NOTHING;

-- Sample RTU (RS485) device - disabled
INSERT INTO modbus_devices (device_name, description, enabled, protocol,
                            com_port, baud_rate, data_bits, stop_bits, parity, slave_id,
                            timeout_ms, retry_count, poll_interval_ms)
VALUES ('GasAnalyser-AIT101', 'Gas analyser on RS485', FALSE, 'RTU',
        '/dev/ttyUSB0', 9600, 8, 1, 'None', 2,
        1000, 3, 10000)
ON CONFLICT (device_name) DO NOTHING;

-- Tags for PLC-1: holding registers, 32-bit float, 2 registers each
INSERT INTO modbus_tags (device_id, tag_name, description, function_code, address, data_type, length)
SELECT d.id, t.tag_name, t.descr, 3, t.addr, 'FLOAT', 2
FROM   modbus_devices d
JOIN  (VALUES
        ('fresh_slurry_flow_scm_hr',    'Fresh slurry flow',      100),
        ('raw_biogas_flow_scm_hr',      'Raw biogas flow',        102),
        ('purified_biogas_flow_scm_hr', 'Purified biogas flow',   104),
        ('dispatch_flow_kg_hr',         'Dispatch flow',          106),
        ('slurry_FlowTotalizer_scm',    'Slurry totaliser',       108),
        ('raw_FlowTotalizer_scm',       'Raw biogas totaliser',   110),
        ('purified_FlowTotalizer_scm',  'Purified totaliser',     112),
        ('dispatch_flowTotalizer_kg',   'Dispatch totaliser',     114)
      ) AS t(tag_name, descr, addr) ON TRUE
WHERE  d.device_name = 'PLC-1'
  AND  NOT EXISTS (SELECT 1 FROM modbus_tags x WHERE x.device_id = d.id);   -- only seed an empty device

-- Tags for the gas analyser (RTU)
INSERT INTO modbus_tags (device_id, tag_name, description, function_code, address, data_type, length)
SELECT d.id, t.tag_name, t.descr, 3, t.addr, 'FLOAT', 2
FROM   modbus_devices d
JOIN  (VALUES
        ('moisture_mg_m3',                 'Moisture',          0),
        ('methane_mole_percent',           'CH4',               2),
        ('h2s_mg_m3',                      'H2S',               4),
        ('totalSulphurIncludingH2s_mg_m3', 'Total sulphur',     6),
        ('co2N2O2_mole_percent',           'CO2+N2+O2',         8),
        ('co2_mole_percent',               'CO2',              10),
        ('oxygen_mole_percent',            'O2',               12)
      ) AS t(tag_name, descr, addr) ON TRUE
WHERE  d.device_name = 'GasAnalyser-AIT101'
  AND  NOT EXISTS (SELECT 1 FROM modbus_tags x WHERE x.device_id = d.id);
