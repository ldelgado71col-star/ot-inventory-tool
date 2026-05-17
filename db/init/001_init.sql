CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_tag VARCHAR(100) UNIQUE NOT NULL,
    vendor VARCHAR(100),
    device_type VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(100),
    ip_address INET,
    protocol VARCHAR(50),
    location VARCHAR(150),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_observations (
    time TIMESTAMPTZ NOT NULL,
    asset_tag VARCHAR(100) NOT NULL,
    parameter VARCHAR(100) NOT NULL,
    value_text TEXT,
    value_numeric DOUBLE PRECISION,
    source_protocol VARCHAR(50),
    quality VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

SELECT create_hypertable(
    'asset_observations',
    'time',
    if_not_exists => TRUE
);

INSERT INTO assets (
    asset_tag,
    vendor,
    device_type,
    model,
    firmware_version,
    ip_address,
    protocol,
    location
)
VALUES
(
    'PLC-LAB-001',
    'Rockwell Automation',
    'PLC',
    'ControlLogix 1756-L81E',
    'Test',
    '192.168.1.100',
    'EtherNet/IP',
    'Lab Hyper-V'
)
ON CONFLICT (asset_tag) DO NOTHING;
