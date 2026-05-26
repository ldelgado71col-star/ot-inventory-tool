ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_address VARCHAR(17);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS classification_source VARCHAR(50);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS subnet VARCHAR(20);

UPDATE assets
SET mac_address = CONCAT(
    SUBSTRING(asset_tag FROM 5 FOR 2), ':',
    SUBSTRING(asset_tag FROM 7 FOR 2), ':',
    SUBSTRING(asset_tag FROM 9 FOR 2), ':',
    SUBSTRING(asset_tag FROM 11 FOR 2), ':',
    SUBSTRING(asset_tag FROM 13 FOR 2), ':',
    SUBSTRING(asset_tag FROM 15 FOR 2)
)
WHERE asset_tag LIKE 'NET-%'
  AND mac_address IS NULL
  AND LENGTH(asset_tag) = 16;

UPDATE assets
SET first_seen = created_at, last_seen = created_at
WHERE first_seen IS NULL;

CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets (last_seen);
CREATE INDEX IF NOT EXISTS idx_assets_subnet ON assets (subnet);
