# Asset Data Model

## Asset Table — Core Fields

| Field | Type | Description |
|---|---|---|
| asset_id | UUID | Primary key, auto-generated |
| ip_address | INET | Current IP address |
| mac_address | MACADDR | MAC address (primary hardware identifier) |
| hostname | VARCHAR(255) | DNS hostname or NetBIOS name |
| vendor | VARCHAR(255) | Hardware vendor (from MAC OUI or SNMP) |
| model | VARCHAR(255) | Device model number |
| firmware_version | VARCHAR(100) | Firmware or software version |
| serial_number | VARCHAR(100) | Device serial number |
| device_type | VARCHAR(100) | PLC, HMI, Switch, RTU, Historian, etc. |
| asset_role | VARCHAR(255) | Functional role in the process |
| location | VARCHAR(255) | Physical location description |
| site | VARCHAR(100) | Plant or facility name |
| area | VARCHAR(100) | Production area or line |
| vlan_id | INTEGER | VLAN number |
| subnet | CIDR | Network subnet |
| operating_system | VARCHAR(255) | OS name and version if known |
| first_seen | TIMESTAMP | When asset was first discovered |
| last_seen | TIMESTAMP | Most recent detection timestamp |
| criticality | VARCHAR(20) | Critical / High / Medium / Low |
| risk_score | DECIMAL(5,2) | Calculated risk score 0–100 |
| obsolescence_status | VARCHAR(50) | Supported / EOL / End-of-Sale / Unknown |
| data_source | VARCHAR(100) | passive / active / snmp / manual |
| confidence_level | VARCHAR(20) | High / Medium / Low |
| validation_status | VARCHAR(20) | Validated / Unvalidated / Disputed |
| owner | VARCHAR(255) | Responsible team or person |
| notes | TEXT | Free-text notes |
| created_at | TIMESTAMP | Record creation timestamp |
| updated_at | TIMESTAMP | Last record update timestamp |

## Asset Protocols Table

Many-to-many: one asset can have multiple detected protocols.

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| asset_id | UUID | Foreign key → assets |
| protocol | VARCHAR(100) | Protocol name (e.g., Modbus TCP) |
| port | INTEGER | Port number if applicable |
| confidence | VARCHAR(20) | High / Medium / Low |
| detected_at | TIMESTAMP | When protocol was detected |

## Asset Ports Table

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| asset_id | UUID | Foreign key → assets |
| port_number | INTEGER | TCP/UDP port number |
| transport | VARCHAR(10) | TCP / UDP |
| service | VARCHAR(100) | Service name (e.g., ssh, http) |
| banner | TEXT | Service banner if captured |
| detected_at | TIMESTAMP | Detection timestamp |

## Communication Map Table

Tracks observed communication between assets.

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| source_asset_id | UUID | Source asset |
| destination_asset_id | UUID | Destination asset |
| protocol | VARCHAR(100) | Protocol observed |
| port | INTEGER | Destination port |
| first_seen | TIMESTAMP | First observed |
| last_seen | TIMESTAMP | Most recently observed |
| packet_count | BIGINT | Observed packet count |

## Change Log Table

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| asset_id | UUID | Affected asset |
| change_type | VARCHAR(50) | new_asset / missing / ip_change / firmware_change / etc. |
| field_changed | VARCHAR(100) | Which field changed |
| old_value | TEXT | Previous value |
| new_value | TEXT | New value |
| detected_at | TIMESTAMP | When change was detected |
| acknowledged | BOOLEAN | Whether alert was acknowledged |
| acknowledged_by | VARCHAR(255) | User who acknowledged |

## Scan Jobs Table

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| scan_type | VARCHAR(50) | passive / arp / icmp / snmp / full |
| target_subnet | CIDR | Target network range |
| started_at | TIMESTAMP | Scan start time |
| completed_at | TIMESTAMP | Scan end time |
| status | VARCHAR(20) | running / completed / failed |
| assets_discovered | INTEGER | Count of assets found |
| initiated_by | VARCHAR(255) | User or scheduler |

## Audit Log Table

| Field | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| user_id | UUID | User who performed action |
| action | VARCHAR(100) | Action performed |
| resource_type | VARCHAR(100) | Asset / Scan / Report / User |
| resource_id | UUID | Affected resource ID |
| details | JSONB | Additional context |
| ip_address | INET | Client IP address |
| timestamp | TIMESTAMP | Event timestamp |
