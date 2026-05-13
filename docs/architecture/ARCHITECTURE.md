# System Architecture

## Architecture Style

Modular monolith with clean module boundaries.
Designed to evolve toward microservices if scale requires it.

## Component Diagram

```
                        ┌─────────────────────────┐
                        │      Web Dashboard       │
                        │   React + TypeScript     │
                        └───────────┬─────────────┘
                                    │ HTTPS / REST
                        ┌───────────▼─────────────┐
                        │     API Layer (FastAPI)  │
                        │   Authentication / RBAC  │
                        └──┬────┬────┬────┬───────┘
                           │    │    │    │
              ┌────────────▼┐ ┌─▼───┐│┌──▼──────────┐
              │  Discovery  │ │Proto││ │   Risk &    │
              │   Engine   │ │  ID ││ │ Obsolescence│
              └────────────┘ └─────┘│└─────────────┘
                                    │
              ┌─────────────────────▼──────────────┐
              │         Asset Database              │
              │           PostgreSQL                │
              └────────────────────────────────────┘
```

## Module Descriptions

### Discovery Engine
- Passive monitoring via packet capture (libpcap / scapy)
- Controlled active scanning (ARP ping, ICMP, selective TCP)
- Scan policy enforcement (rate limits, exclusions, time windows)
- Outputs: IP, MAC, hostname, first/last seen timestamps

### Protocol Identification Module
- Detects OT protocols: EtherNet/IP, Modbus TCP, PROFINET, OPC UA, DNP3, BACnet/IP
- Detects IT protocols: SNMP, HTTP/S, SSH, RDP, SMB
- Port-based and payload-based identification
- Confidence scoring per protocol detection

### Asset Fingerprinting Module
- MAC OUI lookup → vendor identification
- Banner grabbing (where safe and permitted)
- SNMP sysDescr, sysName queries (read-only)
- Device type classification based on protocol + vendor

### Asset Database
- Canonical record per asset (IP + MAC correlation)
- Full metadata schema (see DATA_MODEL.md)
- Version history per asset record
- PostgreSQL with SQLAlchemy ORM

### Change Detection Module
- Scheduled comparison of current scan vs. last known state
- Detects: new assets, missing assets, IP changes, firmware changes
- Generates alerts and change log entries

### Risk Analysis Module
- Criticality classification (manual + rule-based)
- Obsolescence assessment (EOL database lookup)
- Risk scoring formula (criticality × exposure × vulnerability)
- To be confirmed: integration with external CVE/EOL databases

### Reporting Engine
- PDF reports (engineering, cybersecurity, compliance)
- CSV/Excel export of asset inventory
- JSON export for CMDB/SIEM integration

### REST API Layer
- FastAPI framework
- OpenAPI / Swagger documentation auto-generated
- JWT authentication
- Role-based access control (Admin, Analyst, Viewer, Technician)

### Web Dashboard
- React + TypeScript
- Asset inventory table with filtering and search
- Asset detail view
- Network topology visualization (planned)
- Report generation interface

## Data Flow

```
Network Traffic
      │
      ▼
Passive Sensor ──────────────────────────┐
      │                                   │
      │                                   ▼
Active Scanner ──────► Protocol ID ──► Fingerprinting
                                          │
                                          ▼
                                    Asset Database
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                    Change Detection   Risk Analysis   Reporting
                          │               │               │
                          └───────────────┴───────────────┘
                                          │
                                       API Layer
                                          │
                                    Web Dashboard
```

## Deployment Model

```
Docker Compose (single host, development and small deployments)

Services:
  - ot-api         (FastAPI backend)
  - ot-frontend    (React, served via nginx)
  - ot-db          (PostgreSQL)
  - ot-sensor      (passive capture, requires host network access)
```

## Security Architecture

- All API communication over HTTPS (TLS 1.2+)
- JWT tokens with configurable expiry
- Credentials stored encrypted (AES-256)
- No credentials stored in plaintext or environment variables in production
- Full audit log of all user actions and scan events
- Role-based access control enforced at API layer

## Technology Decisions

| Decision | Choice | Reason |
|---|---|---|
| Backend language | Python | Best library ecosystem for networking and OT protocols |
| API framework | FastAPI | Fast, async, auto OpenAPI docs |
| Database | PostgreSQL | Relational, reliable, strong JSON support |
| ORM | SQLAlchemy + Alembic | Industry standard, migration support |
| Frontend | React + TypeScript | Component-based, type-safe, large ecosystem |
| Containerization | Docker | Portability, isolation, easy deployment |
| Packet capture | Scapy | Python-native, OT protocol support |
