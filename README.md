# OT Inventory Tool

**OT Network Asset Discovery and Inventory Platform**

A modular platform for discovering, classifying, documenting, and monitoring technology assets in industrial (OT/ICS) networks — with minimal operational impact.

---

## What this tool does

- Discovers OT assets passively and via controlled active scanning
- Identifies industrial protocols (EtherNet/IP, Modbus, PROFINET, OPC UA, DNP3, BACnet)
- Builds and maintains a structured asset inventory database
- Detects new, changed, and missing assets
- Generates reports for engineering, cybersecurity, maintenance, and compliance teams
- Provides a web dashboard for asset visualization and management

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Web Dashboard                      │
├─────────────────────────────────────────────────────┤
│                    REST API (FastAPI)                │
├──────────┬──────────┬──────────┬────────────────────┤
│ Discovery│ Protocol │   Risk   │     Reporting       │
│  Engine  │   ID     │ Analysis │      Module         │
├──────────┴──────────┴──────────┴────────────────────┤
│              Asset Database (PostgreSQL)             │
└─────────────────────────────────────────────────────┘
```

---

## Project Structure

```
ot-inventory-tool/
├── backend/                  # Python / FastAPI backend
│   ├── app/
│   │   ├── api/              # REST API endpoints
│   │   ├── core/             # Config, security, logging
│   │   ├── db/               # Database models and migrations
│   │   ├── modules/          # Core business logic modules
│   │   │   ├── discovery/    # Asset discovery engine
│   │   │   ├── fingerprinting/ # Device fingerprinting
│   │   │   ├── protocols/    # Industrial protocol identification
│   │   │   ├── risk/         # Risk and obsolescence analysis
│   │   │   ├── reporting/    # Report generation
│   │   │   └── change_detection/ # Change detection engine
│   │   └── schemas/          # Pydantic data schemas
│   └── tests/
├── frontend/                 # Web dashboard (React)
├── infrastructure/           # Docker, deployment scripts
├── config/                   # Configuration files
├── docs/                     # Architecture, API docs, specs
└── .github/                  # CI/CD workflows, issue templates
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy + Alembic |
| Frontend | React + TypeScript |
| Containerization | Docker + Docker Compose |
| CI/CD | GitHub Actions |

---

## Safety Principles

> This tool is designed for OT/ICS environments. The following principles are non-negotiable:

- **Passive discovery first** — never aggressive scanning by default
- **Scan rate limiting** — all active scans are throttled and configurable
- **Exclusion lists** — safety systems, PLCs, and critical devices can be excluded
- **Maintenance window enforcement** — active scans only during approved windows
- **Read-only queries** — credentialed access uses read-only credentials only
- **Lab testing required** — always test scanning config in a lab before production

---

## Project Status

| Phase | Status | Description |
|---|---|---|
| Phase 0 | ✅ In progress | Project setup and architecture |
| Phase 1 | 🔲 Planned | Asset database and manual registration |
| Phase 2 | 🔲 Planned | Passive discovery engine |
| Phase 3 | 🔲 Planned | Active scanning (controlled) |
| Phase 4 | 🔲 Planned | Web dashboard |
| Phase 5 | 🔲 Planned | Reporting and exports |

---

## Getting Started

See [docs/architecture/SETUP.md](docs/architecture/SETUP.md) for environment setup instructions.

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built by Potenza Services Inc.*
