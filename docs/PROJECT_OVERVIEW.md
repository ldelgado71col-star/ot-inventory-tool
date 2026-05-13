# OT Inventory Tool — Project Overview

## Problem Statement

Industrial facilities (manufacturing plants, utilities, oil & gas) lack reliable, up-to-date inventories of their OT/ICS technology assets. Without this visibility:

- Cybersecurity teams cannot assess risk or respond to incidents effectively
- Maintenance teams miss firmware updates and end-of-life equipment
- Engineering teams lack accurate documentation of installed devices
- Compliance audits require manual, time-consuming asset walks
- New vulnerabilities cannot be correlated against installed assets

## Solution

A modular OT asset discovery and inventory platform that:

1. Discovers assets passively by monitoring network traffic
2. Supplements with controlled, low-impact active scanning
3. Identifies industrial protocols and device types automatically
4. Maintains a structured, searchable asset database
5. Detects changes over time (new devices, missing devices, config changes)
6. Generates reports for multiple stakeholders

## Target Users

| User | Need |
|---|---|
| OT/ICS Engineer | Accurate device list with firmware versions and IP addresses |
| Cybersecurity Analyst | Risk scores, vulnerabilities, communication maps |
| Maintenance Technician | End-of-life status, spare parts, maintenance history |
| Plant Manager | Summary reports, compliance status |
| Potenza Field Technician | Fast asset capture during site assessments |

## Core Modules

| Module | Description |
|---|---|
| Discovery Engine | Passive + controlled active asset discovery |
| Protocol Identification | Recognizes OT/IT protocols on the network |
| Asset Fingerprinting | Correlates MAC, IP, vendor, device type |
| Asset Database | Structured inventory with full asset metadata |
| Change Detection | Alerts on new, missing, or changed assets |
| Risk Analysis | Scores assets by criticality and obsolescence |
| Reporting Engine | Generates PDF, CSV, and dashboard reports |
| REST API | Integration with CMDB, SIEM, ticketing systems |
| Web Dashboard | User interface for all platform functions |

## Key Constraints

- Must NOT disrupt OT network operations
- Must support legacy devices and protocols
- Must work in air-gapped or restricted network environments
- Must support role-based access control
- Must maintain full audit log of all actions

## Current Phase

**Phase 0 — Project Setup**
- Repository initialized
- Architecture defined
- Development environment configured

## Project Owner

Potenza Services Inc.
