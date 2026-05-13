# Scanning Strategy

## Guiding Principle

> OT networks are not IT networks. Aggressive scanning can crash PLCs, trip safety systems, or disrupt production. All scanning decisions must be made with OT personnel involvement.

## Scan Levels

### Level 0 — Passive Only (Default)
- Listens to network traffic without sending any packets
- Zero impact on network or devices
- Discovers assets that communicate on the monitored segment
- **Safe for all environments including production**

### Level 1 — ARP Discovery (Low Impact)
- Sends ARP requests to enumerate live hosts on a subnet
- Read by virtually all devices; extremely low risk
- Must be rate-limited (recommended: max 1 packet/second)
- **Requires OT personnel approval before enabling**

### Level 2 — ICMP Ping Sweep (Low-Medium Impact)
- Sends ICMP echo requests to confirm host availability
- Some legacy PLCs may respond poorly to ICMP
- Must be rate-limited and tested in lab first
- **Requires OT personnel approval and exclusion list**

### Level 3 — Controlled Port Scan (Medium Impact)
- Targeted TCP/UDP port scanning on specific ports
- Only safe ports: common OT service ports
- Must never scan safety systems or known-fragile devices
- **Requires maintenance window and explicit approval**

### Level 4 — Credentialed Query (Low Impact if configured correctly)
- SNMP v2c/v3 read-only queries
- OPC UA read-only sessions
- SSH/REST API queries to supported devices
- **Requires valid read-only credentials and device owner approval**

## Safe Scanning Configuration

### Always Required
- Maximum packet rate: configurable, default 10 packets/second
- Timeout per host: 2 seconds maximum
- Retries: 1 maximum
- Exclusion list: mandatory before any active scan

### Exclusion List — Mandatory Entries
The following device types SHALL always be on the exclusion list unless explicitly removed by OT personnel:

- Safety Instrumented Systems (SIS)
- Emergency Shutdown Systems (ESD)
- Protection relays (IEC 61850)
- Known legacy PLCs (to be confirmed per site)
- Any device flagged as "do not scan" in the asset database

### Scan Windows
Active scans (Level 1+) SHALL only run during approved maintenance windows unless passive (Level 0).

## Protocol-Specific Guidance

| Protocol | Safe to Query? | Method | Notes |
|---|---|---|---|
| EtherNet/IP | Caution | Identity object only | Do not send control commands |
| Modbus TCP | Caution | Read-only function codes | FC 01, 02, 03, 04 only |
| PROFINET | Caution | DCP identify only | Never write |
| OPC UA | Yes (credentialed) | Read-only session | Requires valid endpoint |
| SNMP | Yes (v3 preferred) | GET only, no SET | Use read-only community string |
| DNP3 | High caution | Passive observation only | Do not send control objects |
| BACnet/IP | Caution | Read properties only | Never write |

## Pre-Scan Checklist

Before enabling any active scan (Level 1+):

- [ ] Reviewed exclusion list with OT engineer
- [ ] Confirmed maintenance window with plant operations
- [ ] Tested scan configuration in lab or non-production network
- [ ] Set scan rate to minimum effective value
- [ ] Confirmed read-only mode for all credentialed queries
- [ ] Verified rollback plan if issues occur
- [ ] Documented approval from OT personnel
