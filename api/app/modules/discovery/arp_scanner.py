#!/usr/bin/env python3
"""
arp_scanner.py — OT/Home Network ARP Discovery Module
Scans subnet, identifies vendors, classifies device types.
MAC address is the primary identifier — not IP (DHCP changes IPs).

v0.4.0 — Port-aware classification added (OT protocol detection)
"""

import re
import csv
import sys
from datetime import datetime

# ── OUI Lookup Table ──────────────────────────────────────────────────────
# Source: Advanced IP Scanner + manual identification
# Key = first 3 bytes of MAC (lowercase), Value = vendor name
OUI_LOOKUP = {
    # TP-Link routers / APs
    "00:31:92": "TP-Link Corporation Limited",
    # TP-Link EP25 Smart Plugs
    "78:8c:b5": "TP-Link EP25 Smart Plug",
    # TP-Link general
    "68:ff:7b": "TP-Link Technologies Co., Ltd.",
    # Espressif ESP32 / ESP8266 IoT modules
    "48:55:19": "Espressif Inc.",
    "48:e7:29": "Espressif Inc.",
    "0c:8b:95": "Espressif Inc.",
    "08:f9:e0": "Espressif Inc.",
    "3c:61:05": "Espressif Inc.",
    # Lutron lighting control
    "00:0f:e7": "Lutron Electronics Co., Inc.",
    # Emporia energy monitor
    "b0:f2:f6": "Emporia Energy Monitor",
    # Roborock robot vacuum
    "b0:4a:39": "Beijing Roborock Technology Co., Ltd.",
    # Lumi / Aqara Zigbee gateway
    "54:ef:44": "Lumi United Technology (Aqara/Xiaomi)",
    # Olibra / Bond Bridge RF controller
    "f4:4e:38": "Olibra LLC (Bond Bridge)",
    # Apple devices
    "04:99:b9": "Apple Inc.",
    # Dell computers
    "c8:15:4e": "Dell Inc.",
    # Hon Hai / Foxconn NICs
    "2c:6f:c9": "Hon Hai Precision Ind. (Foxconn)",
    # Epson printers
    "58:05:d9": "Seiko Epson Corporation",
    # Action Star USB Ethernet
    "00:24:9b": "Action Star Enterprise Co., Ltd.",
    # Microsoft Hyper-V virtual NICs
    "00:15:5d": "Microsoft Hyper-V (Virtual Machine)",
    # Bizlink USB Ethernet
    "0c:37:96": "Bizlink Technology Inc.",
}

# ── Vendor → Device Type (base classification by vendor name) ─────────────
DEVICE_TYPE_MAP = {
    "TP-Link EP25":          "IoT — Smart Plug / Power Outlet",
    "TP-Link":               "Network — Router / Switch / AP",
    "Lutron":                "IoT — Lighting Control",
    "Apple":                 "Endpoint — Apple Device",
    "Espressif":             "IoT — ESP32/ESP8266 Module",
    "Lumi":                  "IoT — Zigbee Gateway (Aqara)",
    "Aqara":                 "IoT — Zigbee Gateway (Aqara)",
    "Roborock":              "IoT — Robot Vacuum",
    "Olibra":                "IoT — Bond Bridge (RF Control)",
    "Bond":                  "IoT — Bond Bridge (RF Control)",
    "Emporia":               "IoT — Energy Monitor",
    "Epson":                 "Endpoint — Network Printer",
    "Seiko Epson":           "Endpoint — Network Printer",
    "Dell":                  "Endpoint — PC / Workstation",
    "Hon Hai":               "Endpoint — PC / Workstation (Foxconn NIC)",
    "Foxconn":               "Endpoint — PC / Workstation (Foxconn NIC)",
    "Action Star":           "Network — USB Ethernet Adapter",
    "Hyper-V":               "Virtual Machine (Lab)",
    "Microsoft":             "Virtual Machine (Lab)",
    "Bizlink":               "Network — USB Ethernet Adapter",
    "Samsung":               "Endpoint — PC / Workstation (Samsung)",
    "SAMSUNG":               "Endpoint — PC / Workstation (Samsung)",
    "Dyson":                 "IoT — Smart Appliance (Dyson)",
    "Haier":                 "IoT — Smart Appliance",
    "Philips":               "IoT — Smart Lighting / Appliance",
    "Belkin":                "IoT — Smart Plug / WiFi Adapter",
    "Netgear":               "Network — Router / Switch (Netgear)",
    "Ubiquiti":              "Network — UniFi AP / Switch (Ubiquiti)",
    # OT vendors — for when they appear via OUI in the future
    "Rockwell":              "OT — PLC / Controller (Allen-Bradley)",
    "Allen-Bradley":         "OT — PLC / Controller (Allen-Bradley)",
    "Siemens":               "OT — PLC / HMI (Siemens)",
    "Schneider":             "OT — PLC / RTU (Schneider Electric)",
    "ABB":                   "OT — Controller / Drive (ABB)",
    "Beckhoff":              "OT — IPC / Controller (Beckhoff)",
    "Moxa":                  "OT — Serial Gateway / Switch (Moxa)",
    "Advantech":             "OT — Industrial PC / Gateway (Advantech)",
    "Phoenix Contact":       "OT — I/O Module / Gateway (Phoenix Contact)",
    "Wago":                  "OT — PLC / I/O Controller (Wago)",
    "Emerson":               "OT — Controller / RTU (Emerson)",
    "Honeywell":             "OT — Controller / DCS (Honeywell)",
}

# ── OT Protocol Port Map ──────────────────────────────────────────────────
# Maps open TCP/UDP ports to OT protocol classification
# Priority: OT protocols override vendor-based classification
OT_PORT_MAP = {
    "502":   "OT — Modbus TCP Device",
    "44818": "OT — EtherNet/IP Device (Rockwell / Generic CIP)",
    "2222":  "OT — EtherNet/IP Device (EtherNet/IP implicit)",
    "102":   "OT — S7 / PROFINET Device (Siemens)",
    "4840":  "OT — OPC UA Server",
    "20000": "OT — DNP3 Device",
    "47808": "OT — BACnet/IP Device (Building Automation)",
    "1911":  "OT — Niagara Fox / Tridium (BAS / HVAC)",
    "4911":  "OT — Niagara Fox / Tridium TLS",
    "9600":  "OT — OMRON FINS Device",
    "18245": "OT — GE SRTP Device",
    "2404":  "OT — IEC 60870-5-104 Device",
    "4000":  "OT — Emerson DeltaV / HART-IP",
    "161":   "Network — SNMP Device (Managed Switch / Gateway)",
    "162":   "Network — SNMP Trap Receiver",
    "21":    "Endpoint — FTP Service (Legacy / HMI)",
    "23":    "Endpoint — Telnet Service (Legacy Device)",
    "3389":  "Endpoint — Remote Desktop (Windows / HMI)",
    "5900":  "Endpoint — VNC Remote Access",
    "1433":  "Endpoint — SQL Server (Historian / SCADA DB)",
    "1521":  "Endpoint — Oracle Database (Historian / SCADA)",
    "8080":  "Endpoint — Web Interface (HMI / Gateway)",
    "8443":  "Endpoint — Secure Web Interface (HMI / Gateway)",
    "554":   "IoT — RTSP Camera Stream",
    "1883":  "IoT — MQTT Broker (IoT / IIoT Gateway)",
    "8883":  "IoT — MQTT Broker TLS",
    "22":    None,   # SSH — not enough to reclassify, used as enrichment
    "80":    None,   # HTTP — not enough to reclassify alone
    "443":   None,   # HTTPS — not enough to reclassify alone
}

# ── HTTP Banner → Device Type hints ──────────────────────────────────────
# If HTTP title or Server header contains these strings → override device type
HTTP_BANNER_MAP = {
    "RouterOS":         "Network — MikroTik Router",
    "UniFi":            "Network — Ubiquiti UniFi AP / Switch",
    "Cisco":            "Network — Cisco Device",
    "AXIS":             "IoT — AXIS Network Camera",
    "Hikvision":        "IoT — Hikvision IP Camera",
    "Dahua":            "IoT — Dahua IP Camera",
    "FactoryTalk":      "OT — Rockwell FactoryTalk HMI",
    "WinCC":            "OT — Siemens WinCC SCADA / HMI",
    "Ignition":         "OT — Inductive Automation Ignition SCADA",
    "Wonderware":       "OT — AVEVA Wonderware HMI / Historian",
    "Kepware":          "OT — PTC Kepware OPC Server",
    "iSMA":             "OT — iSMA BACnet Controller",
    "Tridium":          "OT — Tridium Niagara BAS Controller",
    "Echelon":          "OT — Echelon LonWorks Controller",
    "Moxa":             "OT — Moxa Serial Gateway / Switch",
    "QNAP":             "Endpoint — QNAP NAS",
    "Synology":         "Endpoint — Synology NAS",
    "pfSense":          "Network — pfSense Firewall / Router",
    "OPNsense":         "Network — OPNsense Firewall / Router",
    "Proxmox":          "Endpoint — Proxmox Hypervisor",
    "ESXi":             "Endpoint — VMware ESXi Hypervisor",
    "TrueNAS":          "Endpoint — TrueNAS Storage Server",
    "Pi-hole":          "Network — Pi-hole DNS / Ad Filter",
    "Home Assistant":   "IoT — Home Assistant Hub",
    "Lutron":           "IoT — Lutron Lighting Control",
    "TP-LINK":          "Network — TP-Link Router / AP",
}


def classify_by_ports(open_ports: list) -> str | None:
    """
    Classify device type based on open ports.
    OT protocol ports take priority over generic ports.
    Returns classification string or None if no match.

    Priority order:
    1. OT industrial protocols (502, 44818, 102, etc.)
    2. Building automation (47808, 1911)
    3. Network management (161)
    4. Legacy/risky services (23, 21)
    5. Generic services (None — no reclassification)
    """
    if not open_ports:
        return None

    ports_set = set(str(p) for p in open_ports)

    # Check in priority order (OT ports first)
    priority_order = [
        "502", "44818", "2222", "102", "4840", "20000",
        "47808", "1911", "4911", "9600", "18245", "2404", "4000",
        "161", "162", "23", "21", "3389", "5900",
        "1433", "1521", "554", "1883", "8883",
        "8080", "8443",
    ]

    for port in priority_order:
        if port in ports_set:
            result = OT_PORT_MAP.get(port)
            if result:  # None means "not enough to reclassify"
                return result

    return None


def classify_by_http_banner(http_banners: dict) -> str | None:
    """
    Classify device type based on HTTP banner (title + server header).
    Returns classification string or None if no match.
    http_banners: dict keyed by port, each with 'title' and 'server' keys.
    """
    if not http_banners:
        return None

    # Combine all titles and server headers into one searchable string
    combined = ""
    for port_data in http_banners.values():
        if isinstance(port_data, dict):
            title = port_data.get("title") or ""
            server = port_data.get("server") or ""
            combined += f" {title} {server}"

    combined = combined.lower()

    for keyword, dtype in HTTP_BANNER_MAP.items():
        if keyword.lower() in combined:
            return dtype

    return None


def classify_device(vendor: str) -> str:
    """
    Classify device type based on vendor name only.
    Used as base classification — may be overridden by port/banner analysis.
    """
    for key, dtype in DEVICE_TYPE_MAP.items():
        if key.lower() in vendor.lower():
            return dtype
    return "Unknown — Classify manually"


def classify_device_enriched(
    vendor: str,
    open_ports: list = None,
    http_banners: dict = None,
    hostname: str = "",
) -> tuple[str, str]:
    """
    Full classification using vendor + ports + HTTP banners.
    Returns (device_type, classification_source) tuple.

    Classification priority (highest to lowest):
    1. OT protocol port detection  → most reliable for OT devices
    2. HTTP banner / web title      → good for HMIs, gateways, cameras
    3. Vendor name (OUI lookup)     → reliable for known vendors
    4. Unknown fallback

    Args:
        vendor:       Resolved vendor string from OUI lookup or arp-scan
        open_ports:   List of open port numbers as strings ['80', '502']
        http_banners: Dict from grab_http_banner() keyed by port number
        hostname:     mDNS / NetBIOS / DNS hostname if available

    Returns:
        Tuple of (device_type_string, source_string)
        source values: 'port_detection' | 'http_banner' | 'vendor_lookup' | 'unknown'
    """
    open_ports = open_ports or []
    http_banners = http_banners or {}

    # 1 — OT/network port detection (highest priority)
    port_classification = classify_by_ports(open_ports)
    if port_classification:
        return port_classification, "port_detection"

    # 2 — HTTP banner analysis
    banner_classification = classify_by_http_banner(http_banners)
    if banner_classification:
        return banner_classification, "http_banner"

    # 3 — Vendor name lookup
    vendor_classification = classify_device(vendor)
    if "Unknown" not in vendor_classification:
        return vendor_classification, "vendor_lookup"

    # 4 — Fallback
    return "Unknown — Classify manually", "unknown"


def resolve_vendor(mac: str, arp_vendor: str) -> str:
    """
    Resolve vendor using local OUI table first.
    Falls back to arp-scan vendor string if OUI not in table.
    MAC is always the primary identifier.
    """
    oui = mac[:8].lower()
    if oui in OUI_LOOKUP:
        return OUI_LOOKUP[oui]
    if "(unknown" not in arp_vendor.lower() and arp_vendor.strip():
        return arp_vendor.strip()
    return f"Unknown OUI: {oui}"


def is_locally_administered(mac: str) -> bool:
    """
    Detect locally administered MACs (virtual, spoofed, or randomized).
    Second bit of first byte = 1 indicates locally administered.
    """
    first_byte = int(mac.split(":")[0], 16)
    return bool(first_byte & 0x02)


def parse_arp_scan(filepath: str) -> list:
    """
    Parse arp-scan output file.
    Returns deduplicated list of devices sorted by last IP octet.
    Note: MAC is the canonical identifier — IP may change via DHCP.
    """
    pattern = re.compile(
        r"^([\d.]+)\s+"
        r"([0-9a-f:]{17})\s+"
        r"(.+?)(?:\s+\(DUP.*)?$",
        re.IGNORECASE
    )

    devices = {}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            match = pattern.match(line)
            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2).lower()
            vendor_raw = match.group(3).strip()

            if mac in devices:
                devices[mac]["dup_count"] += 1
                devices[mac]["ip_address"] = ip
                continue

            vendor = resolve_vendor(mac, vendor_raw)
            device_type, _ = classify_device_enriched(vendor)
            locally_admin = is_locally_administered(mac)

            devices[mac] = {
                "ip_address":    ip,
                "mac_address":   mac,
                "vendor":        vendor,
                "device_type":   device_type,
                "locally_admin": "Yes" if locally_admin else "No",
                "dup_count":     1,
                "notes":         "",
            }

    return sorted(
        devices.values(),
        key=lambda d: int(d["ip_address"].split(".")[-1])
    )


def export_csv(devices: list, output_path: str):
    """Export device list to CSV."""
    fields = [
        "ip_address", "mac_address", "vendor",
        "device_type", "locally_admin", "dup_count", "notes"
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(devices)
    print(f"\n✅ CSV: {output_path} — {len(devices)} devices")


def print_summary(devices: list):
    """Print discovery summary to console."""
    print("\n" + "=" * 80)
    print(f"  OT INVENTORY — Network Discovery Report")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Note: MAC = primary identifier (IP may change via DHCP)")
    print("=" * 80)
    print(f"\n{'IP':<18}{'MAC':<20}{'Vendor':<32}{'Type'}")
    print("-" * 110)

    for d in devices:
        dup = f" [x{d['dup_count']}]" if d["dup_count"] > 1 else ""
        la  = " [LA]" if d["locally_admin"] == "Yes" else ""
        print(
            f"{d['ip_address']:<18}{d['mac_address']:<20}"
            f"{d['vendor'][:30]:<32}{d['device_type']}{dup}{la}"
        )

    print(f"\n📊 Total unique devices: {len(devices)}")

    type_counts = {}
    for d in devices:
        t = d["device_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    print("\n📋 By category:")
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"   {count:>2}x  {t}")

    unknowns = [d for d in devices if "Unknown" in d["device_type"]]
    la_macs  = [d for d in devices if d["locally_admin"] == "Yes"]

    if unknowns or la_macs:
        print("\n⚠️  Alerts:")
        for d in unknowns:
            print(f"   ???: {d['ip_address']} ({d['mac_address']}) — vendor not identified")
        for d in la_macs:
            print(f"   [LA]: {d['ip_address']} ({d['mac_address']}) — locally administered MAC")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 arp_scanner.py <arp_scan_output_file>")
        print("Example: python3 arp_scanner.py discovery/arp_scan_full.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = (
        input_file.rsplit("/", 1)[0] + "/network_inventory.csv"
        if "/" in input_file
        else "network_inventory.csv"
    )

    devices = parse_arp_scan(input_file)
    print_summary(devices)
    export_csv(devices, output_file)
