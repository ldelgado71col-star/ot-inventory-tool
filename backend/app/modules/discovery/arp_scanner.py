#!/usr/bin/env python3
"""
arp_scanner.py — OT/Home Network ARP Discovery Module
Scans subnet, identifies vendors, classifies device types.
MAC address is the primary identifier — not IP (DHCP changes IPs).
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
    # TP-Link Smart Plug Double
    "68:ff:7b": "TP-Link Smart Plug Double",
    # Emporia Smart Plugs (ESP32 based)
    "48:55:19": "Emporia Smart Plug",
    "48:e7:29": "Emporia Smart Plug",
    "0c:8b:95": "Emporia Smart Plug",
    "08:f9:e0": "Emporia Smart Plug",
    "3c:61:05": "Emporia Smart Plug",
    "d8:bc:38": "Emporia Smart Plug",
    "fc:f5:c4": "Emporia Smart Plug",
    # Lutron lighting control
    "00:0f:e7": "Lutron Electronics Co., Inc.",
    # Roborock robot vacuum
    "b0:4a:39": "Beijing Roborock Technology Co., Ltd.",
    # Lumi / Aqara Zigbee gateway
    "54:ef:44": "Lumi United Technology (Aqara/Xiaomi)",
    # Olibra / Bond Bridge RF controller
    "f4:4e:38": "Olibra LLC (Bond Bridge)",
    # Apple devices
    "04:99:b9": "Apple Inc.",
    # Samsung devices
    "8c:b8:4a": "Samsung Electronics",
    "b0:f2:f6": "Samsung Electronics",
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
    # Dyson smart home appliances
    "c8:ff:77": "Dyson Limited",
}

# ── Device Type Classification ────────────────────────────────────────────
DEVICE_TYPE_MAP = {
     "TP-Link EP25":           "IoT — Smart Plug / Power Outlet",
    "TP-Link Smart Plug":     "IoT — Smart Plug / Power Outlet",
    "TP-Link":                "Network — Router / Switch / AP",
    "Emporia Smart Plug":     "IoT — Smart Plug / Power Outlet",
    "Emporia Energy Monitor": "IoT — Energy Monitor",
    "Emporia":                "IoT — Energy Monitor",
    "Lutron":                 "IoT — Lighting Control",
    "Apple":                  "Endpoint — Apple Device",
    "Samsung":                "Endpoint — Smart TV / Samsung Device",
    "Lumi":                   "IoT — Zigbee Gateway (Aqara)",
    "Aqara":                  "IoT — Zigbee Gateway (Aqara)",
    "Roborock":               "IoT — Robot Vacuum",
    "Olibra":                 "IoT — Bond Bridge (RF Control)",
    "Bond":                   "IoT — Bond Bridge (RF Control)",
    "Dyson":                  "IoT — Smart Home Appliance",
    "Epson":                  "Endpoint — Network Printer",
    "Seiko Epson":            "Endpoint — Network Printer",
    "Dell":                   "Endpoint — PC / Laptop",
    "Hon Hai":                "Endpoint — PC / Laptop (Foxconn NIC)",
    "Foxconn":                "Endpoint — PC / Laptop (Foxconn NIC)",
    "Action Star":            "Network — USB Ethernet Adapter",
    "Hyper-V":                "Virtual Machine (Lab)",
    "Microsoft":              "Virtual Machine (Lab)",
    "Bizlink":                "Network — USB Ethernet Adapter",
}


def classify_device(vendor: str) -> str:
    """Classify device type based on vendor name."""
    for key, dtype in DEVICE_TYPE_MAP.items():
        if key.lower() in vendor.lower():
            return dtype
    return "Unknown — Classify manually"


def resolve_vendor(mac: str, arp_vendor: str) -> str:
    """
    Resolve vendor using local OUI table first.
    Falls back to arp-scan vendor string if OUI not in table.
    MAC is always the primary identifier.
    """
    oui = mac[:8].lower()
    # Always prefer local OUI table for accuracy
    if oui in OUI_LOOKUP:
        return OUI_LOOKUP[oui]
    # Fall back to arp-scan result
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

    devices = {}  # key = MAC address (primary identifier)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            match = pattern.match(line)
            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2).lower()
            vendor_raw = match.group(3).strip()

            # Use MAC as primary key — not IP
            if mac in devices:
                devices[mac]["dup_count"] += 1
                # Update IP in case it changed via DHCP
                devices[mac]["ip_address"] = ip
                continue

            vendor = resolve_vendor(mac, vendor_raw)
            device_type = classify_device(vendor)
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
    print(f"\n🚀 Next step: python3 load_to_api.py {output_file}")