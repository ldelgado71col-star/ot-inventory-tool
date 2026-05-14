#!/usr/bin/env python3
"""
clean_arp_scan.py — Limpia, deduplica y clasifica el escaneo ARP
Uso: python3 clean_arp_scan.py discovery/arp_scan_full.txt
Salida: discovery/network_inventory.csv
"""

import re
import csv
import sys
from datetime import datetime

# ── Tabla de identificación por OUI (primeros 3 bytes de MAC) ──────────────
# Agrega aquí los OUI que vayas descubriendo en tu red
OUI_LOOKUP = {
    "00:31:92": "TP-Link Corporation",
    "00:0f:e7": "Lutron Electronics",
    "00:24:9b": "Action Star Enterprise",
    "2c:6f:c9": "Hon Hai Precision (Foxconn)",
    "04:99:b9": "Apple Inc.",
    "f4:4e:38": "Olibra LLC",
    "48:e7:29": "Espressif Inc.",
    "48:55:19": "Espressif Inc.",
    "0c:8b:95": "Espressif Inc.",
    "54:ef:44": "Lumi United Technology",
    "b0:4a:39": "Roborock Technology",
    "54:d6:0d": "Unknown — Investigar",
    "78:8c:b5": "Unknown — Investigar",
    "b0:f2:f6": "Unknown — Investigar",
    "58:05:d9": "Unknown — Investigar",
    "28:07:08": "Unknown — Investigar",
    "08:f9:e0": "Unknown — Investigar",
    "c8:15:4e": "Unknown — Investigar",
    "00:15:5d": "Microsoft Hyper-V (esta VM)",
}

# ── Clasificación de dispositivo por fabricante ────────────────────────────
DEVICE_TYPE_MAP = {
    "TP-Link":     "Network / Router / Switch",
    "Lutron":      "IoT — Lighting Control",
    "Apple":       "Endpoint — Apple Device",
    "Espressif":   "IoT — ESP32/ESP8266 Module",
    "Lumi":        "IoT — Zigbee Gateway (Aqara/Xiaomi)",
    "Roborock":    "IoT — Robot Vacuum",
    "Olibra":      "IoT — Bond Bridge (RF Control)",
    "Hon Hai":     "Endpoint — PC/Laptop (Foxconn NIC)",
    "Foxconn":     "Endpoint — PC/Laptop (Foxconn NIC)",
    "Action Star": "Network — Media Adapter",
    "Hyper-V":     "Virtual Machine (Lab)",
}


def classify_device(vendor: str) -> str:
    """Clasifica el tipo de dispositivo basado en el fabricante."""
    for key, dtype in DEVICE_TYPE_MAP.items():
        if key.lower() in vendor.lower():
            return dtype
    return "Unknown — Clasificar manualmente"


def resolve_vendor(mac: str, arp_vendor: str) -> str:
    """Resuelve el fabricante usando OUI local si arp-scan no lo identificó."""
    oui = mac[:8].lower()
    if "(unknown" in arp_vendor.lower() or not arp_vendor.strip():
        return OUI_LOOKUP.get(oui, f"Unknown OUI: {oui}")
    return arp_vendor.strip()


def is_locally_administered(mac: str) -> bool:
    """Detecta MACs locally administered (segundo bit del primer byte = 1)."""
    first_byte = int(mac.split(":")[0], 16)
    return bool(first_byte & 0x02)


def parse_arp_scan(filepath: str) -> list[dict]:
    """Parsea el archivo arp-scan y devuelve lista deduplicada de dispositivos."""
    pattern = re.compile(
        r"^([\d.]+)\s+"           # IP address
        r"([0-9a-f:]{17})\s+"     # MAC address
        r"(.+?)(?:\s+\(DUP.*)?$", # Vendor (sin marcador DUP)
        re.IGNORECASE
    )

    devices = {}  # key = IP address (deduplicar por IP)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            match = pattern.match(line)
            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2).lower()
            vendor_raw = match.group(3).strip()

            if ip in devices:
                devices[ip]["dup_count"] += 1
                continue

            vendor = resolve_vendor(mac, vendor_raw)
            device_type = classify_device(vendor)
            locally_admin = is_locally_administered(mac)

            devices[ip] = {
                "ip_address":   ip,
                "mac_address":  mac,
                "vendor":       vendor,
                "device_type":  device_type,
                "locally_admin": "Yes" if locally_admin else "No",
                "dup_count":    1,
                "notes":        "",
            }

    # Ordenar por último octeto de IP
    sorted_devices = sorted(
        devices.values(),
        key=lambda d: int(d["ip_address"].split(".")[-1])
    )

    return sorted_devices


def export_csv(devices: list[dict], output_path: str):
    """Exporta a CSV limpio."""
    fields = [
        "ip_address", "mac_address", "vendor",
        "device_type", "locally_admin", "dup_count", "notes"
    ]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(devices)

    print(f"\n✅ CSV generado: {output_path}")
    print(f"   Dispositivos únicos: {len(devices)}")


def print_summary(devices: list[dict]):
    """Imprime resumen en consola."""
    print("\n" + "=" * 70)
    print(f"  OT INVENTORY LAB — Network Discovery Report")
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 70)
    print(f"\n{'IP':<18}{'MAC':<20}{'Vendor':<30}{'Tipo'}")
    print("-" * 100)
    for d in devices:
        dup_flag = f" [x{d['dup_count']}]" if d["dup_count"] > 1 else ""
        la_flag = " [LA]" if d["locally_admin"] == "Yes" else ""
        print(f"{d['ip_address']:<18}{d['mac_address']:<20}"
              f"{d['vendor'][:28]:<30}{d['device_type']}{dup_flag}{la_flag}")

    print(f"\n📊 Total dispositivos únicos: {len(devices)}")

    # Conteo por tipo
    type_counts = {}
    for d in devices:
        t = d["device_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    print("\n📋 Por categoría:")
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"   {count:>2}x  {t}")

    # Alertas
    dups = [d for d in devices if d["dup_count"] > 1]
    unknowns = [d for d in devices if "Unknown" in d["device_type"]
                or "Investigar" in d["vendor"]]
    la_macs = [d for d in devices if d["locally_admin"] == "Yes"]

    if dups or unknowns or la_macs:
        print("\n⚠️  Alertas:")
        for d in dups:
            print(f"   DUP: {d['ip_address']} respondió {d['dup_count']}x "
                  f"— posible bridge/repeater")
        for d in unknowns:
            print(f"   ???: {d['ip_address']} ({d['mac_address']}) "
                  f"— fabricante no identificado")
        for d in la_macs:
            print(f"   [LA]: {d['ip_address']} ({d['mac_address']}) "
                  f"— MAC locally administered (virtual/spoofed)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 clean_arp_scan.py <archivo_arp_scan>")
        print("Ejemplo: python3 clean_arp_scan.py discovery/arp_scan_full.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    if "/" in input_file:
        output_file = input_file.rsplit("/", 1)[0] + "/network_inventory.csv"
    else:
        output_file = "network_inventory.csv"

    devices = parse_arp_scan(input_file)
    print_summary(devices)
    export_csv(devices, output_file)
    print(f"\n🚀 Siguiente paso: python3 load_to_api.py {output_file}")
