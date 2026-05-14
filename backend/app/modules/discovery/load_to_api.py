#!/usr/bin/env python3
"""
load_to_api.py — Carga el CSV de inventario a la API
Uso: python3 load_to_api.py discovery/network_inventory.csv
"""

import csv
import sys
import httpx

API_URL = "http://localhost:8000"

def load_assets(filepath: str):
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        assets = list(reader)

    print(f"\n🚀 Cargando {len(assets)} activos a la API...\n")

    ok = 0
    errors = 0

    for asset in assets:
        mac = asset["mac_address"].replace(":", "").upper()
        payload = {
            "asset_tag": f"NET-{mac}",
            "vendor": asset["vendor"],
            "device_type": asset["device_type"],
            "ip_address": asset["ip_address"],
            "protocol": "ARP",
            "location": "Home Network"
        }

        try:
            r = httpx.post(f"{API_URL}/assets", json=payload, timeout=5)
            if r.status_code == 200:
                print(f"  ✅ {asset['ip_address']} — {asset['vendor'][:30]}")
                ok += 1
            else:
                print(f"  ❌ {asset['ip_address']} — Error {r.status_code}")
                errors += 1
        except Exception as e:
            print(f"  ❌ {asset['ip_address']} — {e}")
            errors += 1

    print(f"\n📊 Resultado: {ok} cargados, {errors} errores")
    print(f"🌐 Ver inventario: {API_URL}/assets")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 load_to_api.py <archivo_csv>")
        sys.exit(1)
    load_assets(sys.argv[1])
