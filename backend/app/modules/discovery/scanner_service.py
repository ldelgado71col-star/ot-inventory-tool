import subprocess
import re
import httpx

from .arp_scanner import resolve_vendor, classify_device, is_locally_administered

class ARPScannerService:
    """
    A service class for running ARP scans and saving the discovered devices to the API.
    """

    def __init__(self, api_url: str = "http://localhost:8000"):
        """
        Initialize the ARPScannerService.

        Args:
            api_url (str): The base URL of the API to save assets to.
        """
        self.api_url = api_url

    def scan(self, subnet: str) -> list[dict]:
        """
        Executes an arp-scan on the given subnet and returns a deduplicated list
        of discovered devices with their classified vendor and device type.

        Args:
            subnet (str): The subnet to scan (e.g., '192.168.1.0/24').

        Returns:
            list[dict]: A list of dictionaries, each containing details about a discovered device.
        """
        # Run the arp-scan command
        result = subprocess.run(
            ["arp-scan", subnet],
            capture_output=True,
            text=True
        )

        pattern = re.compile(
            r"^([\d.]+)\s+"           # IP address
            r"([0-9a-fA-F:]{17})\s+"  # MAC address
            r"(.+?)(?:\s+\(DUP.*)?$", # Vendor (sin marcador DUP)
            re.IGNORECASE
        )

        devices = {}  # key = IP address (deduplicar por IP)

        for line in result.stdout.splitlines():
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

        # Sort by the last octet of the IP
        sorted_devices = sorted(
            devices.values(),
            key=lambda d: int(d["ip_address"].split(".")[-1])
        )

        return sorted_devices

    def save_results(self, devices: list[dict]) -> int:
        """
        Saves the discovered devices to the API.

        Args:
            devices (list[dict]): A list of dictionaries containing device information.

        Returns:
            int: The number of devices successfully saved.
        """
        saved_count = 0

        for asset in devices:
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
                r = httpx.post(f"{self.api_url}/assets", json=payload, timeout=5)
                if r.status_code == 200:
                    saved_count += 1
            except Exception:
                pass

        return saved_count
