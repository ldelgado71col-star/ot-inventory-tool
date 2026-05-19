import subprocess
import httpx
import re
import typing

class DiscoveryService:
    """
    DiscoveryService provides methods to perform network discovery tasks including
    ARP scanning, Nmap port scanning, and HTTP banner grabbing.
    """

    def run_arp_scan(self, subnet: str, interface: str = "eth0", retries: int = 5, timeout_ms: int = 1500) -> list[dict]:
        """
        Run arp-scan via subprocess to find active hosts on the network.

        Args:
            subnet (str): The subnet to scan (e.g., "192.168.1.0/24").
            interface (str): The network interface to use. Defaults to "eth0".
            retries (int): Number of retries. Defaults to 5.
            timeout_ms (int): Per-host timeout in milliseconds. Defaults to 1500.

        Returns:
            list[dict]: A list of dictionaries, each containing 'ip', 'mac', and 'vendor'.
        """
        results = []
        try:
            cmd = [
                "arp-scan",
                "--interface", interface,
                "--retry", str(retries),
                "--timeout", str(timeout_ms),
                subnet
            ]
            process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            output = process.stdout

            # Match lines with IP, MAC, and Vendor
            pattern = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})\s+(.*)$')

            for line in output.splitlines():
                match = pattern.match(line.strip())
                if match:
                    results.append({
                        "ip": match.group(1),
                        "mac": match.group(2),
                        "vendor": match.group(3).strip()
                    })
        except Exception:
            pass

        return results

    def run_nmap_scan(self, targets: list[str], ports: str = "80,443,8080,8443,22,23,554,1883") -> dict:
        """
        Run nmap -sV via subprocess on target IPs to find open ports and services.

        Args:
            targets (list[str]): List of target IP addresses.
            ports (str): Comma-separated list of ports to scan.

        Returns:
            dict: Dictionary keyed by IP with 'open_ports' and 'services'.
        """
        results = {}
        if not targets:
            return results

        try:
            cmd = ["nmap", "-T5", "--open", "-p", ports, "--host-timeout", "5s", "--max-retries", "1", "-oG", "-"] + targets
            process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
            output = process.stdout

            host_pattern = re.compile(r'^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+.*Ports:\s+(.*)$')

            for line in output.splitlines():
                if line.startswith("Host:"):
                    match = host_pattern.match(line.strip())
                    if match:
                        ip = match.group(1)
                        ports_str = match.group(2)

                        open_ports = []
                        services = {}

                        port_entries = ports_str.split(", ")
                        for entry in port_entries:
                            parts = entry.split("/")
                            if len(parts) >= 5 and parts[1] == "open":
                                port_num = parts[0].strip()
                                open_ports.append(port_num)

                                service_name = parts[4]
                                version_info = parts[6] if len(parts) >= 7 else ""
                                full_service = service_name
                                if version_info:
                                    full_service += f" {version_info}"

                                services[port_num] = full_service.strip()

                        if open_ports:
                            results[ip] = {
                                "open_ports": open_ports,
                                "services": services
                            }
        except Exception:
            pass

        return results

    def grab_http_banner(self, ip: str, ports: list = [80, 443, 8080]) -> dict:
        """
        Try HTTP GET on each port using httpx to grab banner and title.

        Args:
            ip (str): The target IP address.
            ports (list): List of ports to try. Defaults to [80, 443, 8080].

        Returns:
            dict: Dictionary keyed by port containing banner info.
        """
        results = {}
        for port in ports:
            port_result = {
                "ip": ip,
                "port": port,
                "status_code": None,
                "title": None,
                "server": None
            }
            try:
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{ip}:{port}/"

                with httpx.Client(timeout=2.0, verify=False) as client:
                    response = client.get(url, follow_redirects=True)

                    port_result["status_code"] = response.status_code
                    port_result["server"] = response.headers.get("Server")

                    title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        port_result["title"] = title_match.group(1).strip()
            except Exception:
                pass

            results[port] = port_result

        return results

    def run_full_discovery(self, subnet: str, interface: str = "eth0") -> list[dict]:
        """
        Run all discovery methods and return an enriched device list combining results.
        v0.4.0 — Now calls classify_device_enriched() using vendor + ports + banners.
        """
        results = []
        try:
            # Import enriched classifier
            from app.modules.discovery.arp_scanner import (
                resolve_vendor,
                classify_device_enriched,
                is_locally_administered,
                OUI_LOOKUP,
            )

            arp_results = self.run_arp_scan(subnet, interface=interface)
            if not arp_results:
                return results

            targets = [device["ip"] for device in arp_results]

            nmap_results     = self.run_nmap_scan(targets)
            hostname_results = self.run_hostname_resolution(targets)
            try:
                mdns_results = self.run_mdns_scan(targets)
            except Exception as e:
                print(f"[mdns] Skipped due to error: {e}")
                mdns_results = {}
            netbios_results  = self.run_netbios_scan(subnet)

            for device in arp_results:
                ip  = device["ip"]
                mac = device["mac"].lower()

                # Resolve vendor (OUI table first, then arp-scan string)
                oui = mac[:8].lower()
                vendor = OUI_LOOKUP.get(oui, device.get("vendor", ""))
                if not vendor or "unknown" in vendor.lower():
                    vendor = device.get("vendor", f"Unknown OUI: {oui}")

                # Collect open ports from nmap
                open_ports = []
                services   = {}
                if ip in nmap_results:
                    open_ports = nmap_results[ip].get("open_ports", [])
                    services   = nmap_results[ip].get("services", {})

                # Resolve hostname (priority: mDNS > NetBIOS > DNS reverse)
                hostname = (
                    mdns_results.get(ip)
                    or netbios_results.get(ip)
                    or hostname_results.get(ip, "")
                    or ""
                )

                # Grab HTTP banners from open web ports
                http_ports_to_try = [80, 443, 8080]
                for p in open_ports:
                    try:
                        port_num = int(p)
                        if port_num not in http_ports_to_try:
                            http_ports_to_try.append(port_num)
                    except ValueError:
                        pass

                try:
                    http_results = self.grab_http_banner(ip, ports=http_ports_to_try)
                    http_banners = {
                        port: data
                        for port, data in http_results.items()
                        if data.get("status_code") is not None
                    }
                except Exception as e:
                    print(f"[http] Skipped {ip}: {e}")
                    http_banners = {}

                # ── ENRICHED CLASSIFICATION ───────────────────────────────
                # Priority: OT ports > HTTP banner > vendor name
                device_type, classification_source = classify_device_enriched(
                    vendor=vendor,
                    open_ports=open_ports,
                    http_banners=http_banners,
                    hostname=hostname,
                )
                # ─────────────────────────────────────────────────────────

                enriched_device = {
                    "ip":                    ip,
                    "mac":                   mac,
                    "vendor":                vendor,
                    "device_type":           device_type,
                    "classification_source": classification_source,
                    "open_ports":            open_ports,
                    "services":              services,
                    "http_banners":          http_banners,
                    "hostname":              hostname,
                }

                results.append(enriched_device)
                print(f"[classify] {ip} → {device_type} [{classification_source}]")

        except Exception as e:
            print(f"[discovery] Error in run_full_discovery: {e}")
            import traceback
            traceback.print_exc()

        return results

    def run_hostname_resolution(self, targets: list[str]) -> dict:
        """
        Resolve hostnames for a list of IPs using nmap -sn -R.
        Safe for OT — no port scan, ping only + DNS reverse lookup.
        Returns dict keyed by IP with 'hostname'.
        """
        results = {}
        if not targets:
            return results
        try:
            cmd = [
                "nmap", "-sn", "-R",
                "--host-timeout", "3s",
                "--max-retries", "1"
            ] + targets
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
            current_ip = None
            for line in process.stdout.splitlines():
                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if "Nmap scan report for" in line:
                    if ip_match:
                        current_ip = ip_match.group(1)
                    host_match = re.search(r'for\s+(\S+)\s+\(', line)
                    if host_match and current_ip:
                        results[current_ip] = host_match.group(1)
        except Exception:
            pass
        return results

    def run_mdns_scan(self, targets: list[str], timeout: float = 3.0) -> dict:
        """
        Resolve mDNS hostnames (.local) for a list of IPs using zeroconf.
        Safe for OT — passive multicast listener only.
        Returns dict keyed by IP with hostname.
        TEMPORARILY DISABLED — zeroconf BadTypeInNameException in thread.
        """
        return {}
        results = {}
        try:
            from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
            import threading
            import socket

            zc = Zeroconf()
            found = {}
            lock = threading.Lock()

            class Listener(ServiceListener):
                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        for addr in info.parsed_addresses():
                            if addr in targets:
                                with lock:
                                    found[addr] = info.server.rstrip(".")

                def update_service(self, zc, type_, name):
                    self.add_service(zc, type_, name)

                def remove_service(self, zc, type_, name):
                    pass

            services = ["_http._tcp.local.", "_workstation._tcp.local.",
                       "_device-info._tcp.local.", "_services._dns-sd._udp.local."]
            browsers = []
            for s in services:
                try:
                    browsers.append(ServiceBrowser(zc, s, Listener()))
                except Exception:
                    pass
            import time
            time.sleep(timeout)
            zc.close()
            results = found
        except Exception as e:
            print(f"[mdns] Error: {e}")
        return results

    def run_netbios_scan(self, subnet: str) -> dict:
        """
        Resolve NetBIOS names using nbtscan.
        Captures Windows workstation names common in OT environments.
        Returns dict keyed by IP with hostname.
        """
        results = {}
        try:
            cmd = ["nbtscan", "-q", subnet]
            process = subprocess.run(cmd, capture_output=True, text=True,
                                   check=False, timeout=30)
            for line in process.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    name = parts[1].strip()
                    if ip and name and name not in ["<unknown>", "WORKGROUP"]:
                        results[ip] = name
        except Exception as e:
            print(f"[netbios] Error: {e}")
        return results
