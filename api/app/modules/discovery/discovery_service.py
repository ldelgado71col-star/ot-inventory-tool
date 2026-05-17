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
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            cmd = ["nmap", "-sV", "-p", ports, "-oG", "-"] + targets
            process = subprocess.run(cmd, capture_output=True, text=True, check=False)
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

        Args:
            subnet (str): The subnet to scan.
            interface (str): The network interface to use.

        Returns:
            list[dict]: Enriched list of devices.
        """
        results = []
        try:
            arp_results = self.run_arp_scan(subnet, interface=interface)

            if not arp_results:
                return results

            targets = [device["ip"] for device in arp_results]

            nmap_results = self.run_nmap_scan(targets)

            for device in arp_results:
                ip = device["ip"]
                enriched_device = dict(device)
                enriched_device["open_ports"] = []
                enriched_device["services"] = {}
                enriched_device["http_banners"] = {}

                if ip in nmap_results:
                    enriched_device["open_ports"] = nmap_results[ip].get("open_ports", [])
                    enriched_device["services"] = nmap_results[ip].get("services", {})

                http_ports_to_try = [80, 443, 8080]
                for p in enriched_device.get("open_ports", []):
                    try:
                        port_num = int(p)
                        if port_num not in http_ports_to_try:
                            http_ports_to_try.append(port_num)
                    except ValueError:
                        pass

                http_results = self.grab_http_banner(ip, ports=http_ports_to_try)

                successful_banners = {}
                for port, data in http_results.items():
                    if data.get("status_code") is not None:
                        successful_banners[port] = data

                enriched_device["http_banners"] = successful_banners

                results.append(enriched_device)

        except Exception:
            pass

        return results
