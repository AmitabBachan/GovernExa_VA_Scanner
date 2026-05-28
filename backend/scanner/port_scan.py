"""
Port Scan Engine
Comprehensive port scanning covering: TCP SYN/Connect, UDP, service version
detection, banner grabbing, OS fingerprinting, and NSE script scanning.

Scan Techniques Used:
  • TCP SYN (half-open) — Fast, stealthy; default for root/privileged
  • TCP Connect — Full 3-way handshake; fallback for unprivileged
  • UDP Scan — Slow but essential for DNS, SNMP, DHCP, NTP detection
  • Service/Version Detection (-sV) — Probe banners to identify software
  • OS Detection (-O) — TCP/IP stack fingerprinting
  • NSE Script Scanning (-sC) — Default safe scripts for extra enumeration
"""
import nmap
import socket
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class PortScanEngine:
    """
    Dedicated engine for the 'port_scan' scan profile.
    Performs deep port enumeration and service fingerprinting on targets.
    """

    def __init__(self):
        self.nm = nmap.PortScanner()

    # ------------------------------------------------------------------
    # 1. TCP SYN Scan (fast stealth scan — requires root/cap_net_raw)
    # ------------------------------------------------------------------
    def tcp_syn_scan(
        self, target: str, ports: str = "1-65535", timing: str = "T4"
    ) -> List[Dict[str, Any]]:
        """
        TCP SYN (half-open) scan across specified port range.
        Default scans ALL 65535 ports.
        """
        results = []
        try:
            logger.info(f"[PortScan] TCP SYN scan on {target} ports={ports}")
            # Speed optimizations: -n (no DNS), --min-rate 1000 (fast packet sending), --max-retries 1
            args = f"-sS -{timing} -Pn -n --open -p {ports} --disable-arp-ping --min-rate 1000 --max-retries 1 --host-timeout 10m"
            self.nm.scan(hosts=target, arguments=args)

            for host in self.nm.all_hosts():
                if "tcp" in self.nm[host]:
                    for port, data in self.nm[host]["tcp"].items():
                        if data["state"] == "open":
                            results.append(self._build_port_record(
                                host, port, "tcp", data, scan_method="SYN"
                            ))
        except Exception as e:
            logger.error(f"TCP SYN scan failed for {target}: {e}")
        return results

    # ------------------------------------------------------------------
    # 2. TCP Connect Scan (unprivileged fallback)
    # ------------------------------------------------------------------
    def tcp_connect_scan(
        self, target: str, ports: str = "--top-ports 1000", timing: str = "T4"
    ) -> List[Dict[str, Any]]:
        """Full 3-way handshake scan. Noisier but works without raw sockets."""
        results = []
        try:
            logger.info(f"[PortScan] TCP Connect scan on {target}")
            port_arg = f"-p {ports}" if not ports.startswith("--") else ports
            args = f"-sT -{timing} -Pn -n --open {port_arg} --disable-arp-ping --min-rate 1000 --max-retries 1 --host-timeout 10m"
            self.nm.scan(hosts=target, arguments=args)

            for host in self.nm.all_hosts():
                if "tcp" in self.nm[host]:
                    for port, data in self.nm[host]["tcp"].items():
                        if data["state"] == "open":
                            results.append(self._build_port_record(
                                host, port, "tcp", data, scan_method="Connect"
                            ))
        except Exception as e:
            logger.error(f"TCP Connect scan failed for {target}: {e}")
        return results

    # ------------------------------------------------------------------
    # 3. UDP Scan (critical for DNS/53, SNMP/161, DHCP/67, NTP/123, etc.)
    # ------------------------------------------------------------------
    def udp_scan(
        self, target: str, ports: str = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353,49152",
        timing: str = "T4"
    ) -> List[Dict[str, Any]]:
        """
        UDP scan on common service ports. UDP is inherently slow;
        we scope it to high-value ports by default.
        """
        results = []
        try:
            logger.info(f"[PortScan] UDP scan on {target} ports={ports}")
            args = f"-sU -{timing} -Pn -n --open -p {ports} --disable-arp-ping --max-retries 1 --host-timeout 10m"
            self.nm.scan(hosts=target, arguments=args)

            for host in self.nm.all_hosts():
                if "udp" in self.nm[host]:
                    for port, data in self.nm[host]["udp"].items():
                        if data["state"] in ("open", "open|filtered"):
                            results.append(self._build_port_record(
                                host, port, "udp", data, scan_method="UDP"
                            ))
        except Exception as e:
            logger.error(f"UDP scan failed for {target}: {e}")
        return results

    # ------------------------------------------------------------------
    # 4. Service Version Detection + Banner Grabbing
    # ------------------------------------------------------------------
    def service_version_scan(
        self, target: str, ports: str = None, timing: str = "T4"
    ) -> List[Dict[str, Any]]:
        """
        Deep version probing (-sV --version-intensity 5) with default
        NSE scripts (-sC) for banner extraction and additional enumeration.
        """
        results = []
        try:
            port_arg = f"-p {ports}" if ports else "--top-ports 1000"
            logger.info(f"[PortScan] Service version scan on {target}")
            args = f"-sV --version-intensity 2 -sC -{timing} -Pn -n --open {port_arg} --disable-arp-ping --max-retries 1 --host-timeout 10m"
            self.nm.scan(hosts=target, arguments=args)

            for host in self.nm.all_hosts():
                for proto in ("tcp", "udp"):
                    if proto in self.nm[host]:
                        for port, data in self.nm[host][proto].items():
                            if data["state"] == "open":
                                record = self._build_port_record(
                                    host, port, proto, data, scan_method="Version"
                                )
                                # Attach NSE script output if available
                                if "script" in data:
                                    record["scripts"] = {
                                        k: v for k, v in data["script"].items()
                                    }
                                results.append(record)
        except Exception as e:
            logger.error(f"Service version scan failed for {target}: {e}")
        return results

    # ------------------------------------------------------------------
    # 5. OS Fingerprinting
    # ------------------------------------------------------------------
    def os_fingerprint(self, target: str) -> Dict[str, Any]:
        """TCP/IP stack OS fingerprinting via Nmap -O."""
        os_info = {
            "ip": target,
            "os_name": "",
            "os_family": "",
            "os_accuracy": "",
            "device_type": "",
        }
        try:
            logger.info(f"[PortScan] OS fingerprint on {target}")
            args = f"-O -Pn -n --disable-arp-ping --max-retries 1 --host-timeout 5m"
            self.nm.scan(hosts=target, arguments=args)

            if target in self.nm.all_hosts():
                os_matches = self.nm[target].get("osmatch", [])
                if os_matches:
                    best = os_matches[0]
                    os_info["os_name"] = best.get("name", "")
                    os_info["os_accuracy"] = best.get("accuracy", "")
                    os_classes = best.get("osclass", [])
                    if os_classes:
                        os_info["os_family"] = os_classes[0].get("osfamily", "")
                        os_info["device_type"] = os_classes[0].get("type", "")
        except Exception as e:
            logger.error(f"OS fingerprint failed for {target}: {e}")
        return os_info

    # ------------------------------------------------------------------
    # 6. Banner Grabbing (raw socket fallback for specific ports)
    # ------------------------------------------------------------------
    def grab_banner(self, ip: str, port: int, timeout: float = 3.0) -> str:
        """Raw TCP socket banner grab for a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                return banner
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # 7. Classify port risk level
    # ------------------------------------------------------------------
    def classify_port_risk(self, port: int, protocol: str, service: str) -> str:
        """
        Assigns a risk classification based on port number and service.
        """
        high_risk_services = {
            "telnet", "ftp", "rsh", "rlogin", "rexec", "vnc",
            "ms-wbt-server", "microsoft-ds", "netbios-ssn",
        }
        high_risk_ports = {21, 23, 25, 135, 137, 139, 445, 512, 513, 514, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 27017}
        critical_ports = {23, 21, 512, 513, 514, 5900, 6379, 27017}

        svc = (service or "").lower()

        if port in critical_ports or svc in {"telnet", "rsh", "rlogin", "rexec", "vnc"}:
            return "CRITICAL"
        if port in high_risk_ports or svc in high_risk_services:
            return "HIGH"
        if port > 49151:
            return "MEDIUM"  # ephemeral / dynamic ports
        if protocol == "udp":
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Helper: build a standardised port record dict
    # ------------------------------------------------------------------
    def _build_port_record(
        self, host: str, port: int, protocol: str, data: dict, scan_method: str = ""
    ) -> Dict[str, Any]:
        service = data.get("name", "")
        return {
            "ip": host,
            "port": port,
            "protocol": protocol,
            "state": data.get("state", "open"),
            "service": service,
            "product": data.get("product", ""),
            "version": data.get("version", ""),
            "extrainfo": data.get("extrainfo", ""),
            "cpe": data.get("cpe", ""),
            "reason": data.get("reason", ""),
            "scan_method": scan_method,
            "risk": self.classify_port_risk(port, protocol, service),
        }
