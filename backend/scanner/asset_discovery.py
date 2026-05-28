"""
Asset Discovery Engine
Comprehensive asset enumeration covering: live hosts, IPs, hostnames,
cloud instances, containers, routers/firewalls, and web applications.
"""
import nmap
import socket
import logging
import subprocess
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class AssetDiscoveryEngine:
    """
    Dedicated engine for the 'asset_discovery' scan profile.
    Collects rich asset metadata without running vulnerability correlation.
    """

    def __init__(self):
        self.nm = nmap.PortScanner()

    # ------------------------------------------------------------------
    # 1. Live hosts + IPs + MACs  (fast ping sweep)
    # ------------------------------------------------------------------
    def discover_live_hosts(self, target: str) -> List[Dict[str, Any]]:
        hosts = []
        try:
            logger.info(f"[AssetDiscovery] Ping sweep on {target}")
            self.nm.scan(hosts=target, arguments="-sn -n -T4 -PE -PS443,80 -PA80 --open --disable-arp-ping")
            for h in self.nm.all_hosts():
                if self.nm[h].state() == "up":
                    mac = self.nm[h]["addresses"].get("mac", "")
                    hosts.append({
                        "ip": h,
                        "mac_address": mac,
                        "vendor": self.nm[h]["vendor"].get(mac, "") if mac else "",
                        "status": "up",
                    })
        except Exception as e:
            logger.error(f"Live host discovery failed: {e}")
            
        # Fallback to Scapy for local subnets if Nmap misses hosts or fails
        try:
            import ipaddress
            from scapy.all import ARP, Ether, srp
            
            # Basic check if it looks like a local subnet that scapy can ARP
            net = ipaddress.ip_network(target, strict=False)
            if net.is_private and not hosts:
                logger.info(f"[AssetDiscovery] Running Scapy ARP fallback on {target}")
                arp = ARP(pdst=target)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                result = srp(ether/arp, timeout=3, verbose=0)[0]
                
                existing_ips = {h["ip"] for h in hosts}
                for sent, received in result:
                    ip = received.psrc
                    if ip not in existing_ips:
                        hosts.append({
                            "ip": ip,
                            "mac_address": received.hwsrc,
                            "vendor": "Unknown (Scapy)",
                            "status": "up",
                        })
        except Exception as e:
            logger.error(f"Scapy ARP fallback failed: {e}")

        return hosts

    # ------------------------------------------------------------------
    # 2. Hostname resolution
    # ------------------------------------------------------------------
    def resolve_hostnames(self, hosts: List[Dict]) -> List[Dict]:
        for host in hosts:
            try:
                host["hostname"] = socket.gethostbyaddr(host["ip"])[0]
            except Exception:
                host["hostname"] = ""
        return hosts

    # ------------------------------------------------------------------
    # 3. OS + device-type fingerprinting (router/firewall detection)
    # ------------------------------------------------------------------
    def fingerprint_hosts(self, hosts: List[Dict]) -> List[Dict]:
        for host in hosts:
            ip = host["ip"]
            try:
                self.nm.scan(hosts=ip, arguments="-O -sV --top-ports 100 -T4 --open")
                if ip in self.nm.all_hosts():
                    nm_host = self.nm[ip]

                    # OS detection
                    os_matches = nm_host.get("osmatch", [])
                    if os_matches:
                        best = os_matches[0]
                        host["os_name"] = best.get("name", "")
                        host["os_accuracy"] = best.get("accuracy", "")
                        os_classes = best.get("osclass", [])
                        if os_classes:
                            host["os_family"] = os_classes[0].get("osfamily", "")
                            host["device_type"] = os_classes[0].get("type", "")
                    else:
                        host["os_name"] = ""
                        host["os_family"] = ""
                        host["device_type"] = ""

                    # Open ports / services
                    open_ports = []
                    for proto in ["tcp", "udp"]:
                        if proto in nm_host:
                            for port, pdata in nm_host[proto].items():
                                if pdata["state"] == "open":
                                    open_ports.append({
                                        "port": port,
                                        "protocol": proto,
                                        "service": pdata.get("name", ""),
                                        "product": pdata.get("product", ""),
                                        "version": pdata.get("version", ""),
                                    })
                    host["open_ports"] = open_ports

                    # Classify device role
                    host["role"] = self._classify_role(host)

            except Exception as e:
                logger.error(f"Fingerprinting failed for {ip}: {e}")
                host.setdefault("open_ports", [])
                host.setdefault("role", "unknown")

        return hosts

    # ------------------------------------------------------------------
    # 4. Web application detection
    # ------------------------------------------------------------------
    def detect_web_apps(self, hosts: List[Dict]) -> List[Dict]:
        web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 9090}
        for host in hosts:
            web_services = []
            for svc in host.get("open_ports", []):
                if svc.get("port") in web_ports or svc.get("service") in ("http", "https", "http-alt"):
                    proto = "https" if svc["port"] in (443, 8443) else "http"
                    web_services.append({
                        "url": f"{proto}://{host['ip']}:{svc['port']}",
                        "port": svc["port"],
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                    })
            host["web_apps"] = web_services
        return hosts

    # ------------------------------------------------------------------
    # 5. Container detection (Docker daemon port 2375/2376, K8s 6443)
    # ------------------------------------------------------------------
    def detect_containers(self, hosts: List[Dict]) -> List[Dict]:
        container_ports = {2375, 2376, 2377, 6443, 10250, 10255}
        for host in hosts:
            containers = []
            for svc in host.get("open_ports", []):
                if svc.get("port") in container_ports:
                    label = "Docker Daemon" if svc["port"] in (2375, 2376, 2377) else "Kubernetes API"
                    containers.append({
                        "type": label,
                        "port": svc["port"],
                        "secured": svc["port"] in (2376, 6443, 10250),
                    })
            host["containers"] = containers
            if containers:
                host["role"] = "container_host"
        return hosts

    # ------------------------------------------------------------------
    # Helper: classify device role from OS / service fingerprint
    # ------------------------------------------------------------------
    def _classify_role(self, host: Dict) -> str:
        device_type = (host.get("device_type") or "").lower()
        os_family = (host.get("os_family") or "").lower()
        ports = {p["port"] for p in host.get("open_ports", [])}
        services = {p["service"] for p in host.get("open_ports", [])}

        if "router" in device_type or "firewall" in device_type or "switch" in device_type:
            return "network_device"
        if "specialized" in device_type and {"snmp"} & services:
            return "network_device"
        if 2375 in ports or 2376 in ports or 6443 in ports:
            return "container_host"
        if {80, 443, 8080, 8443} & ports:
            return "web_server"
        if {22, 3389} & ports:
            return "server"
        if "windows" in os_family:
            return "windows_host"
        if "linux" in os_family:
            return "linux_host"
        return "host"
