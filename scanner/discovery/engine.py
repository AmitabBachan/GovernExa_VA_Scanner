import nmap
import ipaddress
import platform
import asyncio
from typing import List, Dict, Any
from scapy.all import ARP, Ether, srp

class DiscoveryEngine:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def discover(self, target: str) -> List[Dict[str, Any]]:
        """
        Discover hosts using nmap as primary and scapy for local ARP fallback.
        Supports IPv4, IPv6, CIDR.
        """
        results = []
        is_local_subnet = self._is_local_subnet(target)
        
        try:
            # -sn: Ping Scan (disable port scan)
            # -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
            # -PS/PA/PU/PY: TCP SYN/ACK, UDP, SCTP discovery
            scan_args = '-sn -PE -PS443,80 -PA80 -PU40125'
            if platform.system() != "Windows":
                # Ensure we run as root if we want aggressive ARP, or just rely on nmap defaults
                pass
                
            self.nm.scan(hosts=target, arguments=scan_args)
            
            for host in self.nm.all_hosts():
                status = self.nm[host].state()
                if status == 'up':
                    mac = self.nm[host]['addresses'].get('mac', '')
                    hostnames = self.nm[host].hostnames()
                    hostname = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else ''
                    vendor = self.nm[host]['vendor'].get(mac, '') if mac else ''
                    
                    results.append({
                        "ip": host,
                        "hostname": hostname,
                        "status": status,
                        "mac_address": mac,
                        "vendor": vendor,
                        "response_time_ms": "" # could parse from nmap XML if needed
                    })
                    
        except nmap.PortScannerError as e:
            print(f"Nmap error: {e}")
            
        # Supplemental: ARP discovery for local subnets using Scapy
        if is_local_subnet and not results:
            print(f"Falling back to Scapy ARP discovery for {target}")
            results = self._scapy_arp_discovery(target)
            
        return results

    def _is_local_subnet(self, target: str) -> bool:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private
        except ValueError:
            return False

    def _scapy_arp_discovery(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                results.append({
                    "ip": received.psrc,
                    "hostname": "",
                    "status": "up",
                    "mac_address": received.hwsrc,
                    "vendor": "",
                    "response_time_ms": ""
                })
        except Exception as e:
            print(f"Scapy ARP error: {e}")
        return results
