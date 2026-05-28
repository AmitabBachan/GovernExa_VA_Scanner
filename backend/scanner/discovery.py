import nmap
import ipaddress
import platform
import logging
from typing import List, Dict, Any
from scapy.all import ARP, Ether, srp

logger = logging.getLogger(__name__)

class DiscoveryEngine:
    """
    Handles local network asset discovery using Nmap as primary and Scapy as fallback.
    Designed to be executed concurrently via Celery workers.
    """
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_network(self, target: str) -> List[Dict[str, Any]]:
        """
        Executes ARP, ICMP, TCP, UDP sweeps based on the target.
        """
        results = []
        is_local = self._is_local_subnet(target)
        
        try:
            # -sn: Ping Scan
            # -PE/PP/PM: ICMP probes
            # -PS/PA/PU: TCP SYN/ACK, UDP sweeps
            # -n: No DNS resolution (dramatically speeds up local scans)
            # -T4: Aggressive timing
            scan_args = '-sn -n -T4 -PE -PS443,80 -PA80 -PU40125 --disable-arp-ping'
            self.nm.scan(hosts=target, arguments=scan_args)
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    mac = self.nm[host]['addresses'].get('mac', '')
                    results.append({
                        "ip": host,
                        "status": "up",
                        "mac_address": mac,
                        "vendor": self.nm[host]['vendor'].get(mac, '') if mac else ''
                    })
                    
        except Exception as e:
            logger.error(f"Nmap discovery failed for {target}: {e}")
            
        # Fallback to Scapy for local subnets if Nmap fails or returns empty
        if is_local and not results:
            logger.info(f"Falling back to Scapy ARP discovery for {target}")
            results = self._scapy_arp_sweep(target)
            
        return results

    def _is_local_subnet(self, target: str) -> bool:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private
        except ValueError:
            return False

    def _scapy_arp_sweep(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                results.append({
                    "ip": received.psrc,
                    "status": "up",
                    "mac_address": received.hwsrc,
                    "vendor": "Unknown (Scapy)"
                })
        except Exception as e:
            logger.error(f"Scapy ARP sweep failed: {e}")
        return results
