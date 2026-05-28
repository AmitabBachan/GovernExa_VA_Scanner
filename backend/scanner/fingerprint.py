import nmap
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class FingerprintEngine:
    """
    Performs deep inspection on discovered assets.
    Service detection, OS detection, and version detection.
    """
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_host(self, target_ip: str, ports: str = None) -> List[Dict[str, Any]]:
        """
        Runs an Nmap service scan against the target IP.
        """
        results = []
        try:
            # -sV: Probe open ports to determine service/version info
            # -O: OS detection
            # -sC: Default scripts
            scan_args = '-sV -O -sC'
            if ports:
                scan_args += f' -p {ports}'
            else:
                scan_args += ' --top-ports 1000'
                
            logger.info(f"Starting fingerprint scan on {target_ip} with args: {scan_args}")
            self.nm.scan(hosts=target_ip, arguments=scan_args)
            
            if target_ip in self.nm.all_hosts():
                host_data = self.nm[target_ip]
                
                for proto in ['tcp', 'udp']:
                    if proto in host_data:
                        for port, port_data in host_data[proto].items():
                            if port_data['state'] == 'open':
                                results.append({
                                    "port": port,
                                    "protocol": proto,
                                    "service": port_data.get('name', ''),
                                    "product": port_data.get('product', ''),
                                    "version": port_data.get('version', ''),
                                    "extrainfo": port_data.get('extrainfo', ''),
                                    "cpe": port_data.get('cpe', '')
                                })
        except Exception as e:
            logger.error(f"Fingerprinting failed for {target_ip}: {e}")
            
        return results
