import nmap
from typing import List, Dict, Any

class FingerprintEngine:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def fingerprint(self, target_ip: str, ports: str = None) -> List[Dict[str, Any]]:
        """
        Fingerprint services on the target IP using Nmap.
        Performs port scan, banner grabbing, service detection, and version detection.
        """
        results = []
        
        try:
            # -sV: Probe open ports to determine service/version info
            # -O: OS detection (requires root, might fail if not run as root)
            # --script=default,banner: Run default scripts and banner grabbing
            scan_args = '-sV -sC -O'
            if ports:
                scan_args += f' -p {ports}'
            else:
                # Fast scan of top 1000 ports if no ports specified
                scan_args += ' --top-ports 1000'
                
            self.nm.scan(hosts=target_ip, arguments=scan_args)
            
            if target_ip in self.nm.all_hosts():
                host_data = self.nm[target_ip]
                
                # Check TCP ports
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            results.append({
                                "port": port,
                                "protocol": "tcp",
                                "service": port_data.get('name', ''),
                                "product": port_data.get('product', ''),
                                "version": port_data.get('version', ''),
                                "extrainfo": port_data.get('extrainfo', ''),
                                "cpe": port_data.get('cpe', '')
                            })
                
                # Check UDP ports
                if 'udp' in host_data:
                    for port, port_data in host_data['udp'].items():
                        if port_data['state'] == 'open':
                            results.append({
                                "port": port,
                                "protocol": "udp",
                                "service": port_data.get('name', ''),
                                "product": port_data.get('product', ''),
                                "version": port_data.get('version', ''),
                                "extrainfo": port_data.get('extrainfo', ''),
                                "cpe": port_data.get('cpe', '')
                            })
                            
        except nmap.PortScannerError as e:
            print(f"Nmap fingerprinting error: {e}")
            
        return results
