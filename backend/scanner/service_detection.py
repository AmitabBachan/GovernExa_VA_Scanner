"""
Service Detection Engine
Determines the software and version running on open ports.
Methods:
- Nmap -sV (Protocol negotiation, response analysis)
- Custom Banner Grabbing
- HTTP/HTTPS Server header extraction
"""
import nmap
import socket
import requests
import urllib3
import logging
from typing import List, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class ServiceDetectionEngine:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def detect_services(self, target: str, ports: str = None) -> List[Dict[str, Any]]:
        results = []
        try:
            # -sV: Probe open ports to determine service/version info
            # Speed optimizations: -n (no DNS), --min-rate 1000, --max-retries 1, light intensity
            scan_args = '-sV --version-intensity 2 -Pn -n --disable-arp-ping --min-rate 1000 --max-retries 1 --host-timeout 10m'
            if ports:
                scan_args += f' -p {ports}'
            else:
                scan_args += ' --top-ports 1000'
                
            logger.info(f"[ServiceDetection] Scanning {target} with args: {scan_args}")
            self.nm.scan(hosts=target, arguments=scan_args)
            
            if target in self.nm.all_hosts():
                host_data = self.nm[target]
                for proto in ['tcp', 'udp']:
                    if proto in host_data:
                        for port, data in host_data[proto].items():
                            if data['state'] == 'open':
                                record = {
                                    "ip": target,
                                    "port": port,
                                    "protocol": proto,
                                    "service": data.get('name', ''),
                                    "product": data.get('product', ''),
                                    "version": data.get('version', ''),
                                    "extrainfo": data.get('extrainfo', ''),
                                    "cpe": data.get('cpe', ''),
                                    "banner": "",
                                    "http_server": ""
                                }
                                
                                # Custom Banner Grabbing for TCP
                                if proto == 'tcp' and not record['product']:
                                    banner = self._grab_banner(target, port)
                                    if banner:
                                        record['banner'] = banner
                                        
                                # HTTP Header Extraction (if it's a web port)
                                if proto == 'tcp' and (record['service'] in ['http', 'https', 'http-proxy'] or port in [80, 443, 8080, 8443]):
                                    server_header = self._grab_http_server(target, port, record['service'])
                                    if server_header:
                                        record['http_server'] = server_header
                                        if not record['product']:
                                            record['product'] = server_header
                                            
                                results.append(record)
        except Exception as e:
            logger.error(f"Service detection failed for {target}: {e}")
            
        return results

    def _grab_banner(self, ip: str, port: int, timeout: float = 3.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(b"\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='replace').strip()
                return banner
        except Exception:
            return ""

    def _grab_http_server(self, ip: str, port: int, service: str) -> str:
        scheme = "https" if port in (443, 8443) or service == "https" else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            res = requests.head(url, timeout=3.0, verify=False, allow_redirects=True)
            return res.headers.get('Server', '')
        except Exception:
            try:
                res = requests.get(url, timeout=3.0, verify=False, allow_redirects=True)
                return res.headers.get('Server', '')
            except Exception:
                return ""
