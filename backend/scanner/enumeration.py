import nmap
import logging
from typing import List, Dict, Any
import json

logger = logging.getLogger(__name__)

class EnumerationEngine:
    """
    Performs deep enumeration on target hosts using Nmap NSE scripts.
    Collects info on SMB, SNMP, SSL, and DNS.
    """
    def __init__(self):
        self.nm = nmap.PortScanner()

    def run_enumeration(self, target: str) -> Dict[str, Any]:
        """
        Runs enumeration scripts and returns structured data per host.
        """
        results = {}
        
        # We target specific common ports for these services to speed up scanning.
        # 139,445 (SMB)
        # 161 (SNMP)
        # 53 (DNS)
        # 443,8443,etc (SSL)
        scripts = "smb-enum-shares,smb-os-discovery,snmp-sysdescr,snmp-interfaces,ssl-cert,dns-nsid,dns-zone-transfer"
        ports = "53,139,445,161,443,8443"
        
        try:
            # -sU -sS: We need both UDP (SNMP, DNS) and TCP
            logger.info(f"[Enumeration] Scanning {target} with scripts: {scripts}")
            
            # Using basic TCP SYN and UDP scan, specifically targeting the ports of interest
            args = f"-sS -sU -p T:53,139,445,443,8443,U:53,161 --script {scripts} -Pn -n --disable-arp-ping --host-timeout 10m"
            
            self.nm.scan(hosts=target, arguments=args)
            
            for host in self.nm.all_hosts():
                host_data = {
                    "ip": host,
                    "smb_shares": [],
                    "smb_users": [],
                    "snmp_sysdescr": "",
                    "snmp_interfaces": [],
                    "dns_records": [],
                    "ssl_certs": [],
                    "os_info": ""
                }
                
                # Nmap stores host scripts (like smb-os-discovery) here
                if 'hostscript' in self.nm[host]:
                    for script in self.nm[host]['hostscript']:
                        if script['id'] == 'smb-os-discovery':
                            host_data['os_info'] = script.get('output', '').strip()
                        elif script['id'] == 'smb-enum-shares':
                            # Nmap returns a large text block. We can store the raw output or parse basic lines.
                            # For simplicity, we store the raw output in a structured dict wrapper.
                            host_data['smb_shares'].append({"raw_output": script.get('output', '').strip()})
                            
                # Nmap stores port scripts here
                for proto in ['tcp', 'udp']:
                    if proto in self.nm[host]:
                        for port, port_data in self.nm[host][proto].items():
                            if 'script' in port_data:
                                sdata = port_data['script']
                                
                                # SSL Cert
                                if 'ssl-cert' in sdata:
                                    host_data['ssl_certs'].append({
                                        "port": port,
                                        "details": sdata['ssl-cert'].strip()
                                    })
                                    
                                # SNMP
                                if 'snmp-sysdescr' in sdata:
                                    host_data['snmp_sysdescr'] = sdata['snmp-sysdescr'].strip()
                                if 'snmp-interfaces' in sdata:
                                    host_data['snmp_interfaces'].append(sdata['snmp-interfaces'].strip())
                                    
                                # DNS
                                if 'dns-nsid' in sdata:
                                    host_data['dns_records'].append(sdata['dns-nsid'].strip())
                                if 'dns-zone-transfer' in sdata:
                                    host_data['dns_records'].append(sdata['dns-zone-transfer'].strip())
                
                results[host] = host_data
                
        except Exception as e:
            logger.error(f"Enumeration failed for {target}: {e}")
            
        return results
