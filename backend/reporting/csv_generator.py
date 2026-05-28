import csv
import os
from typing import Dict, Any

class CSVGenerator:
    """
    Generates CSV exports for tabular data like findings and assets.
    """
    def __init__(self, output_dir: str = "/tmp/reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self, data: Dict[str, Any], filename: str, report_type: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename}.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            if report_type == "technical":
                writer.writerow(["Target IP", "Port", "Protocol", "Service", "CVE", "Severity", "Risk Score"])
                for finding in data.get("findings", []):
                    writer.writerow([
                        finding.get("ip"),
                        finding.get("port"),
                        finding.get("protocol"),
                        finding.get("service"),
                        finding.get("cve_id"),
                        finding.get("severity"),
                        finding.get("risk_score")
                    ])
            elif report_type == "remediation":
                writer.writerow(["Target IP", "CVE", "Severity", "Recommended Update", "Mitigation"])
                for finding in data.get("findings", []):
                    writer.writerow([
                        finding.get("ip"),
                        finding.get("cve_id"),
                        finding.get("severity"),
                        finding.get("recommended_update"),
                        finding.get("mitigation")
                    ])
                    
        return filepath
