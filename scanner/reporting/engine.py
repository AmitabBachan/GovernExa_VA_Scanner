import json
import csv
import os
from typing import Dict, Any, List
from datetime import datetime

class ReportingEngine:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_report(self, scan_data: Dict[str, Any], formats: List[str] = ["json", "csv"]) -> Dict[str, str]:
        """
        Generate reports in specified formats based on scan findings.
        scan_data should contain 'asset_summary', 'findings', etc.
        """
        report_paths = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = os.path.join(self.output_dir, f"vulnscope_report_{timestamp}")
        
        if "json" in formats:
            path = f"{base_filename}.json"
            self._generate_json(scan_data, path)
            report_paths["json"] = path
            
        if "csv" in formats:
            path = f"{base_filename}.csv"
            self._generate_csv(scan_data, path)
            report_paths["csv"] = path
            
        if "pdf" in formats:
            path = f"{base_filename}.pdf"
            self._generate_pdf(scan_data, path)
            report_paths["pdf"] = path
            
        return report_paths

    def _generate_json(self, data: Dict[str, Any], filepath: str):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

    def _generate_csv(self, data: Dict[str, Any], filepath: str):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Target IP", "Port", "Service", "Product", "Version", "CVE", "Severity", "Risk Score"])
            
            for finding in data.get("findings", []):
                writer.writerow([
                    finding.get("ip"),
                    finding.get("port"),
                    finding.get("service"),
                    finding.get("product"),
                    finding.get("version"),
                    finding.get("cve_id"),
                    finding.get("severity"),
                    finding.get("risk_score")
                ])

    def _generate_pdf(self, data: Dict[str, Any], filepath: str):
        # Stub logic using a simple text-to-pdf library or reportlab
        # For a full implementation, we'd use ReportLab to construct tables and charts
        try:
            from reportlab.pdfgen import canvas
            c = canvas.Canvas(filepath)
            c.drawString(100, 800, "VulnScope Vulnerability Report")
            c.drawString(100, 780, f"Generated: {datetime.now().isoformat()}")
            
            y = 750
            for finding in data.get("findings", []):
                c.drawString(100, y, f"IP: {finding.get('ip')} - CVE: {finding.get('cve_id')} - Severity: {finding.get('severity')}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = 800
            c.save()
        except ImportError:
            print("ReportLab is not installed. PDF generation failed.")
