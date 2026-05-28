import json
import os
from pathlib import Path
from typing import List, Dict, Any
from core.config import settings

class CorrelationEngine:
    def __init__(self):
        self.cve_path = Path(settings.CVE_DB_PATH)

    def correlate(self, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Map Product + Version -> CPE -> CVE
        Uses local CVE JSON database.
        """
        vulnerabilities = []
        cpe_target = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*" # Simplified CPE matching pattern
        
        # In a real-world scenario, we wouldn't scan all files for every query.
        # We would index this data into PostgreSQL/Redis beforehand.
        # This is a simple proof of concept simulation reading the files directly.
        if not self.cve_path.exists():
            print(f"CVE database path {self.cve_path} does not exist.")
            return vulnerabilities
            
        try:
            for root, dirs, files in os.walk(self.cve_path):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            
                            # Extremely simplified CVE JSON parsing (assuming NVD JSON 5.0 schema loosely)
                            if 'cveMetadata' in data:
                                cve_id = data['cveMetadata'].get('cveId')
                                # check CPE configurations
                                if self._matches_cpe(data, product, version):
                                    vulnerabilities.append({
                                        "cve_id": cve_id,
                                        "cvss": self._extract_cvss(data),
                                        "severity": self._extract_severity(data),
                                        "affected_package": product,
                                        "vulnerable_version_range": version # In reality, we'd extract the range from the CVE data
                                    })
        except Exception as e:
            print(f"Error correlating CVEs: {e}")
            
        return vulnerabilities

    def _matches_cpe(self, cve_data: Dict[str, Any], product: str, version: str) -> bool:
        # Stub logic to search for the product and version in the JSON structure
        # A full implementation would parse the complex NVD nodes/cpeMatch arrays
        json_str = json.dumps(cve_data).lower()
        if product.lower() in json_str and version.lower() in json_str:
            return True
        return False

    def _extract_cvss(self, cve_data: Dict[str, Any]) -> float:
        # Stub logic to extract CVSS base score
        return 7.5

    def _extract_severity(self, cve_data: Dict[str, Any]) -> str:
        # Stub logic
        return "High"
