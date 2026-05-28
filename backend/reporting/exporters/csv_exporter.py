import csv

class CSVExporter:
    def __init__(self):
        pass

    def export(self, report_data: dict, output_path: str) -> bool:
        findings = report_data.get('detailed_findings', [])
        
        if not findings:
            # Just create an empty file with headers if no findings
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Severity', 'Name', 'Host', 'Port', 'Service', 'CVSS', 'CVE', 'Description'])
            return True

        # Extract keys from the first finding to use as headers, or default to a known set
        headers = ['severity', 'name', 'host', 'port', 'service', 'cvss', 'cve', 'profile_type', 'description', 'ai_explanation', 'remediation']
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            for finding in findings:
                if not isinstance(finding, dict):
                    finding_dict = getattr(finding, '__dict__', {})
                else:
                    finding_dict = finding
                writer.writerow(finding_dict)
                
        return True
