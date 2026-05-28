try:
    import openpyxl
except ImportError:
    openpyxl = None

class XLSXExporter:
    def __init__(self):
        pass

    def export(self, report_data: dict, output_path: str) -> bool:
        if openpyxl is None:
            raise ImportError("openpyxl is not installed.")

        wb = openpyxl.Workbook()
        
        # Metadata Sheet
        ws_meta = wb.active
        ws_meta.title = "Report Metadata"
        ws_meta.append(["Property", "Value"])
        ws_meta.append(["Title", report_data.get('title', '')])
        ws_meta.append(["Generated Timestamp", report_data.get('generated_timestamp', '')])
        ws_meta.append(["Executive Summary", report_data.get('executive_summary', '')])
        
        # Findings Sheet
        findings = report_data.get('detailed_findings', [])
        if findings:
            ws_findings = wb.create_sheet(title="Findings")
            
            headers = ['Severity', 'Name', 'Host', 'Port', 'Service', 'CVSS', 'CVE', 'Profile Type', 'Description', 'AI Explanation', 'Remediation']
            ws_findings.append(headers)
            
            keys = ['severity', 'name', 'host', 'port', 'service', 'cvss', 'cve', 'profile_type', 'description', 'ai_explanation', 'remediation']
            
            for finding in findings:
                if not isinstance(finding, dict):
                    finding_dict = getattr(finding, '__dict__', {})
                else:
                    finding_dict = finding
                    
                row = [finding_dict.get(k, '') for k in keys]
                ws_findings.append(row)
                
        wb.save(output_path)
        return True
