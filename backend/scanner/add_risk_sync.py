import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

# We need to insert a global Vulnerability update inside run_risk_scoring.
# Around line 944, right after `db.add(risk_result)`
target = """                    db.add(risk_result)
                    total_scored += 1"""

replacement = """                    db.add(risk_result)
                    total_scored += 1
                    
                    # Update the Global Vulnerability Tracker
                    from models.vulnerabilities import Vulnerability
                    from models.scans import ScanResult
                    from models.assets import Device
                    
                    # Join through Device to get the right ScanResult
                    device = db.query(Device).filter(Device.ip_address == ip).first()
                    if device:
                        scan_res = db.query(ScanResult).filter(
                            ScanResult.device_id == device.id,
                            ScanResult.scan_job_id == scan_job_id
                        ).first()
                        if scan_res:
                            global_vuln = db.query(Vulnerability).filter(
                                Vulnerability.scan_result_id == scan_res.id,
                                Vulnerability.cve_id == cve.get("id")
                            ).first()
                            
                            if global_vuln:
                                global_vuln.risk_score = calc["risk_score"]"""

content = content.replace(target, replacement)

with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("tasks.py updated with global vulnerability risk score sync")
