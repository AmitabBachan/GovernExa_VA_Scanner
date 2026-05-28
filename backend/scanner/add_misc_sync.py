import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = """                if not existing_vuln:
                    v_record = Vulnerability(
                        cve_id=cve_id,
                        scan_result_id=scan_result.id,
                        risk_score=50.0, # Will be updated by risk scoring task later
                        status="Open"
                    )
                    db.add(v_record)
                    db.flush()
                    sync_count += 1
                    
                    # 4. Generate Remediation
                    existing_rem = db.query(RemediationLibrary).filter(RemediationLibrary.vulnerability_id == v_record.id).first()
                    if not existing_rem:
                        rem = RemediationLibrary(
                            vulnerability_id=v_record.id,
                            patch_version="Latest",
                            recommended_update=f"Apply latest vendor patches for {finding.product or 'the affected service'}.",
                            workaround="Isolate service if patch is unavailable.",
                            mitigation="Restrict network access to affected port."
                        )
                        db.add(rem)"""

replacement = """                if not existing_vuln:
                    v_record = Vulnerability(
                        cve_id=cve_id,
                        scan_result_id=scan_result.id,
                        risk_score=cvss * 10, # default risk score
                        status="Open"
                    )
                    db.add(v_record)
                    db.flush()
                    sync_count += 1
                    
                    # 4. Generate Remediation
                    existing_rem = db.query(RemediationLibrary).filter(RemediationLibrary.vulnerability_id == v_record.id).first()
                    if not existing_rem:
                        rem = RemediationLibrary(
                            vulnerability_id=v_record.id,
                            patch_version="Latest",
                            recommended_update=f"Apply latest vendor patches for {finding.product or 'the affected service'}.",
                            workaround="Isolate service if patch is unavailable.",
                            mitigation="Restrict network access to affected port."
                        )
                        db.add(rem)
                        
            # Also process misconfigurations as vulnerabilities
            misconfigs = finding.misconfigurations
            if isinstance(misconfigs, str):
                import json
                try:
                    misconfigs = json.loads(misconfigs)
                except:
                    misconfigs = []
            if not misconfigs:
                misconfigs = []
                
            import hashlib
            for idx, misc in enumerate(misconfigs):
                misc_text = str(misc)
                # Create a pseudo-CVE ID for the misconfiguration
                misc_hash = hashlib.md5(misc_text.encode()).hexdigest()[:8]
                misc_id = f"MISC-{misc_hash.upper()}"
                
                # Ensure pseudo-CVE in catalog
                cve_entry = db.query(CveCatalog).filter(CveCatalog.cve_id == misc_id).first()
                if not cve_entry:
                    cve_entry = CveCatalog(
                        cve_id=misc_id,
                        description=misc_text,
                        severity="Medium",
                        cvss_score=5.0
                    )
                    db.add(cve_entry)
                    db.flush()
                    
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.scan_result_id == scan_result.id,
                    Vulnerability.cve_id == misc_id
                ).first()
                
                if not existing_vuln:
                    v_record = Vulnerability(
                        cve_id=misc_id,
                        scan_result_id=scan_result.id,
                        risk_score=50.0,
                        status="Open"
                    )
                    db.add(v_record)
                    db.flush()
                    sync_count += 1
                    
                    rem = RemediationLibrary(
                        vulnerability_id=v_record.id,
                        patch_version="N/A",
                        recommended_update="Review configuration against security best practices.",
                        workaround="Apply secure configuration changes.",
                        mitigation="Disable insecure features or protocols."
                    )
                    db.add(rem)"""

content = content.replace(target, replacement)

with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("tasks.py updated to include misconfigurations in sync")
