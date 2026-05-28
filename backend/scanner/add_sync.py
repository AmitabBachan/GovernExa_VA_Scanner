import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

# The function to append
sync_func = """
# =====================================================================
# Synchronize Modular Findings to Global Tracker
# =====================================================================
def sync_findings_to_global_tracker(scan_job_id: str):
    from db.session import SessionLocal
    from models.scans import ScanResult, ScanJob
    from models.vulnerabilities import Vulnerability, CveCatalog, RemediationLibrary
    from models.assets import Device
    from models.vulnerability_scan import VulnerabilityScanFinding
    
    log_scan_event(scan_job_id, "[Sync] Synchronizing scan findings with Global Tracker...")
    
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            return
            
        # Get all raw findings from this job
        findings = db.query(VulnerabilityScanFinding).filter(VulnerabilityScanFinding.scan_job_id == scan_job_id).all()
        
        sync_count = 0
        for finding in findings:
            # 1. Ensure Device exists
            device = db.query(Device).filter(Device.ip_address == finding.ip_address).first()
            if not device:
                device = Device(ip_address=finding.ip_address, os_family="Unknown")
                db.add(device)
                db.flush()
                
            # 2. Ensure ScanResult exists
            scan_result = db.query(ScanResult).filter(
                ScanResult.scan_job_id == scan_job_id,
                ScanResult.device_id == device.id
            ).first()
            if not scan_result:
                scan_result = ScanResult(
                    scan_job_id=scan_job_id,
                    device_id=device.id,
                    protocol=finding.protocol or "tcp",
                    service_name=finding.service or "unknown"
                )
                db.add(scan_result)
                db.flush()
                
            # 3. Add Vulnerabilities
            cves = finding.cves
            if isinstance(cves, str):
                import json
                cves = json.loads(cves)
                
            for cve_id in cves:
                # Ensure CVE in catalog
                cve_entry = db.query(CveCatalog).filter(CveCatalog.cve_id == cve_id).first()
                if not cve_entry:
                    cve_entry = CveCatalog(
                        cve_id=cve_id,
                        description="Automatically populated from scan.",
                        severity="High",
                        cvss_score=7.0
                    )
                    db.add(cve_entry)
                    db.flush()
                
                # Check if this vuln is already tracked for this scan_result
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.scan_result_id == scan_result.id,
                    Vulnerability.cve_id == cve_id
                ).first()
                
                if not existing_vuln:
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
                        db.add(rem)
        
        db.commit()
        log_scan_event(scan_job_id, f"[Sync] Successfully correlated {sync_count} vulnerabilities into the Global Tracker.")
    except Exception as e:
        logger.error(f"Sync error: {e}")
        db.rollback()
    finally:
        db.close()
"""

# Append to file
content += sync_func

# Now we need to insert the call `sync_findings_to_global_tracker(scan_job_id)`
# at the end of `run_vulnerability_scan` right before `log_scan_event(scan_job_id, f"[VulnScan] COMPLETE.")`

call_string = """
    # Sync to global tracker
    sync_findings_to_global_tracker(scan_job_id)

    log_scan_event"""

content = content.replace('    log_scan_event(scan_job_id, f"[VulnScan] COMPLETE.")', call_string)

with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("tasks.py updated with sync_findings_to_global_tracker")
