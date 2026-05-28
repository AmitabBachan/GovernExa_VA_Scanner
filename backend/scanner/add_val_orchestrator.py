import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add run_validation task before run_risk_scoring
validation_task = """
# =====================================================================
# Validation & Verification Scan
# =====================================================================
@shared_task(name="scanner.orchestrator.run_validation")
def run_validation(target: str, scan_job_id: str, mark_completed: bool = True):
    from scanner.validation import ValidationEngine
    from db.session import SessionLocal
    from models.vulnerability_scan import VulnerabilityScanFinding
    from models.validation import ValidationResult
    
    log_scan_event(scan_job_id, f"[Validation] Starting Validation & Verification on: {target}")
    
    db = SessionLocal()
    engine = ValidationEngine()
    try:
        # Fetch findings to validate
        findings = db.query(VulnerabilityScanFinding).filter(VulnerabilityScanFinding.scan_job_id == scan_job_id).all()
        if not findings:
            log_scan_event(scan_job_id, "[Validation] No findings to validate. Completing job.")
            if mark_completed:
                _mark_job_completed(scan_job_id)
            return {"status": "completed"}
            
        total_validated = 0
        total_fps = 0
        
        for finding in findings:
            cves = []
            if finding.cves:
                c_list = finding.cves if isinstance(finding.cves, list) else []
                cves.extend(c_list)
                
            if finding.misconfigurations:
                m_list = finding.misconfigurations if isinstance(finding.misconfigurations, list) else []
                # Map misconfigs to dict format for engine
                for m in m_list:
                    import hashlib
                    m_str = str(m)
                    cves.append({
                        "id": f"MISC-{hashlib.md5(m_str.encode()).hexdigest()[:8].upper()}",
                        "description": m_str
                    })
                    
            if not cves:
                continue
                
            log_scan_event(scan_job_id, f"[Validation] Verifying {len(cves)} finding(s) on {finding.ip_address}:{finding.port}...")
            
            results = engine.validate_findings(
                ip_address=finding.ip_address,
                cves=cves,
                port=finding.port,
                protocol=finding.protocol
            )
            
            for res in results:
                v_record = ValidationResult(
                    scan_job_id=scan_job_id,
                    ip_address=finding.ip_address,
                    vulnerability_id=res["vulnerability_id"],
                    is_confirmed=res["is_confirmed"],
                    is_false_positive=res["is_false_positive"],
                    verification_method=res["verification_method"],
                    proof_of_concept=res["proof_of_concept"]
                )
                db.add(v_record)
                total_validated += 1
                if res["is_false_positive"]:
                    total_fps += 1
                    
        db.commit()
        log_scan_event(scan_job_id, f"[Validation] Validated {total_validated} findings. Flagged {total_fps} false positives.")
    except Exception as e:
        log_scan_event(scan_job_id, f"Fatal error during validation: {e}")
        db.rollback()
        return {"status": "error"}
    finally:
        db.close()
        
    if mark_completed:
        _mark_job_completed(scan_job_id)
    return {"status": "completed", "validated": total_validated, "false_positives": total_fps}

"""

# Insert right before run_risk_scoring
parts = content.split('# =====================================================================\n# Risk Scoring')
content = parts[0] + validation_task + '\n# =====================================================================\n# Risk Scoring' + parts[1]


# 2. Modify run_risk_scoring to consume validation flags
# In run_risk_scoring around line 911 (or the loop):
# We need to query ValidationResult to see if it's a false positive.
target_risk = """            # Fetch existing vulnerabilities for this IP from recent scans
            vulns = db.query(VulnerabilityScanFinding).filter(
                VulnerabilityScanFinding.ip_address == ip
            ).all()"""

replacement_risk = """            # Fetch existing vulnerabilities for this IP from recent scans
            vulns = db.query(VulnerabilityScanFinding).filter(
                VulnerabilityScanFinding.ip_address == ip
            ).all()
            
            from models.validation import ValidationResult
            
            validations = db.query(ValidationResult).filter(
                ValidationResult.scan_job_id == scan_job_id,
                ValidationResult.ip_address == ip
            ).all()
            val_map = {v.vulnerability_id: v for v in validations}"""

content = content.replace(target_risk, replacement_risk)

target_risk_calc = """                    calc = engine.calculate_risk(cvss, environmental_factors)
                    
                    risk_result = RiskScoringResult("""

replacement_risk_calc = """                    calc = engine.calculate_risk(cvss, environmental_factors)
                    
                    # Apply False Positive Override
                    vuln_id = cve.get("id", "Unknown")
                    if vuln_id in val_map and val_map[vuln_id].is_false_positive:
                        calc["risk_score"] = 0.0
                        calc["severity"] = "False Positive"
                    
                    risk_result = RiskScoringResult("""
content = content.replace(target_risk_calc, replacement_risk_calc)

# 3. Modify run_full_scan to include run_validation
target_full = """    chain = (
        run_asset_discovery.s(target, scan_job_id, mark_completed=False) |
        run_port_scan.s(target, scan_job_id, mark_completed=False) |
        run_service_fingerprint.s(target, scan_job_id, mark_completed=False) |
        run_enumeration.s(target, scan_job_id, mark_completed=False) |
        run_vulnerability_scan.s(target, scan_job_id, mark_completed=False) |
        run_authenticated_scan.s(target, scan_job_id, credential_id, mark_completed=False) |
        run_risk_scoring.s(target, scan_job_id, mark_completed=True)
    )"""

replacement_full = """    chain = (
        run_asset_discovery.s(target, scan_job_id, mark_completed=False) |
        run_port_scan.s(target, scan_job_id, mark_completed=False) |
        run_service_fingerprint.s(target, scan_job_id, mark_completed=False) |
        run_enumeration.s(target, scan_job_id, mark_completed=False) |
        run_vulnerability_scan.s(target, scan_job_id, mark_completed=False) |
        run_authenticated_scan.s(target, scan_job_id, credential_id, mark_completed=False) |
        run_validation.s(target, scan_job_id, mark_completed=False) |
        run_risk_scoring.s(target, scan_job_id, mark_completed=True)
    )"""

content = content.replace(target_full, replacement_full)


with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("tasks.py updated for Validation Orchestration")
