import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Update run_scan_pipeline to handle full_scan
replacement = """    # ---- Full Scan (1 to 7) ----
    if scan_type == "full_scan":
        credential_id = kwargs.get("credential_id")
        run_full_scan.delay(target, scan_job_id, credential_id)
        return {"status": "started", "scan_job_id": scan_job_id}"""

content = content.replace(
    '    # ---- Asset Discovery profile — dedicated lightweight pipeline ----',
    replacement + '\n\n    # ---- Asset Discovery profile — dedicated lightweight pipeline ----'
)

# 2. Add run_full_scan at the end of the file
full_scan_task = """
# =====================================================================
# Full Scan Orchestrator
# =====================================================================
@shared_task(name="scanner.orchestrator.run_full_scan")
def run_full_scan(target: str, scan_job_id: str, credential_id: str = None):
    log_scan_event(scan_job_id, f"=== STARTING FULL SCAN FOR {target} ===")
    
    # Step 1: Asset Discovery
    log_scan_event(scan_job_id, "[Step 1/7] Asset Discovery...")
    run_asset_discovery(target, scan_job_id, cloud_integration=None, mark_completed=False)
    
    # Step 2: Port Scan
    log_scan_event(scan_job_id, "[Step 2/7] Port Scan...")
    run_port_scan(target, scan_job_id, mark_completed=False)
    
    # Step 3: Service Fingerprint
    log_scan_event(scan_job_id, "[Step 3/7] Service Fingerprint...")
    run_service_fingerprint(target, scan_job_id, mark_completed=False)
    
    # Step 4: Enumeration
    log_scan_event(scan_job_id, "[Step 4/7] System Enumeration...")
    run_enumeration(target, scan_job_id, mark_completed=False)
    
    # Step 5: Vulnerability Scan
    log_scan_event(scan_job_id, "[Step 5/7] Vulnerability Detection...")
    run_vulnerability_scan(target, scan_job_id, mark_completed=False)
    
    # Step 6: Authenticated Scan (if credentials provided)
    if credential_id:
        log_scan_event(scan_job_id, "[Step 6/7] Authenticated Deep Scan...")
        run_authenticated_scan(target, scan_job_id, int(credential_id), mark_completed=False)
    else:
        log_scan_event(scan_job_id, "[Step 6/7] Authenticated Deep Scan skipped (No credentials provided).")
        
    # Step 7: Risk Scoring
    log_scan_event(scan_job_id, "[Step 7/7] Risk Scoring & Severity Classification...")
    # This one CAN mark it as completed since it is the last step!
    run_risk_scoring(target, scan_job_id, mark_completed=True)
    
    log_scan_event(scan_job_id, f"=== FULL SCAN COMPLETED FOR {target} ===")
    return {"status": "completed"}
"""

content += full_scan_task

with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("tasks.py updated with run_full_scan")
