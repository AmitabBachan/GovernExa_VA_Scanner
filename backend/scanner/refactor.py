import re

with open('backend/scanner/tasks.py', 'r', encoding='utf-8') as f:
    content = f.read()

tasks = [
    "run_asset_discovery",
    "run_port_scan",
    "run_service_fingerprint",
    "run_enumeration",
    "run_vulnerability_scan",
    "run_authenticated_scan",
    "run_risk_scoring"
]

for task in tasks:
    # 1. Update signature
    if task == "run_asset_discovery":
        content = re.sub(
            r'def run_asset_discovery\(target: str, scan_job_id: str, cloud_integration: str = None\):',
            'def run_asset_discovery(target: str, scan_job_id: str, cloud_integration: str = None, mark_completed: bool = True):',
            content
        )
    elif task == "run_authenticated_scan":
        content = re.sub(
            r'def run_authenticated_scan\(target: str, scan_job_id: str, credential_id: int\):',
            'def run_authenticated_scan(target: str, scan_job_id: str, credential_id: int, mark_completed: bool = True):',
            content
        )
    else:
        content = re.sub(
            f'def {task}\\(target: str, scan_job_id: str\\):',
            f'def {task}(target: str, scan_job_id: str, mark_completed: bool = True):',
            content
        )
        
    # 2. Update completion block inside the function (it's always before `return {"status": "completed"}`)
    # Since there can be multiple returns or mark_completed, let's just replace `_mark_job_completed(scan_job_id)` 
    # but ONLY inside these functions. To be safe, I'll replace all `_mark_job_completed(scan_job_id)` with a check,
    # except we need to be careful. Let's just do a global replace for the exact string if it's indented.
    
# Global replace for the completion call
content = content.replace(
    '    _mark_job_completed(scan_job_id)\n',
    '    if mark_completed:\n        _mark_job_completed(scan_job_id)\n'
)

# And if there are `return {"status": "completed"}` inside a bare `_mark_job_completed`, wait, some early returns have it too:
# `_mark_job_completed(scan_job_id, status="FAILED")` shouldn't be gated by mark_completed if it's an error. 
# We'll leave `status="FAILED"` alone.

with open('backend/scanner/tasks.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Tasks refactored.")
