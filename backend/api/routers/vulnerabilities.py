from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from auth.rbac import require_role
from api.deps import get_db
from models.vulnerabilities import Vulnerability
from models.scans import ScanResult
from models.assets import Device

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

@router.get("/")
def list_vulnerabilities(
    page: int = 1, 
    limit: int = 50, 
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """
    Retrieve paginated list of all vulnerabilities.
    """
    offset = (page - 1) * limit
    total = db.query(Vulnerability).count()
    
    from models.vulnerabilities import CveCatalog
    from models.scans import ScanJob
    # Join with ScanResult, Device, CveCatalog, and ScanJob
    vulns = db.query(Vulnerability, ScanResult, Device, CveCatalog, ScanJob).join(
        ScanResult, Vulnerability.scan_result_id == ScanResult.id
    ).join(
        Device, ScanResult.device_id == Device.id
    ).outerjoin(
        CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id
    ).join(
        ScanJob, ScanResult.scan_job_id == ScanJob.id
    ).offset(offset).limit(limit).all()
    
    from utils.cve_parser import get_cve_details
    
    enriched_data = []
    for v in vulns:
        details = get_cve_details(v.Vulnerability.cve_id)
        
        # Prefer the exact severity from the JSON if valid, else fallback to catalog
        json_severity = details.get("cvss_severity", "Unknown")
        final_severity = json_severity if json_severity != "Unknown" else (v.CveCatalog.severity if v.CveCatalog else "Unknown")
        
        enriched_data.append({
            "id": v.Vulnerability.id,
            "cve_id": v.Vulnerability.cve_id,
            "ip": v.Device.ip_address,
            "severity": final_severity.upper(),
            "risk_score": v.Vulnerability.risk_score,
            "status": v.Vulnerability.status,
            "reason": v.Vulnerability.reason,
            "scan_date": v.ScanJob.started_at.isoformat() if v.ScanJob and v.ScanJob.started_at else None,
            # Merging with ALL parser data
            **details
        })
    
    return {
        "total": total,
        "page": page,
        "data": enriched_data
    }

from pydantic import BaseModel
class StatusUpdate(BaseModel):
    status: str

@router.patch("/{vuln_id}/status")
def update_vulnerability_status(
    vuln_id: int, 
    update: StatusUpdate,
    current_user: dict = Depends(require_role("editor")),
    db: Session = Depends(get_db)
):
    from fastapi import HTTPException
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    valid_statuses = ["Open", "InProcess", "Closed"]
    if update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    if update.status == "Closed" and (not v.reason or v.reason.strip() == ""):
        raise HTTPException(status_code=400, detail="A reason is required before marking a vulnerability as Closed.")
        
    v.status = update.status
    db.commit()
    
    return {"message": "Status updated successfully", "status": v.status}

class ReasonUpdate(BaseModel):
    reason: str

@router.patch("/{vuln_id}/reason")
def update_vulnerability_reason(
    vuln_id: int, 
    update: ReasonUpdate,
    current_user: dict = Depends(require_role("editor")),
    db: Session = Depends(get_db)
):
    from fastapi import HTTPException
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    if v.status == "Closed" and (not update.reason or update.reason.strip() == ""):
        raise HTTPException(status_code=400, detail="Cannot clear the reason while the vulnerability is marked as Closed.")
        
    v.reason = update.reason
    db.commit()
    
    return {"message": "Reason updated successfully", "reason": v.reason}

@router.post("/{vuln_id}/ticket")
def generate_ticket_via_webhook(
    vuln_id: int,
    current_user: dict = Depends(require_role("editor")),
    db: Session = Depends(get_db)
):
    from fastapi import HTTPException
    import requests
    from models.settings import SystemSetting
    
    # Get settings
    webhook_url_setting = db.query(SystemSetting).filter(SystemSetting.key == "webhook_url").first()
    webhook_auth_setting = db.query(SystemSetting).filter(SystemSetting.key == "webhook_auth_token").first()
    
    if not webhook_url_setting or not webhook_url_setting.value:
        raise HTTPException(status_code=400, detail="Ticketing Webhook URL is not configured in Settings.")
        
    # Get vulnerability data
    from models.vulnerabilities import CveCatalog
    v = db.query(Vulnerability, ScanResult, Device, CveCatalog).join(
        ScanResult, Vulnerability.scan_result_id == ScanResult.id
    ).join(
        Device, ScanResult.device_id == Device.id
    ).outerjoin(
        CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id
    ).filter(Vulnerability.id == vuln_id).first()
    
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    from utils.cve_parser import get_cve_details
    details = get_cve_details(v.Vulnerability.cve_id)
    
    payload = {
        "id": v.Vulnerability.id,
        "cve_id": v.Vulnerability.cve_id,
        "ip": v.Device.ip_address,
        "severity": v.CveCatalog.severity if v.CveCatalog else "Unknown",
        "risk_score": v.Vulnerability.risk_score,
        "status": v.Vulnerability.status,
        "reason": v.Vulnerability.reason,
        **details
    }
    
    headers = {"Content-Type": "application/json"}
    if webhook_auth_setting and webhook_auth_setting.value:
        headers["Authorization"] = webhook_auth_setting.value
        
    try:
        response = requests.post(webhook_url_setting.value, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Failed to generate ticket via webhook: {str(e)}")
        
    return {"message": "Ticket generated successfully", "webhook_status_code": response.status_code}

@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: int, current_user: dict = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    from models.vulnerabilities import CveCatalog
    from models.scans import ScanJob
    v = db.query(Vulnerability, ScanResult, Device, CveCatalog, ScanJob).join(
        ScanResult, Vulnerability.scan_result_id == ScanResult.id
    ).join(
        Device, ScanResult.device_id == Device.id
    ).outerjoin(
        CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id
    ).join(
        ScanJob, ScanResult.scan_job_id == ScanJob.id
    ).filter(Vulnerability.id == vuln_id).first()
    
    if not v:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    from utils.cve_parser import get_cve_details
    details = get_cve_details(v.Vulnerability.cve_id)
    
    return {
        "id": v.Vulnerability.id,
        "cve_id": v.Vulnerability.cve_id,
        "ip": v.Device.ip_address,
        "scan_date": v.ScanJob.started_at.isoformat() if v.ScanJob and v.ScanJob.started_at else None,
        "severity": v.CveCatalog.severity if v.CveCatalog else "Unknown",
        "risk_score": v.Vulnerability.risk_score,
        "status": v.Vulnerability.status,
        "reason": v.Vulnerability.reason,
        **details
    }
