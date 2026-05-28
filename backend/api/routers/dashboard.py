from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from auth.rbac import require_role
from api.deps import get_db
from models.assets import Device
from models.vulnerabilities import Vulnerability
from models.scans import ScanJob

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    total_assets = db.query(Device).count()
    
    # Severity counts
    from models.vulnerabilities import CveCatalog
    critical_findings = db.query(Vulnerability).join(CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id).filter(func.lower(CveCatalog.severity) == 'critical').count()
    high_findings = db.query(Vulnerability).join(CveCatalog, Vulnerability.cve_id == CveCatalog.cve_id).filter(func.lower(CveCatalog.severity) == 'high').count()
    
    # Recent scans
    recent_scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).limit(5).all()
    
    return {
        "total_assets": total_assets,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "recent_scans": [
            {
                "id": s.id,
                "target": s.target,
                "type": s.scan_type,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at
            } for s in recent_scans
        ]
    }
