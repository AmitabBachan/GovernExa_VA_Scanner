from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from datetime import datetime
import json
from fastapi.responses import StreamingResponse
import io

from auth.rbac import require_role
from api.deps import get_db
from licensing.dependencies import verify_license

from models.scans import ScanJob, ScanResult
from models.assets import Device, InstalledSoftware
from models.asset_discovery import AssetDiscoveryResult
from models.port_scan import PortScanResult, PortScanSummary
from models.service_fingerprint import ServiceFingerprintResult
from models.enumeration import EnumerationResult
from models.vulnerability_scan import VulnerabilityScanFinding
from models.auth_scan import AuthScanFinding
from models.risk_scoring import RiskScoringResult
from models.validation import ValidationResult
from models.reports import Report

router = APIRouter(prefix="/backup", tags=["Backup"], dependencies=[Depends(verify_license)])

def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        val = getattr(row, column.name)
        if isinstance(val, datetime):
            d[column.name] = val.isoformat()
        else:
            d[column.name] = val
    return d

MODELS_TO_BACKUP = {
    "scan_jobs": ScanJob,
    "devices": Device,
    "installed_software": InstalledSoftware,
    "scan_results": ScanResult,
    "asset_discovery": AssetDiscoveryResult,
    "port_scan_summaries": PortScanSummary,
    "port_scan_results": PortScanResult,
    "service_fingerprints": ServiceFingerprintResult,
    "enumerations": EnumerationResult,
    "vulnerability_scans": VulnerabilityScanFinding,
    "auth_scans": AuthScanFinding,
    "risk_scoring": RiskScoringResult,
    "validations": ValidationResult,
    "reports": Report
}

@router.get("/export")
def export_backup(
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """
    Generate a full JSON backup of all scan data.
    """
    backup_data = {}
    
    for key, model in MODELS_TO_BACKUP.items():
        records = db.query(model).all()
        backup_data[key] = [row2dict(r) for r in records]
        
    json_str = json.dumps(backup_data)
    
    return StreamingResponse(
        io.BytesIO(json_str.encode('utf-8')),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=vulnerability_scanner_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
    )

@router.post("/import")
async def import_backup(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """
    Restore data from a JSON backup file.
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only JSON files are supported for backup restoration.")
        
    try:
        contents = await file.read()
        backup_data = json.loads(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {str(e)}")
        
    try:
        # Import in correct order to respect foreign keys
        order = [
            "devices", "installed_software", "scan_jobs", "scan_results", 
            "asset_discovery", "port_scan_summaries", "port_scan_results", "service_fingerprints",
            "enumerations", "vulnerability_scans", "auth_scans", 
            "risk_scoring", "validations", "reports"
        ]
        
        for key in order:
            if key in backup_data and key in MODELS_TO_BACKUP:
                model = MODELS_TO_BACKUP[key]
                items = backup_data[key]
                for item_dict in items:
                    # Convert iso strings back to datetime if necessary
                    # SQLAlchemy handles most string-to-datetime automatically during merge
                    obj = model(**item_dict)
                    db.merge(obj)
                    
        db.commit()
        return {"status": "success", "message": "Backup restored successfully."}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to restore backup: {str(e)}")
