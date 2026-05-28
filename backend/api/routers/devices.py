from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from auth.rbac import require_role
from api.deps import get_db
from models.assets import Device

router = APIRouter(prefix="/devices", tags=["Inventory"])

@router.get("/")
def list_devices(
    page: int = 1, 
    limit: int = 50, 
    current_user: dict = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    """
    Retrieve paginated list of all scanned devices.
    """
    offset = (page - 1) * limit
    total = db.query(Device).count()
    devices = db.query(Device).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "page": page,
        "data": [
            {
                "id": d.id,
                "ip": d.ip_address,
                "hostname": d.hostname,
                "os": d.os_name,
                "mac": d.mac_address,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None
            }
            for d in devices
        ]
    }

@router.get("/{device_id}")
def get_device(device_id: int, current_user: dict = Depends(require_role("viewer"))):
    return {"id": device_id, "ip_address": "192.168.1.10", "details": "Stub details"}
