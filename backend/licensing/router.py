from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from pydantic import BaseModel

from licensing.models import License, LicenseActivation, AuditLog, RevokedLicense
from licensing.validators import verify_license_token
from licensing.dependencies import get_db, verify_license
from licensing.system_fingerprint import get_machine_fingerprint
from licensing.state_manager import update_state_file, _hash_state

router = APIRouter(prefix="/api/licensing", tags=["Licensing"])

class LicenseActivationRequest(BaseModel):
    license_token: str # A JWT containing license data signed by private key
    device_id: str
    
class OnlineActivationRequest(BaseModel):
    license_key: str
    device_id: str

@router.post("/activate/offline")
def activate_offline(request: LicenseActivationRequest, db: Session = Depends(get_db)):
    """
    Activates a license offline using a signed token (JWT).
    """
    try:
        payload = verify_license_token(request.license_token)
    except ValueError as e:
        db.add(AuditLog(action="FAILED_OFFLINE_ACTIVATION", details=str(e), device_id=request.device_id))
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        
    license_key = payload.get("license_key")
    license_id = payload.get("license_id")
    payload_fingerprint = payload.get("machine_fingerprint")
    
    if not license_key or not license_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload: missing license_key or license_id.")
        
    local_fingerprint = get_machine_fingerprint()
    if payload_fingerprint and payload_fingerprint != local_fingerprint:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This license belongs to another GovernExa installation.")

    # Check if the license is revoked
    if db.query(RevokedLicense).filter(RevokedLicense.license_key == license_key).first():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="License has been revoked.")
        
    # Check if license exists and is consumed
    db_license = db.query(License).filter(License.license_id == license_id).first()
    if db_license and db_license.consumed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This license has already been consumed and cannot be reused.")
        
    if not db_license:
        # Calculate expiration based on validity_days from activation time
        validity_days = payload.get("validity_days")
        if validity_days is not None:
            expires_at = datetime.utcnow() + timedelta(days=int(validity_days))
        else:
            # Fallback for old tokens
            expires_at = datetime.fromtimestamp(payload.get("exp")) if payload.get("exp") else None

        activation_time = datetime.utcnow()
        # Generate activation hash
        hash_str = f"{license_id}|True|{local_fingerprint}|{activation_time.isoformat()}"
        import hashlib
        activation_hash = hashlib.sha256(hash_str.encode('utf-8')).hexdigest()

        db_license = License(
            license_id=license_id,
            license_key=license_key,
            customer_name=payload.get("customer_name") or payload.get("customer"),
            tier=payload.get("tier") or payload.get("type") or "Standard",
            features=str(payload.get("features", [])),
            max_scans=payload.get("max_scans", -1),
            max_assets=payload.get("max_assets", -1),
            expires_at=expires_at,
            issued_at=activation_time, 
            signature=request.license_token,
            machine_fingerprint=local_fingerprint,
            consumed=True,
            consumed_at=activation_time,
            activation_hash=activation_hash
        )
        db.add(db_license)
        db.commit()
        db.refresh(db_license)
        
        # Write to local state file for anti-rollback protection
        update_state_file(license_id, local_fingerprint, activation_time)
        
    # Create or update activation record
    activation = db.query(LicenseActivation).filter(
        LicenseActivation.license_id == db_license.id,
        LicenseActivation.device_id == request.device_id
    ).first()
    
    if not activation:
        activation = LicenseActivation(
            license_id=db_license.id,
            device_id=request.device_id
        )
        db.add(activation)
    else:
        activation.last_ping = datetime.utcnow()
        activation.is_active = True
        
    # Create audit log
    db.add(AuditLog(
        action="OFFLINE_ACTIVATION",
        license_key=license_key,
        device_id=request.device_id,
        details="Offline license activation successful."
    ))
    db.commit()
    
    return {"message": "License activated successfully offline.", "license_id": db_license.id}

@router.post("/activate/online")
def activate_online(request: OnlineActivationRequest, db: Session = Depends(get_db)):
    """
    Activates a license online by contacting the central license server.
    """
    # In a real scenario, this would make an HTTP request to the GovernExa License Server
    # central_server_url = "https://license.governexa.com/api/v1/licenses/fetch"
    # response = requests.post(central_server_url, json={"license_key": request.license_key, "device_id": request.device_id})
    # if response.status_code != 200:
    #     raise HTTPException(...)
    # token = response.json().get("license_token")
    # return activate_offline(LicenseActivationRequest(license_token=token, device_id=request.device_id), db)
    
    return {
        "message": "Online activation requires internet connectivity and communicates with the central server.", 
        "status": "simulated"
    }

@router.get("/status")
def get_license_status(current_license: License = Depends(verify_license)):
    """
    Returns the current active license status. Protected by verify_license dependency.
    """
    return {
        "status": "active",
        "license_key": current_license.license_key,
        "customer": current_license.customer_name,
        "tier": current_license.tier,
        "issued_at": current_license.issued_at,
        "expires_at": current_license.expires_at,
        "features": current_license.features
    }

@router.get("/fingerprint")
def get_fingerprint():
    """Returns the stable machine fingerprint for binding licenses."""
    from licensing.system_fingerprint import get_machine_fingerprint
    return {"machine_fingerprint": get_machine_fingerprint()}

@router.delete("/flush")
def flush_licenses(db: Session = Depends(get_db)):
    """
    TEMPORARY: Flushes all licenses from the database for testing purposes.
    """
    db.query(LicenseActivation).delete()
    db.query(AuditLog).delete()
    db.query(RevokedLicense).delete()
    db.query(License).delete()
    db.commit()
    return {"message": "All license data has been flushed from the database."}
