from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from db.session import SessionLocal
from licensing.models import License, RevokedLicense

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_license(db: Session = Depends(get_db)):
    """
    FastAPI dependency to check if the current active license is valid.
    Blocks scans and other restricted endpoints if expired or revoked.
    """
    from licensing.state_manager import verify_state
    
    # 1. Look for the most recently issued active license
    active_license = db.query(License).order_by(License.issued_at.desc()).first()
    
    if not active_license:
        # If DB says no license, verify the state file agrees (anti-rollback)
        if not verify_state(None):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="License Validation Failed: System tampering detected. Activation rejected."
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active license found. Please activate your product."
        )
        
    # Verify DB against state file
    if not verify_state(active_license.license_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License Validation Failed: System tampering detected. Activation rejected."
        )
    
    # Check if the license has been revoked
    is_revoked = db.query(RevokedLicense).filter(RevokedLicense.license_key == active_license.license_key).first()
    if is_revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"License has been revoked: {is_revoked.reason}"
        )
        
    # Check expiration date
    if active_license.expires_at and datetime.utcnow() > active_license.expires_at:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License has expired."
        )
        
    return active_license
