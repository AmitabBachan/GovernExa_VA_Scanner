from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
import base64

from api.deps import get_db
from models.assets import CredentialStore
from api.routers.users import require_role

router = APIRouter()

class CredentialCreate(BaseModel):
    name: str
    auth_type: str # ssh, winrm
    username: str = None
    password: str = None
    private_key: str = None

class CredentialResponse(BaseModel):
    id: int
    name: str
    auth_type: str
    username: str = None
    
    class Config:
        from_attributes = True

@router.get("/", response_model=List[CredentialResponse])
def list_credentials(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("viewer"))
):
    """List all saved credentials (without secrets)."""
    return db.query(CredentialStore).all()

@router.post("/", response_model=CredentialResponse)
def create_credential(
    cred: CredentialCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Save a new credential (admin only)."""
    existing = db.query(CredentialStore).filter(CredentialStore.name == cred.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Credential with this name already exists")
    
    new_cred = CredentialStore(
        name=cred.name,
        auth_type=cred.auth_type,
        username=cred.username,
        encrypted_password=cred.password, # In a real app, encrypt this before saving
        private_key=cred.private_key
    )
    db.add(new_cred)
    db.commit()
    db.refresh(new_cred)
    return new_cred

@router.delete("/{cred_id}")
def delete_credential(
    cred_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Delete a credential (admin only)."""
    cred = db.query(CredentialStore).filter(CredentialStore.id == cred_id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    db.delete(cred)
    db.commit()
    return {"status": "deleted"}
