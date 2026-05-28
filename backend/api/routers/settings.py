from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from pydantic import BaseModel

from api.deps import get_db
from auth.rbac import require_role
from models.settings import SystemSetting

router = APIRouter(prefix="/settings", tags=["settings"])

class SettingsUpdate(BaseModel):
    settings: Dict[str, str]

@router.get("/")
def get_settings(
    current_user: dict = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    settings = db.query(SystemSetting).all()
    return {s.key: s.value for s in settings}

@router.put("/")
def update_settings(
    update_data: SettingsUpdate,
    current_user: dict = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    for key, value in update_data.settings.items():
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if setting:
            setting.value = value
        else:
            new_setting = SystemSetting(key=key, value=value)
            db.add(new_setting)
    db.commit()
    return {"message": "Settings updated successfully"}
