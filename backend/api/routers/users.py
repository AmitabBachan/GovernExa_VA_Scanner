from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
import bcrypt

from api.deps import get_db
from auth.rbac import require_role
from models.users import User, Role

router = APIRouter(prefix="/users", tags=["Users"])

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    email: str
    password: str
    role_name: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role_name: Optional[str] = None
    password: Optional[str] = None

@router.get("/", response_model=List[UserResponse])
def get_users(
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    result = []
    for u in users:
        role_name = "Unknown"
        if u.role:
            role_name = u.role.name
        elif u.role_id:
            role = db.query(Role).filter(Role.id == u.role_id).first()
            if role:
                role_name = role.name
        
        result.append(UserResponse(
            id=u.id,
            email=u.email,
            role=role_name,
            is_active=u.is_active
        ))
    return result

@router.post("/", response_model=UserResponse)
def create_user(
    user_in: UserCreate,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    role = db.query(Role).filter(Role.name == user_in.role_name).first()
    if not role:
        # Create role if it doesn't exist
        role = Role(name=user_in.role_name)
        db.add(role)
        db.commit()
        db.refresh(role)
        
    hashed_pw = bcrypt.hashpw(user_in.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    new_user = User(
        email=user_in.email,
        hashed_password=hashed_pw,
        role_id=role.id,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        role=role.name,
        is_active=new_user.is_active
    )

@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_in: UserUpdate,
    current_user: dict = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user_in.email:
        existing = db.query(User).filter(User.email == user_in.email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        user.email = user_in.email
        
    if user_in.role_name:
        role = db.query(Role).filter(Role.name == user_in.role_name).first()
        if not role:
            role = Role(name=user_in.role_name)
            db.add(role)
            db.commit()
            db.refresh(role)
        user.role_id = role.id
        
    if user_in.password:
        hashed_pw = bcrypt.hashpw(user_in.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.hashed_password = hashed_pw
        
    db.commit()
    db.refresh(user)
    
    role_name = "Unknown"
    role = db.query(Role).filter(Role.id == user.role_id).first()
    if role:
        role_name = role.name
        
    return UserResponse(
        id=user.id,
        email=user.email,
        role=role_name,
        is_active=user.is_active
    )
