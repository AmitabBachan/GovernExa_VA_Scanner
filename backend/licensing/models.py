from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from models.base import Base

class License(Base):
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(String, unique=True, index=True) # UUID
    license_key = Column(String, unique=True, index=True)
    customer_name = Column(String)
    tier = Column(String) # e.g. Free, Pro, Enterprise
    features = Column(String) # JSON or comma-separated string
    max_scans = Column(Integer, default=-1) # -1 for unlimited
    max_assets = Column(Integer, default=-1)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    signature = Column(Text)
    
    # Anti-replay / Anti-rollback columns
    machine_fingerprint = Column(String)
    consumed = Column(Boolean, default=False)
    consumed_at = Column(DateTime)
    activation_hash = Column(Text)
    
    activations = relationship("LicenseActivation", back_populates="license")

class LicenseActivation(Base):
    __tablename__ = "license_activations"
    
    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"))
    device_id = Column(String, index=True)
    activated_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_ping = Column(DateTime, default=datetime.utcnow)
    
    license = relationship("License", back_populates="activations")

class RevokedLicense(Base):
    __tablename__ = "revoked_licenses"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String)

class AuditLog(Base):
    __tablename__ = "license_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String) # e.g. ACTIVATION, REVOCATION, EXPIRED_ATTEMPT
    license_key = Column(String)
    device_id = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(Text)
