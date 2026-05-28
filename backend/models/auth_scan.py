from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class AuthScanFinding(Base):
    """Stores findings for a specific authenticated deep scan."""
    __tablename__ = "auth_scan_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    os_details = Column(String, nullable=True)
    
    # JSON Arrays
    packages = Column(JSON, nullable=True)  # [{"name": "", "version": "", "cpe": ""}]
    local_users = Column(JSON, nullable=True) # [{"username": "", "description": "", "active": bool}]
    patch_levels = Column(JSON, nullable=True) # Windows KB or Linux updates
    
    discovered_at = Column(DateTime, default=datetime.now)

    scan_job = relationship("ScanJob")
