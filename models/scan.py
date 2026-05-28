from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    
    id = Column(String, primary_key=True, index=True) # Celery task ID
    target = Column(String, nullable=False) # IP, CIDR, or hostname
    status = Column(String, default="PENDING")
    scan_type = Column(String, nullable=False) # "discovery", "fingerprint", "auth", "full"
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    results = relationship("ScanResult", back_populates="scan_job", cascade="all, delete")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    
    scan_job = relationship("ScanJob", back_populates="results")
    device = relationship("Device", back_populates="scan_results")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_result", cascade="all, delete")
