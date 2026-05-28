from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from datetime import datetime
from .base import Base

class ServiceFingerprintResult(Base):
    __tablename__ = "service_fingerprint_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    service = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    extrainfo = Column(String, nullable=True)
    cpe = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    http_server = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.now)
