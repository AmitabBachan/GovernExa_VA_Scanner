from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class ValidationResult(Base):
    """Stores the verification results for discovered vulnerabilities."""
    __tablename__ = "validation_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    vulnerability_id = Column(String, nullable=False) # e.g. CVE ID or MISC ID
    
    is_confirmed = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    verification_method = Column(String, nullable=True) # e.g. "SSL Handshake", "Version Match"
    proof_of_concept = Column(Text, nullable=True)
    
    discovered_at = Column(DateTime, default=datetime.now)

    scan_job = relationship("ScanJob")
