from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class RiskScoringResult(Base):
    """Stores findings for a specific risk scoring/severity classification scan."""
    __tablename__ = "risk_scoring_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    
    vulnerability_id = Column(String, nullable=False) # e.g. CVE-2021-44228
    description = Column(String, nullable=True)
    
    base_severity = Column(String, nullable=True)
    base_score = Column(Float, nullable=True)
    
    environmental_factors = Column(JSON, nullable=True) # {"internet_exposure": bool, "business_criticality": str}
    
    adjusted_score = Column(Float, nullable=True)
    final_severity = Column(String, nullable=False)
    
    calculated_at = Column(DateTime, default=datetime.now)

    scan_job = relationship("ScanJob")
