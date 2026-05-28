from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from .base import Base

class CveCatalog(Base):
    __tablename__ = "cve_catalog"

    cve_id = Column(String, primary_key=True, index=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    published_date = Column(String, nullable=True)
    json_data = Column(JSON, nullable=True)

class CpeCatalog(Base):
    __tablename__ = "cpe_catalog"

    id = Column(Integer, primary_key=True, index=True)
    cpe_string = Column(String, unique=True, index=True, nullable=False)
    vendor = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    cve_id = Column(String, ForeignKey("cve_catalog.cve_id"), nullable=False)
    risk_score = Column(Float, nullable=True)
    priority = Column(Integer, nullable=True)
    status = Column(String, default="Open", nullable=False)
    reason = Column(Text, nullable=True)
    
    scan_result = relationship("ScanResult", back_populates="vulnerabilities")
    cve = relationship("CveCatalog")
    remediations = relationship("RemediationLibrary", back_populates="vulnerability", cascade="all, delete-orphan")

class RemediationLibrary(Base):
    __tablename__ = "remediation_library"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    patch_version = Column(String, nullable=True)
    recommended_update = Column(Text, nullable=True)
    workaround = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    
    vulnerability = relationship("Vulnerability", back_populates="remediations")

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    rule_action = Column(String, nullable=False) # block, allow
    protocol = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    
    vulnerability = relationship("Vulnerability")
