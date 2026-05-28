from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class EnumerationResult(Base):
    """Stores deep enumeration results for a target host."""
    __tablename__ = "enumeration_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    
    # SMB Enumeration
    smb_shares = Column(JSON, nullable=True)     # List of dicts: {"name": "", "path": "", "comment": ""}
    smb_users = Column(JSON, nullable=True)      # List of strings or dicts
    
    # SNMP Enumeration
    snmp_sysdescr = Column(Text, nullable=True)
    snmp_interfaces = Column(JSON, nullable=True)
    
    # DNS Enumeration
    dns_records = Column(JSON, nullable=True)    # A, AAAA, MX, NS records found
    
    # SSL/TLS Enumeration
    ssl_certs = Column(JSON, nullable=True)      # Cert details (subject, issuer, expiry)
    
    # OS/General
    os_info = Column(String, nullable=True)
    
    discovered_at = Column(DateTime, default=datetime.now)

    scan_job = relationship("ScanJob")
