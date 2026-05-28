from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from datetime import datetime
from .base import Base

class PortScanResult(Base):
    __tablename__ = "port_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    state = Column(String, nullable=True)
    service = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)
    extrainfo = Column(String, nullable=True)
    cpe = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    scan_method = Column(String, nullable=True)
    risk = Column(String, nullable=True)
    reason = Column(String, nullable=True)
    scripts = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.now)

class PortScanSummary(Base):
    __tablename__ = "port_scan_summaries"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_family = Column(String, nullable=True)
    os_accuracy = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    total_open_ports = Column(Integer, default=0)
    tcp_open = Column(Integer, default=0)
    udp_open = Column(Integer, default=0)
    critical_ports = Column(Integer, default=0)
    high_risk_ports = Column(Integer, default=0)
    overall_risk = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.now)
