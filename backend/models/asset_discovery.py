from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from datetime import datetime
from .base import Base

class AssetDiscoveryResult(Base):
    __tablename__ = "asset_discovery_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_family = Column(String, nullable=True)
    os_accuracy = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    role = Column(String, nullable=True)
    open_ports = Column(JSON, nullable=True)
    web_apps = Column(JSON, nullable=True)
    containers = Column(JSON, nullable=True)
    cloud_instance = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.now)
