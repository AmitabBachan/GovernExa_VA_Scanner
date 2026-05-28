from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, nullable=False)
    mac_address = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    os_details = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    last_scanned_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    software = relationship("InstalledSoftware", back_populates="device", cascade="all, delete")
    scan_results = relationship("ScanResult", back_populates="device", cascade="all, delete")

class InstalledSoftware(Base):
    __tablename__ = "installed_software"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    install_date = Column(DateTime, nullable=True)
    cpe = Column(String, nullable=True)
    
    device = relationship("Device", back_populates="software")
