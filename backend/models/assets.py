from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    status = Column(String, default="up")
    last_seen = Column(DateTime, default=datetime.now)
    
    software = relationship("InstalledSoftware", back_populates="device", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="device", cascade="all, delete-orphan")

class InstalledSoftware(Base):
    __tablename__ = "installed_software"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    cpe = Column(String, nullable=True)
    
    device = relationship("Device", back_populates="software")

class CredentialStore(Base):
    __tablename__ = "credentials_store"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    auth_type = Column(String, nullable=False) # ssh, winrm, snmp
    username = Column(String, nullable=True)
    encrypted_password = Column(Text, nullable=True)
    private_key = Column(Text, nullable=True)
