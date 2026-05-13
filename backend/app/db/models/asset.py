"""
Asset database model — core OT asset record.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Numeric, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, INET, MACADDR
from app.db.base import Base


class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(INET, nullable=True, index=True)
    mac_address = Column(MACADDR, nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    model = Column(String(255), nullable=True)
    firmware_version = Column(String(100), nullable=True)
    serial_number = Column(String(100), nullable=True)
    device_type = Column(String(100), nullable=True)
    asset_role = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)
    site = Column(String(100), nullable=True, index=True)
    area = Column(String(100), nullable=True)
    vlan_id = Column(Integer, nullable=True)
    subnet = Column(String(50), nullable=True)
    operating_system = Column(String(255), nullable=True)
    first_seen = Column(DateTime, nullable=True, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True, default=datetime.utcnow)
    criticality = Column(String(20), nullable=True, default="Unknown")
    risk_score = Column(Numeric(5, 2), nullable=True)
    obsolescence_status = Column(String(50), nullable=True, default="Unknown")
    data_source = Column(String(100), nullable=True)
    confidence_level = Column(String(20), nullable=True, default="Low")
    validation_status = Column(String(20), nullable=True, default="Unvalidated")
    owner = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Asset {self.asset_id} | {self.ip_address} | {self.device_type}>"
