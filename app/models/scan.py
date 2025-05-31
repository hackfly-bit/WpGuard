"""
Database models for scan data using SQLAlchemy
"""
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum as SQLEnum, JSON
from enum import Enum
from app.core.database import Base

class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanType(str, Enum):
    """Scan type enumeration"""
    UPLOAD = "upload"
    FTP = "ftp"
    SCHEDULED = "scheduled"

class ScanRecord(Base):
    """Database model for scan records"""
    
    __tablename__ = "scan_records"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    
    # Source information
    source_path = Column(String)
    source_size = Column(Integer)
    
    # FTP information (if applicable)
    ftp_host = Column(String)
    ftp_port = Column(Integer)
    ftp_username = Column(String)
    ftp_remote_path = Column(String)
    
    # Scan results
    total_files = Column(Integer)
    changed_files = Column(Integer)
    new_files = Column(Integer)
    deleted_files = Column(Integer)
    suspicious_files = Column(Integer)
      # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Additional scan metadata
    scan_metadata = Column(JSON)
    error_message = Column(Text)
