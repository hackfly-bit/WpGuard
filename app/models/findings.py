"""
Data models for findings and reports
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from enum import Enum

class FindingType(str, Enum):
    """Types of findings"""
    NEW_FILE = "new_file"
    CHANGED_FILE = "changed_file"
    DELETED_FILE = "deleted_file"
    SUSPICIOUS_CODE = "suspicious_code"
    MALWARE_SIGNATURE = "malware_signature"

class RiskLevel(str, Enum):
    """Risk levels for findings"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Finding(BaseModel):
    """Individual finding from scan"""
    
    file_path: str
    finding_type: FindingType
    risk_level: RiskLevel
    description: str
    
    # For code analysis findings
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    pattern_matched: Optional[str] = None
    
    # For file integrity findings
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_modified: Optional[datetime] = None
    new_modified: Optional[datetime] = None
    
    # Additional metadata
    confidence: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None

class ScanSummary(BaseModel):
    """Summary of scan results"""
    
    scan_id: str
    scan_type: str
    status: str
    
    # File counts
    total_files_scanned: int
    new_files: int
    changed_files: int
    deleted_files: int
    suspicious_files: int
    
    # Risk assessment
    critical_findings: int
    high_risk_findings: int
    medium_risk_findings: int
    low_risk_findings: int
    
    # Timing
    scan_duration: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

class ScanReport(BaseModel):
    """Complete scan report"""
    
    summary: ScanSummary
    findings: List[Finding]
    
    # WordPress-specific information
    wp_version: Optional[str] = None
    wp_plugins: Optional[List[str]] = None
    wp_themes: Optional[List[str]] = None
    
    # Recommendations
    recommendations: Optional[List[str]] = None

class UploadRequest(BaseModel):
    """Request model for file upload"""
    filename: str
    scan_name: Optional[str] = None

class FTPRequest(BaseModel):
    """Request model for FTP scan"""
    host: str
    port: int = 21
    username: str
    password: str
    remote_path: str = "/"
    scan_name: Optional[str] = None
    use_sftp: bool = False

class ScanRequest(BaseModel):
    """Request model for initiating scan"""
    scan_id: str
    include_malware_scan: bool = True
    include_integrity_check: bool = True
