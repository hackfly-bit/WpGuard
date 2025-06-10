"""
WPGuard Advanced Security API
API endpoints for Phase 9: Advanced Security Features
"""
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field
import os
import json
import logging

from app.scanner.ml_detection import MLMalwareDetector, WordPressSpecificDetector
from app.scanner.advanced_reporting import AdvancedReportGenerator
from app.core.database import get_db_session

router = APIRouter()
logger = logging.getLogger(__name__)

# Request/Response Models
class AdvancedScanRequest(BaseModel):
    """Advanced scan request with ML options"""
    scan_path: str = Field(..., description="Path to scan")
    scan_name: Optional[str] = Field(None, description="Custom scan name")
    enable_ml_detection: bool = Field(True, description="Enable ML-enhanced detection")
    enable_wp_specific: bool = Field(True, description="Enable WordPress-specific checks")
    max_files: int = Field(1000, description="Maximum files to scan")
    include_compliance: bool = Field(True, description="Include compliance analysis")
    generate_recommendations: bool = Field(True, description="Generate security recommendations")

class SecurityMetricsResponse(BaseModel):
    """Security metrics response"""
    overall_risk_score: float
    security_posture: str
    threat_distribution: Dict
    file_type_analysis: Dict
    recommendations_count: int
    last_scan_date: Optional[str]

class ComplianceReportResponse(BaseModel):
    """Compliance report response"""
    wordpress_compliance: Dict
    web_security_compliance: Dict
    file_security_compliance: Dict
    overall_score: int
    recommendations: List[str]

class RecommendationResponse(BaseModel):
    """Security recommendation response"""
    priority: str
    category: str
    title: str
    description: str
    impact: str
    effort: str
    steps: List[str]

class AdvancedScanResponse(BaseModel):
    """Advanced scan response"""
    scan_id: str
    status: str
    scan_type: str = "advanced_ml"
    started_at: datetime
    completed_at: Optional[datetime]
    results: Optional[Dict]
    error: Optional[str]

# Advanced Security Endpoints
@router.post("/security/scan/advanced", response_model=AdvancedScanResponse)
async def start_advanced_scan(
    request: AdvancedScanRequest,
    background_tasks: BackgroundTasks
):
    """Start an advanced ML-enhanced security scan"""
    
    if not os.path.exists(request.scan_path):
        raise HTTPException(status_code=400, detail="Scan path does not exist")
    
    # Generate scan ID
    scan_id = f"advanced-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    # Store scan record in database
    scan_record = {
        'scan_id': scan_id,
        'scan_type': 'advanced_ml',
        'status': 'running',
        'scan_path': request.scan_path,
        'scan_name': request.scan_name or f"Advanced Scan {scan_id}",
        'started_at': datetime.utcnow(),
        'config': request.dict()
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_advanced_scan,
        scan_id,
        request.scan_path,
        request.dict()
    )
    
    return AdvancedScanResponse(
        scan_id=scan_id,
        status="running",
        started_at=scan_record['started_at']
    )

@router.get("/security/scan/advanced/{scan_id}", response_model=AdvancedScanResponse)
async def get_advanced_scan_status(scan_id: str):
    """Get the status of an advanced scan"""
    
    # In a real implementation, this would query the database
    # For now, return a mock response
    return AdvancedScanResponse(
        scan_id=scan_id,
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        results={"message": "Scan completed successfully"}
    )

@router.get("/security/metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics():
    """Get overall security metrics and dashboard data"""
    
    # This would typically aggregate data from recent scans
    # For demonstration, return sample metrics
    return SecurityMetricsResponse(
        overall_risk_score=25.5,
        security_posture="Good",
        threat_distribution={
            "critical": 2,
            "high": 5,
            "medium": 12,
            "low": 8,
            "clean": 173
        },
        file_type_analysis={
            ".php": {"total": 145, "threats": 18, "avg_risk": 22.3},
            ".js": {"total": 42, "threats": 5, "avg_risk": 15.1},
            ".html": {"total": 13, "threats": 1, "avg_risk": 8.2}
        },
        recommendations_count=8,
        last_scan_date=datetime.utcnow().isoformat()
    )

@router.get("/security/compliance", response_model=ComplianceReportResponse)
async def get_compliance_report(scan_id: Optional[str] = None):
    """Get compliance report for the latest or specified scan"""
    
    # Sample compliance data
    return ComplianceReportResponse(
        wordpress_compliance={
            "score": 85,
            "issues": ["PHP files found in uploads directory"],
            "compliant": False
        },
        web_security_compliance={
            "score": 92,
            "issues": [],
            "compliant": True
        },
        file_security_compliance={
            "score": 78,
            "issues": ["Obfuscated files detected"],
            "compliant": False
        },
        overall_score=85,
        recommendations=[
            "Remove PHP execution from uploads directory",
            "Investigate obfuscated files",
            "Enable automatic security updates",
            "Implement file integrity monitoring"
        ]
    )

@router.get("/security/recommendations", response_model=List[RecommendationResponse])
async def get_security_recommendations(
    priority: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 10
):
    """Get prioritized security recommendations"""
    
    # Sample recommendations
    recommendations = [
        RecommendationResponse(
            priority="critical",
            category="malware",
            title="Remove Confirmed Malware",
            description="2 files match known malware signatures and must be removed immediately",
            impact="System compromise, data theft",
            effort="high",
            steps=[
                "Immediately backup clean files",
                "Quarantine infected files",
                "Run full system scan",
                "Change all passwords",
                "Update security measures"
            ]
        ),
        RecommendationResponse(
            priority="high",
            category="vulnerability",
            title="Update WordPress Core",
            description="WordPress core is outdated and contains known vulnerabilities",
            impact="Security vulnerabilities, potential exploitation",
            effort="medium",
            steps=[
                "Backup current installation",
                "Update WordPress to latest version",
                "Test functionality after update",
                "Update themes and plugins",
                "Monitor for issues"
            ]
        ),
        RecommendationResponse(
            priority="medium",
            category="configuration",
            title="Secure File Permissions",
            description="Some files have overly permissive access settings",
            impact="Unauthorized file access, modification",
            effort="low",
            steps=[
                "Review file permissions",
                "Set appropriate permissions (644 for files, 755 for directories)",
                "Remove write permissions from sensitive files",
                "Implement permission monitoring"
            ]
        )
    ]
    
    # Filter by priority and category if specified
    filtered = recommendations
    if priority:
        filtered = [r for r in filtered if r.priority == priority]
    if category:
        filtered = [r for r in filtered if r.category == category]
    
    return filtered[:limit]

@router.get("/security/threats/top")
async def get_top_threats():
    """Get the top threats found in recent scans"""
    
    return {
        "top_threats": [
            {
                "threat_type": "known_malware",
                "count": 3,
                "severity": "critical",
                "description": "Files matching known malware signatures",
                "files": [
                    "/wp-content/uploads/suspicious.php",
                    "/wp-includes/malicious.php",
                    "/wp-content/themes/infected/backdoor.php"
                ]
            },
            {
                "threat_type": "obfuscated_code",
                "count": 8,
                "severity": "high",
                "description": "Files containing obfuscated or encoded content",
                "files": [
                    "/wp-content/plugins/suspicious/encoded.php",
                    "/wp-content/themes/theme/obfuscated.js"
                ]
            },
            {
                "threat_type": "suspicious_patterns",
                "count": 15,
                "severity": "medium",
                "description": "Files with suspicious code patterns",
                "files": [
                    "/wp-content/uploads/form.php",
                    "/wp-content/cache/temp.php"
                ]
            }
        ],
        "summary": {
            "total_unique_threats": 26,
            "critical_threats": 3,
            "high_threats": 8,
            "medium_threats": 15
        }
    }

@router.get("/security/trends")
async def get_security_trends():
    """Get security trends and historical data"""
    
    return {
        "threat_trends": {
            "last_30_days": [
                {"date": "2025-06-01", "threats": 5},
                {"date": "2025-06-05", "threats": 8},
                {"date": "2025-06-10", "threats": 12},
            ],
            "trend_direction": "increasing",
            "threat_velocity": 2.3
        },
        "file_growth": {
            "total_files_scanned": [1200, 1250, 1300, 1350],
            "weekly_change": 4.2
        },
        "security_score_history": [
            {"date": "2025-05-01", "score": 78},
            {"date": "2025-05-15", "score": 82},
            {"date": "2025-06-01", "score": 85},
            {"date": "2025-06-10", "score": 88}
        ]
    }

@router.post("/security/baseline/create")
async def create_security_baseline(scan_id: str):
    """Create a security baseline from a clean scan"""
    
    return {
        "baseline_id": f"baseline-{datetime.utcnow().strftime('%Y%m%d')}",
        "created_from_scan": scan_id,
        "status": "created",
        "files_included": 1250,
        "created_at": datetime.utcnow().isoformat()
    }

@router.get("/security/baseline/compare/{baseline_id}")
async def compare_with_baseline(baseline_id: str, current_scan_id: str):
    """Compare current scan with security baseline"""
    
    return {
        "baseline_id": baseline_id,
        "current_scan_id": current_scan_id,
        "comparison_date": datetime.utcnow().isoformat(),
        "changes": {
            "new_files": 15,
            "modified_files": 8,
            "deleted_files": 3,
            "new_threats": 5,
            "resolved_threats": 2
        },
        "risk_change": {
            "baseline_score": 82,
            "current_score": 85,
            "improvement": 3
        },
        "detailed_changes": [
            {
                "file": "/wp-content/uploads/new-file.php",
                "change_type": "new_file",
                "threat_level": "high",
                "action_needed": "investigate"
            }
        ]
    }

# Background task functions
async def run_advanced_scan(scan_id: str, scan_path: str, config: Dict):
    """Run advanced ML-enhanced scan in background"""
    
    try:
        logger.info(f"Starting advanced scan {scan_id} for path: {scan_path}")
        
        # Initialize detectors
        ml_detector = MLMalwareDetector()
        wp_detector = WordPressSpecificDetector()
        report_generator = AdvancedReportGenerator()
        
        # Run ML-enhanced scan
        if config.get('enable_ml_detection', True):
            ml_results = ml_detector.scan_directory(
                scan_path, 
                max_files=config.get('max_files', 1000)
            )
        else:
            ml_results = {"file_results": [], "summary": {}}
        
        # Run WordPress-specific checks
        if config.get('enable_wp_specific', True):
            wp_findings = wp_detector.check_wp_integrity(scan_path)
            # Integrate WP findings into ML results
            # (Implementation details would go here)
        
        # Generate advanced reports
        if config.get('include_compliance', True) or config.get('generate_recommendations', True):
            advanced_report = report_generator.generate_full_report(ml_results)
        else:
            advanced_report = ml_results
        
        # Save results to database
        # (Database storage implementation would go here)
        
        logger.info(f"Advanced scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Advanced scan {scan_id} failed: {e}")
        # Update scan status to failed in database
