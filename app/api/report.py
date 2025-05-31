"""
Report and results API endpoints
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_session
from app.models.scan import ScanRecord, ScanStatus
from app.models.findings import ScanReport, ScanSummary

router = APIRouter()

@router.get("/report/{scan_id}")
async def get_scan_report(scan_id: str, db: Session = Depends(get_session)):
    """
    Get complete scan report with findings and recommendations
    """
    
    # Check if scan exists
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_record.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400, 
            detail=f"Scan not completed. Current status: {scan_record.status.value}"
        )
    
    # Load report from file
    report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Scan report not found")
    
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        return JSONResponse(content=report_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading report: {str(e)}")

@router.get("/summary/{scan_id}")
async def get_scan_summary(scan_id: str, db: Session = Depends(get_session)):
    """
    Get scan summary with key metrics
    """
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Calculate scan duration
    duration = None
    if scan_record.started_at and scan_record.completed_at:
        duration = (scan_record.completed_at - scan_record.started_at).total_seconds()
    elif scan_record.started_at:
        duration = (datetime.utcnow() - scan_record.started_at).total_seconds()

    # Ensure all fields are serializable (convert None to 0 or empty string)
    summary = {
        "scan_id": scan_id,
        "scan_type": getattr(scan_record.scan_type, 'value', str(scan_record.scan_type)),
        "status": getattr(scan_record.status, 'value', str(scan_record.status)),
        "created_at": scan_record.created_at.isoformat() if scan_record.created_at else None,
        "started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
        "completed_at": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
        "scan_duration": duration if duration is not None else 0,
        "total_files": scan_record.total_files if scan_record.total_files is not None else 0,
        "changed_files": scan_record.changed_files if scan_record.changed_files is not None else 0,
        "new_files": scan_record.new_files if scan_record.new_files is not None else 0,
        "deleted_files": scan_record.deleted_files if scan_record.deleted_files is not None else 0,
        "suspicious_files": scan_record.suspicious_files if scan_record.suspicious_files is not None else 0,
        "metadata": scan_record.scan_metadata or {}
    }

    if scan_record.error_message:
        summary["error"] = scan_record.error_message

    # Add risk assessment if scan is completed
    if getattr(scan_record.status, 'value', str(scan_record.status)) == "completed":
        try:
            report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
            if report_path.exists():
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                summary["risk_assessment"] = {
                    "critical_findings": report_data["summary"].get("critical_findings", 0),
                    "high_risk_findings": report_data["summary"].get("high_risk_findings", 0),
                    "medium_risk_findings": report_data["summary"].get("medium_risk_findings", 0),
                    "low_risk_findings": report_data["summary"].get("low_risk_findings", 0)
                }
                summary["overall_risk"] = _calculate_overall_risk(summary["risk_assessment"])
        except Exception as e:
            summary["risk_assessment_error"] = f"Could not load risk assessment: {e}"
    return summary

@router.get("/findings/{scan_id}")
async def get_scan_findings(
    scan_id: str,
    risk_level: Optional[str] = Query(None, description="Filter by risk level: critical, high, medium, low"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    limit: int = Query(100, ge=1, le=1000, description="Number of findings to return"),
    offset: int = Query(0, ge=0, description="Number of findings to skip"),
    db: Session = Depends(get_session)
):
    """
    Get scan findings with filtering and pagination
    """
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_record.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan not completed. Current status: {scan_record.status.value}"
        )
    
    # Load report
    report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Scan report not found")
    
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        findings = report_data["findings"]
        
        # Apply filters
        if risk_level:
            findings = [f for f in findings if f["risk_level"] == risk_level.lower()]
        
        if finding_type:
            findings = [f for f in findings if f["finding_type"] == finding_type.lower()]
        
        # Apply pagination
        total_findings = len(findings)
        paginated_findings = findings[offset:offset + limit]
        
        return {
            "scan_id": scan_id,
            "total_findings": total_findings,
            "returned_findings": len(paginated_findings),
            "offset": offset,
            "limit": limit,
            "findings": paginated_findings
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading findings: {str(e)}")

@router.get("/scans")
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_session)
):
    """
    List all scans with filtering and pagination
    """
    
    query = db.query(ScanRecord)
    
    # Apply filters
    if status:
        try:
            status_enum = ScanStatus(status.lower())
            query = query.filter(ScanRecord.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    
    if scan_type:
        query = query.filter(ScanRecord.scan_type == scan_type.upper())
    
    # Get total count
    total_scans = query.count()
    
    # Apply pagination and ordering
    scans = query.order_by(ScanRecord.created_at.desc()).offset(offset).limit(limit).all()
    
    # Format response
    scan_list = []
    for scan in scans:
        scan_data = {
            "scan_id": scan.scan_id,
            "scan_type": scan.scan_type.value,
            "status": scan.status.value,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
            "total_files": scan.total_files,
            "suspicious_files": scan.suspicious_files
        }
          # Add scan name if available
        if scan.scan_metadata and "scan_name" in scan.scan_metadata:
            scan_data["scan_name"] = scan.scan_metadata["scan_name"]
        
        scan_list.append(scan_data)
    
    return {
        "total_scans": total_scans,
        "returned_scans": len(scan_list),
        "offset": offset,
        "limit": limit,
        "scans": scan_list
    }

@router.get("/stats")
async def get_scan_statistics(db: Session = Depends(get_session)):
    """
    Get overall scanning statistics
    """
    
    # Count scans by status
    stats = {
        "total_scans": db.query(ScanRecord).count(),
        "completed_scans": db.query(ScanRecord).filter(ScanRecord.status == ScanStatus.COMPLETED).count(),
        "running_scans": db.query(ScanRecord).filter(ScanRecord.status == ScanStatus.RUNNING).count(),
        "failed_scans": db.query(ScanRecord).filter(ScanRecord.status == ScanStatus.FAILED).count(),
        "pending_scans": db.query(ScanRecord).filter(ScanRecord.status == ScanStatus.PENDING).count()
    }
    
    # Count by scan type
    stats["upload_scans"] = db.query(ScanRecord).filter(ScanRecord.scan_type == "UPLOAD").count()
    stats["ftp_scans"] = db.query(ScanRecord).filter(ScanRecord.scan_type == "FTP").count()
    
    # Get recent activity (last 24 hours)
    from datetime import timedelta
    last_24h = datetime.utcnow() - timedelta(hours=24)
    stats["recent_scans"] = db.query(ScanRecord).filter(ScanRecord.created_at >= last_24h).count()
    
    return stats

def _calculate_overall_risk(risk_assessment: dict) -> str:
    """Calculate overall risk level based on findings"""
    
    if risk_assessment["critical_findings"] > 0:
        return "critical"
    elif risk_assessment["high_risk_findings"] > 5:
        return "high"
    elif risk_assessment["high_risk_findings"] > 0 or risk_assessment["medium_risk_findings"] > 10:
        return "medium"
    elif risk_assessment["medium_risk_findings"] > 0 or risk_assessment["low_risk_findings"] > 0:
        return "low"
    else:
        return "clean"

@router.delete("/reports/{scan_id}")
async def delete_scan_report(scan_id: str, db: Session = Depends(get_session)):
    """Delete scan report and associated files"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Remove all associated files
    scan_dir = Path(settings.TEMP_DIR) / scan_id
    if scan_dir.exists():
        import shutil
        shutil.rmtree(scan_dir, ignore_errors=True)
    
    # Remove snapshot
    snapshot_path = Path(settings.SNAPSHOTS_DIR) / f"{scan_id}.json"
    if snapshot_path.exists():
        snapshot_path.unlink()
    
    # Remove report
    report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
    if report_path.exists():
        report_path.unlink()
    
    # Remove database record
    db.delete(scan_record)
    db.commit()
    
    return {"message": f"Scan {scan_id} and all associated data deleted successfully"}
