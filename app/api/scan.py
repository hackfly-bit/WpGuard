"""
Scan execution API endpoints
"""
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_session
from app.models.scan import ScanRecord, ScanStatus
from app.models.findings import ScanRequest, ScanSummary, ScanReport
from app.scanner.integrity import check_file_integrity
from app.scanner.malware import scan_for_malware
from app.scanner.baseline import load_baseline_snapshot

router = APIRouter()

@router.post("/scan/{scan_id}")
async def start_scan(
    scan_id: str,
    scan_request: Optional[ScanRequest] = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_session)
):
    """
    Start integrity and malware scan for uploaded/FTP files
    """
    
    # Get scan record
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_record.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Scan already running")
    
    if scan_record.status == ScanStatus.COMPLETED:
        return JSONResponse(
            content={
                "scan_id": scan_id,
                "status": "already_completed",
                "message": "Scan already completed. Use GET /report/{scan_id} to view results"
            }
        )
    
    # Find scan directory and WordPress root
    scan_dir = Path(settings.TEMP_DIR) / scan_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail="Scan files not found")
    
    # Find WordPress root
    wp_root = await _find_wordpress_root(scan_dir)
    if not wp_root:
        raise HTTPException(status_code=400, detail="WordPress installation not found")
    
    # Update scan status
    scan_record.status = ScanStatus.RUNNING
    scan_record.started_at = datetime.utcnow()
    db.commit()
    
    # Start background scan
    background_tasks.add_task(
        _execute_scan,
        scan_id,
        wp_root,
        scan_request.include_integrity_check if scan_request else True,
        scan_request.include_malware_scan if scan_request else True
    )
    
    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "started",
            "message": "Scan started in background",
            "check_status": f"GET /api/v1/scan/{scan_id}/status"
        }
    )

async def _execute_scan(
    scan_id: str,
    wp_root: Path,
    include_integrity: bool,
    include_malware: bool
):
    """Execute the actual scan in background"""
      # Get database session
    from app.core.database import SessionLocal
    with SessionLocal() as db:
        scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        try:
            all_findings = []
            wp_info = {}
            integrity_summary = {}
            malware_summary = {}
            
            # Run integrity check
            if include_integrity:
                try:
                    integrity_findings, integrity_summary = await check_file_integrity(scan_id, wp_root)
                    all_findings.extend(integrity_findings)
                except Exception as e:
                    print(f"Integrity check failed: {e}")
                    integrity_summary = {"error": str(e)}
            
            # Run malware scan
            if include_malware:
                try:
                    malware_findings, malware_summary, wp_info = await scan_for_malware(wp_root)
                    all_findings.extend(malware_findings)
                except Exception as e:
                    print(f"Malware scan failed: {e}")
                    malware_summary = {"error": str(e)}
            
            # Generate scan summary
            summary = _generate_scan_summary(scan_record, all_findings, integrity_summary, malware_summary)
            
            # Create scan report
            report = ScanReport(
                summary=summary,
                findings=all_findings,
                wp_version=wp_info.get("version"),
                wp_plugins=wp_info.get("plugins", []),
                wp_themes=wp_info.get("themes", []),
                recommendations=_generate_recommendations(all_findings)
            )
            
            # Save report
            await _save_scan_report(scan_id, report)
            
            # Update scan record
            scan_record.status = ScanStatus.COMPLETED
            scan_record.completed_at = datetime.utcnow()
            scan_record.changed_files = integrity_summary.get("changed_files", 0)
            scan_record.new_files = integrity_summary.get("new_files", 0)
            scan_record.deleted_files = integrity_summary.get("deleted_files", 0)
            scan_record.suspicious_files = malware_summary.get("total_suspicious_files", 0)
            
            db.commit()
            
        except Exception as e:
            # Mark scan as failed
            scan_record.status = ScanStatus.FAILED
            scan_record.error_message = str(e)
            scan_record.completed_at = datetime.utcnow()
            db.commit()
            print(f"Scan {scan_id} failed: {e}")

def _generate_scan_summary(scan_record, findings, integrity_summary, malware_summary) -> ScanSummary:
    """Generate scan summary from results"""
    
    # Count findings by risk level
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    suspicious_files = set()
    
    for finding in findings:
        risk_counts[finding.risk_level.value] += 1
        if finding.finding_type.value == "suspicious_code":
            suspicious_files.add(finding.file_path)
    
    # Calculate scan duration
    duration = None
    if scan_record.started_at and scan_record.completed_at:
        duration = (scan_record.completed_at - scan_record.started_at).total_seconds()
    elif scan_record.started_at:
        duration = (datetime.utcnow() - scan_record.started_at).total_seconds()
    
    return ScanSummary(
        scan_id=scan_record.scan_id,
        scan_type=scan_record.scan_type.value,
        status=scan_record.status.value,
        total_files_scanned=scan_record.total_files or 0,
        new_files=integrity_summary.get("new_files", 0),
        changed_files=integrity_summary.get("changed_files", 0),
        deleted_files=integrity_summary.get("deleted_files", 0),
        suspicious_files=len(suspicious_files),
        critical_findings=risk_counts["critical"],
        high_risk_findings=risk_counts["high"],
        medium_risk_findings=risk_counts["medium"],
        low_risk_findings=risk_counts["low"],
        scan_duration=duration,
        created_at=scan_record.created_at,
        completed_at=scan_record.completed_at
    )

def _generate_recommendations(findings) -> list:
    """Generate security recommendations based on findings"""
    recommendations = []
    
    # Count findings by type and risk
    critical_count = sum(1 for f in findings if f.risk_level.value == "critical")
    high_count = sum(1 for f in findings if f.risk_level.value == "high")
    suspicious_count = sum(1 for f in findings if f.finding_type.value == "suspicious_code")
    
    if critical_count > 0:
        recommendations.append("⚠️ CRITICAL: Immediate action required - critical security issues detected")
        recommendations.append("🔒 Isolate the WordPress site immediately and review all critical findings")
    
    if high_count > 0:
        recommendations.append("🔴 HIGH PRIORITY: Review and address high-risk findings as soon as possible")
    
    if suspicious_count > 0:
        recommendations.append("🔍 Review all suspicious code patterns - they may indicate malware or vulnerabilities")
        recommendations.append("🧹 Consider cleaning or replacing affected files from clean backups")
    
    # General WordPress security recommendations
    recommendations.extend([
        "🔄 Keep WordPress core, themes, and plugins updated to latest versions",
        "🔐 Use strong passwords and enable two-factor authentication",
        "🛡️ Install a WordPress security plugin for ongoing monitoring",
        "📋 Regularly backup your WordPress site",
        "🚫 Remove unused themes and plugins",
        "📁 Set proper file permissions (644 for files, 755 for directories)"
    ])
    
    return recommendations

async def _save_scan_report(scan_id: str, report: ScanReport):
    """Save scan report to JSON file"""
    report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
    
    # Convert to JSON-serializable format
    report_dict = report.dict()
    
    # Convert datetime objects to ISO format
    if report_dict["summary"]["created_at"]:
        report_dict["summary"]["created_at"] = report_dict["summary"]["created_at"].isoformat()
    if report_dict["summary"]["completed_at"]:
        report_dict["summary"]["completed_at"] = report_dict["summary"]["completed_at"].isoformat()
    
    for finding in report_dict["findings"]:
        if finding.get("old_modified"):
            finding["old_modified"] = finding["old_modified"].isoformat()
        if finding.get("new_modified"):
            finding["new_modified"] = finding["new_modified"].isoformat()
    
    with open(report_path, 'w') as f:
        json.dump(report_dict, f, indent=2)

async def _find_wordpress_root(scan_dir: Path) -> Optional[Path]:
    """Find WordPress root directory"""
    # Check extracted directory first
    extracted_dir = scan_dir / "extracted"
    if extracted_dir.exists():
        return await _find_wp_in_dir(extracted_dir)
    
    # Check scan directory itself
    return await _find_wp_in_dir(scan_dir)

async def _find_wp_in_dir(directory: Path) -> Optional[Path]:
    """Find WordPress installation in given directory"""
    # Check if directory itself is WordPress root
    if (directory / "wp-config.php").exists() or (directory / "wp-includes").exists():
        return directory
    
    # Search in subdirectories
    for item in directory.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            if (item / "wp-config.php").exists() or (item / "wp-includes").exists():
                return item
    
    return None

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, db: Session = Depends(get_session)):
    """Get current status of scan"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    response = {
        "scan_id": scan_id,
        "status": scan_record.status.value,
        "scan_type": scan_record.scan_type.value,
        "created_at": scan_record.created_at,
        "started_at": scan_record.started_at,
        "completed_at": scan_record.completed_at
    }
    
    if scan_record.error_message:
        response["error"] = scan_record.error_message
    
    if scan_record.status == ScanStatus.COMPLETED:
        response.update({
            "total_files": scan_record.total_files,
            "changed_files": scan_record.changed_files,
            "new_files": scan_record.new_files,
            "deleted_files": scan_record.deleted_files,
            "suspicious_files": scan_record.suspicious_files
        })
    
    return response

@router.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str, db: Session = Depends(get_session)):
    """Cancel running scan or delete completed scan"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_record.status == ScanStatus.RUNNING:
        scan_record.status = ScanStatus.FAILED
        scan_record.error_message = "Cancelled by user"
        scan_record.completed_at = datetime.utcnow()
        db.commit()
        return {"message": f"Scan {scan_id} cancelled"}
    
    else:
        # Delete scan and all associated files
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
        
        db.delete(scan_record)
        db.commit()
        
        return {"message": f"Scan {scan_id} deleted successfully"}
