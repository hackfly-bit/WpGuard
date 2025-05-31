"""
File upload API endpoints
"""
import os
import zipfile
import tarfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_session
from app.models.scan import ScanRecord, ScanType, ScanStatus
from app.models.findings import UploadRequest
from app.scanner.baseline import create_baseline_snapshot

router = APIRouter()

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    scan_name: Optional[str] = None,
    db: Session = Depends(get_session)
):
    """
    Upload WordPress site archive for scanning
    
    Accepts ZIP or TAR.GZ files containing WordPress installation
    """
    
    # Validate file type
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ['.zip', '.tar', '.gz']:
        raise HTTPException(
            status_code=400, 
            detail="Only ZIP and TAR.GZ files are supported"
        )
    
    # Generate unique scan ID
    scan_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
    
    # Create scan directory
    scan_dir = Path(settings.TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Save uploaded file
        upload_path = scan_dir / file.filename
        
        content = await file.read()
        
        # Check file size
        if len(content) > settings.UPLOAD_MAX_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size: {settings.UPLOAD_MAX_SIZE // (1024*1024)}MB"
            )
        
        with open(upload_path, "wb") as f:
            f.write(content)
        
        # Extract archive
        extract_dir = scan_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        
        if file_ext == '.zip':
            await _extract_zip(upload_path, extract_dir)
        elif file_ext in ['.tar', '.gz']:
            await _extract_tar(upload_path, extract_dir)
        
        # Validate WordPress structure
        wp_root = await _find_wordpress_root(extract_dir)
        if not wp_root:
            raise HTTPException(
                status_code=400,
                detail="Invalid WordPress installation. wp-config.php or wp-includes not found."
            )
        
        # Create database record
        scan_record = ScanRecord(
            scan_id=scan_id,
            scan_type=ScanType.UPLOAD,
            status=ScanStatus.PENDING,
            source_path=str(upload_path),
            source_size=len(content),
            created_at=datetime.utcnow()
        )
        
        if scan_name:
            scan_record.metadata = {"scan_name": scan_name}
        
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        # Generate baseline snapshot
        snapshot = await create_baseline_snapshot(scan_id, wp_root)
        
        return JSONResponse(
            status_code=201,
            content={
                "scan_id": scan_id,
                "status": "uploaded",
                "message": "File uploaded and extracted successfully",
                "wordpress_root": str(wp_root.relative_to(scan_dir)),
                "total_files": len(snapshot["files"]),
                "next_steps": f"Use POST /api/v1/scan/{scan_id} to start scanning"
            }
        )
        
    except HTTPException:
        # Clean up on error
        if scan_dir.exists():
            import shutil
            shutil.rmtree(scan_dir, ignore_errors=True)
        raise
    except Exception as e:
        # Clean up on error
        if scan_dir.exists():
            import shutil
            shutil.rmtree(scan_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

async def _extract_zip(zip_path: Path, extract_dir: Path):
    """Extract ZIP archive"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")

async def _extract_tar(tar_path: Path, extract_dir: Path):
    """Extract TAR/TAR.GZ archive"""
    try:
        with tarfile.open(tar_path, 'r:*') as tar_ref:
            tar_ref.extractall(extract_dir)
    except tarfile.TarError:
        raise HTTPException(status_code=400, detail="Invalid TAR file")

async def _find_wordpress_root(extract_dir: Path) -> Optional[Path]:
    """
    Find WordPress root directory in extracted files
    
    Looks for wp-config.php or wp-includes directory
    """
    # Check if extract_dir itself is WordPress root
    if (extract_dir / "wp-config.php").exists() or (extract_dir / "wp-includes").exists():
        return extract_dir
    
    # Search in subdirectories (common when ZIP contains a folder)
    for item in extract_dir.iterdir():
        if item.is_dir():
            if (item / "wp-config.php").exists() or (item / "wp-includes").exists():
                return item
    
    return None

@router.get("/upload/{scan_id}/status")
async def get_upload_status(scan_id: str, db: Session = Depends(get_session)):
    """Get status of uploaded scan"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "scan_type": scan_record.scan_type,
        "status": scan_record.status,
        "created_at": scan_record.created_at,
        "metadata": scan_record.metadata or {}
    }

@router.delete("/upload/{scan_id}")
async def delete_upload(scan_id: str, db: Session = Depends(get_session)):
    """Delete uploaded scan and associated files"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Remove files
    scan_dir = Path(settings.TEMP_DIR) / scan_id
    if scan_dir.exists():
        import shutil
        shutil.rmtree(scan_dir, ignore_errors=True)
    
    # Remove snapshot
    snapshot_path = Path(settings.SNAPSHOTS_DIR) / f"{scan_id}.json"
    if snapshot_path.exists():
        snapshot_path.unlink()
    
    # Remove reports
    report_path = Path(settings.REPORTS_DIR) / f"{scan_id}.json"
    if report_path.exists():
        report_path.unlink()
    
    # Remove database record
    db.delete(scan_record)
    db.commit()
    
    return {"message": f"Scan {scan_id} deleted successfully"}
