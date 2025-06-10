"""
FTP connection and scanning API endpoints
"""
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
import paramiko
import ftplib
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_session
from app.models.scan import ScanRecord, ScanType, ScanStatus
from app.models.findings import FTPRequest
from app.scanner.baseline import create_baseline_snapshot

router = APIRouter()

@router.post("/ftp")
async def connect_ftp(
    ftp_request: FTPRequest,
    db: Session = Depends(get_session)
):
    """
    Connect to FTP/SFTP server and download WordPress files for scanning
    """
    
    # Generate unique scan ID
    scan_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
    
    # Create scan directory
    scan_dir = Path(settings.TEMP_DIR) / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Create database record
        scan_record = ScanRecord(
            scan_id=scan_id,
            scan_type=ScanType.FTP,
            status=ScanStatus.PENDING,
            ftp_host=ftp_request.host,
            ftp_port=ftp_request.port,
            ftp_username=ftp_request.username,
            ftp_remote_path=ftp_request.remote_path,
            created_at=datetime.utcnow()
        )
        
        if ftp_request.scan_name:
            scan_record.metadata = {"scan_name": ftp_request.scan_name}
        
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        
        # Download files
        if ftp_request.use_sftp:
            download_stats = await _download_via_sftp(ftp_request, scan_dir)
        else:
            download_stats = await _download_via_ftp(ftp_request, scan_dir)
        
        # Find WordPress root
        wp_root = await _find_wordpress_root(scan_dir)
        if not wp_root:
            raise HTTPException(
                status_code=400,
                detail="WordPress installation not found in the specified path"
            )
        
        # Generate baseline snapshot
        snapshot = await create_baseline_snapshot(scan_id, wp_root)
        
        # Update scan record with download stats
        scan_record.total_files = len(snapshot["files"])
        scan_record.source_size = download_stats["total_size"]
        db.commit()
        
        return JSONResponse(
            status_code=201,
            content={
                "scan_id": scan_id,
                "status": "connected",
                "message": "FTP connection successful, files downloaded",
                "download_stats": download_stats,
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
        raise HTTPException(status_code=500, detail=f"FTP connection failed: {str(e)}")

async def _download_via_ftp(ftp_request: FTPRequest, local_dir: Path) -> dict:
    """Download files via regular FTP"""
    stats = {"files_downloaded": 0, "total_size": 0, "errors": []}
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(ftp_request.host, ftp_request.port, timeout=settings.FTP_TIMEOUT)
        ftp.login(ftp_request.username, ftp_request.password)
        
        # Change to remote directory
        try:
            ftp.cwd(ftp_request.remote_path)
        except ftplib.error_perm:
            raise HTTPException(status_code=400, detail=f"Cannot access remote path: {ftp_request.remote_path}")
        
        # Download files recursively
        await _ftp_download_recursive(ftp, ".", local_dir, stats)
        
        ftp.quit()
        
    except ftplib.all_errors as e:
        raise HTTPException(status_code=400, detail=f"FTP error: {str(e)}")
    
    return stats

async def _download_via_sftp(ftp_request: FTPRequest, local_dir: Path) -> dict:
    """Download files via SFTP"""
    stats = {"files_downloaded": 0, "total_size": 0, "errors": []}
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=ftp_request.host,
            port=ftp_request.port,
            username=ftp_request.username,
            password=ftp_request.password,
            timeout=settings.FTP_TIMEOUT
        )
        
        sftp = ssh.open_sftp()
        
        # Download files recursively
        await _sftp_download_recursive(sftp, ftp_request.remote_path, local_dir, stats)
        
        sftp.close()
        ssh.close()
        
    except paramiko.AuthenticationException:
        raise HTTPException(status_code=401, detail="Authentication failed")
    except paramiko.SSHException as e:
        raise HTTPException(status_code=400, detail=f"SSH error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SFTP error: {str(e)}")
    
    return stats

async def _ftp_download_recursive(ftp, remote_path: str, local_path: Path, stats: dict):
    """Recursively download files via FTP"""
    try:
        # List directory contents
        items = []
        ftp.retrlines('LIST', items.append)
        
        for item in items:
            # Parse item (simplified parsing)
            parts = item.split()
            if len(parts) < 9:
                continue
                
            permissions = parts[0]
            filename = ' '.join(parts[8:])
            
            if filename in ['.', '..']:
                continue
            
            remote_item_path = f"{remote_path}/{filename}" if remote_path != "." else filename
            local_item_path = local_path / filename
            
            if permissions.startswith('d'):
                # Directory
                local_item_path.mkdir(exist_ok=True)
                old_cwd = ftp.pwd()
                try:
                    ftp.cwd(remote_item_path)
                    await _ftp_download_recursive(ftp, ".", local_item_path, stats)
                    ftp.cwd(old_cwd)
                except:
                    stats["errors"].append(f"Cannot access directory: {remote_item_path}")
            else:
                # File - only download certain file types
                if _should_download_file(filename):
                    try:
                        with open(local_item_path, 'wb') as f:
                            ftp.retrbinary(f'RETR {filename}', f.write)
                        
                        file_size = local_item_path.stat().st_size
                        stats["files_downloaded"] += 1
                        stats["total_size"] += file_size
                        
                    except Exception as e:
                        stats["errors"].append(f"Failed to download {remote_item_path}: {str(e)}")
                        
    except Exception as e:
        stats["errors"].append(f"Error listing directory {remote_path}: {str(e)}")

async def _sftp_download_recursive(sftp, remote_path: str, local_path: Path, stats: dict):
    """Recursively download files via SFTP"""
    try:
        for item in sftp.listdir_attr(remote_path):
            remote_item_path = f"{remote_path}/{item.filename}"
            local_item_path = local_path / item.filename
            
            if item.filename in ['.', '..']:
                continue
            
            try:
                # Check if it's a directory
                if sftp.stat(remote_item_path).st_mode & 0o040000:  # S_IFDIR
                    # Directory
                    local_item_path.mkdir(exist_ok=True)
                    await _sftp_download_recursive(sftp, remote_item_path, local_item_path, stats)
                else:
                    # File - only download certain file types
                    if _should_download_file(item.filename):
                        sftp.get(remote_item_path, str(local_item_path))
                        
                        file_size = local_item_path.stat().st_size
                        stats["files_downloaded"] += 1
                        stats["total_size"] += file_size
                        
            except Exception as e:
                stats["errors"].append(f"Failed to download {remote_item_path}: {str(e)}")
                
    except Exception as e:
        stats["errors"].append(f"Error listing directory {remote_path}: {str(e)}")

def _should_download_file(filename: str) -> bool:
    """Check if file should be downloaded based on extension"""
    download_extensions = ['.php', '.js', '.html', '.htm', '.css', '.htaccess', '.txt', '.json', '.xml']
    
    # Always download WordPress core files
    if filename in ['wp-config.php', '.htaccess', 'index.php']:
        return True
    
    # Check extension
    file_ext = Path(filename).suffix.lower()
    return file_ext in download_extensions

async def _find_wordpress_root(scan_dir: Path) -> Optional[Path]:
    """Find WordPress root directory in downloaded files"""
    # Check if scan_dir itself is WordPress root
    if (scan_dir / "wp-config.php").exists() or (scan_dir / "wp-includes").exists():
        return scan_dir
    
    # Search in subdirectories
    for item in scan_dir.rglob("wp-config.php"):
        return item.parent
    
    for item in scan_dir.rglob("wp-includes"):
        if item.is_dir():
            return item.parent
    
    return None

@router.get("/ftp/{scan_id}/status")
async def get_ftp_status(scan_id: str, db: Session = Depends(get_session)):
    """Get status of FTP scan"""
    
    scan_record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "scan_type": scan_record.scan_type,
        "status": scan_record.status,
        "ftp_host": scan_record.ftp_host,
        "ftp_port": scan_record.ftp_port,
        "ftp_remote_path": scan_record.ftp_remote_path,
        "created_at": scan_record.created_at,
        "total_files": scan_record.total_files,
        "metadata": scan_record.metadata or {}
    }

@router.post("/ftp/test")
async def test_ftp_connection(ftp_request: FTPRequest):
    """Test FTP connection without downloading files"""
    
    try:
        if ftp_request.use_sftp:
            # Test SFTP connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=ftp_request.host,
                port=ftp_request.port,
                username=ftp_request.username,
                password=ftp_request.password,
                timeout=settings.FTP_TIMEOUT
            )
            
            sftp = ssh.open_sftp()
            
            # Try to list remote directory
            files = sftp.listdir(ftp_request.remote_path)
            
            sftp.close()
            ssh.close()
            
            return {
                "status": "success",
                "message": "SFTP connection successful",
                "remote_files_count": len(files)
            }
            
        else:
            # Test FTP connection
            ftp = ftplib.FTP()
            ftp.connect(ftp_request.host, ftp_request.port, timeout=settings.FTP_TIMEOUT)
            ftp.login(ftp_request.username, ftp_request.password)
            
            # Try to change to remote directory
            ftp.cwd(ftp_request.remote_path)
            
            # List files
            files = ftp.nlst()
            
            ftp.quit()
            
            return {
                "status": "success", 
                "message": "FTP connection successful",
                "remote_files_count": len(files)
            }
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Connection test failed: {str(e)}")

# Internal function for scheduled scans
async def connect_ftp_internal(ftp_config: dict, scan_id: str) -> dict:
    """Internal FTP connection function for scheduled scans"""
    try:
        # Create scan directory
        scan_dir = Path(settings.TEMP_DIR) / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract config
        host = ftp_config.get("host")
        port = ftp_config.get("port", 21)
        username = ftp_config.get("username")
        password = ftp_config.get("password")
        remote_path = ftp_config.get("remote_path", "/")
        use_sftp = ftp_config.get("use_sftp", False)
        scan_name = ftp_config.get("scan_name", "Scheduled Scan")
        
        # Create FTP request object
        ftp_request = FTPRequest(
            host=host,
            port=port,
            username=username,
            password=password,
            remote_path=remote_path,
            use_sftp=use_sftp,
            scan_name=scan_name
        )
        
        # Download files
        if use_sftp:
            download_stats = await _download_via_sftp(ftp_request, scan_dir)
        else:
            download_stats = await _download_via_ftp(ftp_request, scan_dir)
        
        # Find WordPress root
        wp_root = await _find_wordpress_root(scan_dir)
        if not wp_root:
            return {"success": False, "error": "WordPress installation not found"}
        
        # Generate baseline snapshot
        from app.scanner.baseline import create_baseline_snapshot
        snapshot = await create_baseline_snapshot(scan_id, wp_root)
        
        return {
            "success": True,
            "scan_id": scan_id,
            "wordpress_root": str(wp_root.relative_to(scan_dir)),
            "total_files": len(snapshot["files"]),
            "download_stats": download_stats
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}
