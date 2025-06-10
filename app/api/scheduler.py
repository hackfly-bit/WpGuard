"""
WPGuard Scheduler API
API endpoints for managing scheduled scans and notifications
"""
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.scheduler.scheduler import get_scheduler, ScheduledScan
from app.scheduler.notifications import NotificationManager, NotificationChannel

router = APIRouter()

# Request/Response Models
class ScheduledScanCreate(BaseModel):
    """Create scheduled scan request"""
    name: str = Field(..., description="Name for the scheduled scan")
    scan_type: str = Field(..., description="Type of scan: 'ftp' or 'upload'")
    schedule_type: str = Field(..., description="Schedule type: 'interval' or 'cron'")
    schedule_config: Dict = Field(..., description="Schedule configuration")
    
    # FTP Configuration
    ftp_config: Optional[Dict] = Field(None, description="FTP connection settings")
    
    # Notification settings
    notify_on_completion: bool = Field(True, description="Send notification when scan completes")
    notify_on_threats: bool = Field(True, description="Send notification when threats detected")
    notification_channels: List[str] = Field(["email"], description="Notification channels to use")
    
    # Scan settings
    include_malware_scan: bool = Field(True, description="Include malware detection")
    include_integrity_check: bool = Field(True, description="Include integrity checking")
    enabled: bool = Field(True, description="Enable the scheduled scan")

class ScheduledScanUpdate(BaseModel):
    """Update scheduled scan request"""
    name: Optional[str] = None
    schedule_type: Optional[str] = None
    schedule_config: Optional[Dict] = None
    ftp_config: Optional[Dict] = None
    notify_on_completion: Optional[bool] = None
    notify_on_threats: Optional[bool] = None
    notification_channels: Optional[List[str]] = None
    include_malware_scan: Optional[bool] = None
    include_integrity_check: Optional[bool] = None
    enabled: Optional[bool] = None

class ScheduledScanResponse(BaseModel):
    """Scheduled scan response"""
    id: str
    name: str
    scan_type: str
    schedule_type: str
    schedule_config: Dict
    enabled: bool
    ftp_config: Optional[Dict] = None
    notify_on_completion: bool
    notify_on_threats: bool
    notification_channels: List[str]
    include_malware_scan: bool
    include_integrity_check: bool
    created_at: datetime
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None

class NotificationChannelCreate(BaseModel):
    """Create notification channel request"""
    name: str
    type: str  # 'email', 'webhook', 'telegram'
    config: Dict
    enabled: bool = True

class NotificationTest(BaseModel):
    """Test notification request"""
    channels: List[str] = Field(..., description="Channels to test")
    message: Optional[str] = Field("Test notification from WPGuard", description="Test message")

# Scheduled Scans Endpoints
@router.get("/scheduler/scans", response_model=List[ScheduledScanResponse])
async def list_scheduled_scans():
    """List all scheduled scans"""
    scheduler = get_scheduler()
    scans = scheduler.get_scheduled_scans()
    return [ScheduledScanResponse(**scan.dict()) for scan in scans]

@router.post("/scheduler/scans", response_model=ScheduledScanResponse)
async def create_scheduled_scan(scan_data: ScheduledScanCreate):
    """Create a new scheduled scan"""
    scheduler = get_scheduler()
    
    # Validate schedule configuration
    if scan_data.schedule_type == "interval":
        required_fields = ["seconds", "minutes", "hours", "days", "weeks"]
        if not any(field in scan_data.schedule_config for field in required_fields):
            raise HTTPException(
                status_code=400,
                detail="Interval schedule requires at least one time unit (seconds, minutes, hours, days, weeks)"
            )
    elif scan_data.schedule_type == "cron":
        required_fields = ["second", "minute", "hour", "day", "month", "day_of_week"]
        # Cron can work with default values, but validate format if provided
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail="Schedule type must be 'interval' or 'cron'"
        )
    
    # Validate FTP config for FTP scans
    if scan_data.scan_type == "ftp" and not scan_data.ftp_config:
        raise HTTPException(
            status_code=400,
            detail="FTP configuration required for FTP scans"
        )
    
    # Generate unique ID
    scan_id = f"scheduled-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    # Create scheduled scan
    scheduled_scan = ScheduledScan(
        id=scan_id,
        created_at=datetime.utcnow(),
        **scan_data.dict()
    )
    
    # Add to scheduler
    if scheduler.add_scheduled_scan(scheduled_scan):
        return ScheduledScanResponse(**scheduled_scan.dict())
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to create scheduled scan"
        )

@router.get("/scheduler/scans/{scan_id}", response_model=ScheduledScanResponse)
async def get_scheduled_scan(scan_id: str):
    """Get a specific scheduled scan"""
    scheduler = get_scheduler()
    scan = scheduler.get_scheduled_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    return ScheduledScanResponse(**scan.dict())

@router.put("/scheduler/scans/{scan_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan(scan_id: str, scan_update: ScheduledScanUpdate):
    """Update a scheduled scan"""
    scheduler = get_scheduler()
    existing_scan = scheduler.get_scheduled_scan(scan_id)
    
    if not existing_scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    # Update fields
    update_data = scan_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(existing_scan, field, value)
    
    # Update in scheduler
    if scheduler.update_scheduled_scan(existing_scan):
        return ScheduledScanResponse(**existing_scan.dict())
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to update scheduled scan"
        )

@router.delete("/scheduler/scans/{scan_id}")
async def delete_scheduled_scan(scan_id: str):
    """Delete a scheduled scan"""
    scheduler = get_scheduler()
    
    if scheduler.remove_scheduled_scan(scan_id):
        return {"message": f"Scheduled scan {scan_id} deleted successfully"}
    else:
        raise HTTPException(
            status_code=404,
            detail="Scheduled scan not found"
        )

@router.post("/scheduler/scans/{scan_id}/toggle")
async def toggle_scheduled_scan(scan_id: str):
    """Enable/disable a scheduled scan"""
    scheduler = get_scheduler()
    scan = scheduler.get_scheduled_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    # Toggle enabled status
    scan.enabled = not scan.enabled
    
    if scheduler.update_scheduled_scan(scan):
        status = "enabled" if scan.enabled else "disabled"
        return {"message": f"Scheduled scan {scan_id} {status} successfully"}
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to toggle scheduled scan"
        )

# Notification Endpoints
@router.get("/scheduler/notifications/channels")
async def list_notification_channels():
    """List all notification channels"""
    notification_manager = NotificationManager()
    channels = notification_manager.get_channels()
    return [
        {
            "name": channel.name,
            "type": channel.type,
            "enabled": channel.enabled,
            "config": {k: "***" if "password" in k.lower() or "token" in k.lower() else v 
                      for k, v in channel.config.items()}  # Mask sensitive data
        }
        for channel in channels
    ]

@router.post("/scheduler/notifications/channels")
async def create_notification_channel(channel_data: NotificationChannelCreate):
    """Create a new notification channel"""
    notification_manager = NotificationManager()
    
    channel = NotificationChannel(**channel_data.dict())
    notification_manager.add_channel(channel)
    
    return {"message": f"Notification channel '{channel.name}' created successfully"}

@router.delete("/scheduler/notifications/channels/{channel_name}")
async def delete_notification_channel(channel_name: str):
    """Delete a notification channel"""
    notification_manager = NotificationManager()
    notification_manager.remove_channel(channel_name)
    
    return {"message": f"Notification channel '{channel_name}' deleted successfully"}

@router.post("/scheduler/notifications/test")
async def test_notifications(test_request: NotificationTest):
    """Test notification channels"""
    notification_manager = NotificationManager()
    
    results = await notification_manager.send_notification(
        channels=test_request.channels,
        subject="WPGuard Test Notification",
        message=test_request.message,
        scan_id=None,
        severity="info"
    )
    
    return {
        "message": "Test notifications sent",
        "results": results,
        "successful_channels": [channel for channel, success in results.items() if success],
        "failed_channels": [channel for channel, success in results.items() if not success]
    }

@router.get("/scheduler/status")
async def get_scheduler_status():
    """Get scheduler status and statistics"""
    scheduler = get_scheduler()
    scans = scheduler.get_scheduled_scans()
    
    enabled_scans = [scan for scan in scans if scan.enabled]
    disabled_scans = [scan for scan in scans if not scan.enabled]
    
    # Get next run times from APScheduler
    next_runs = []
    for scan in enabled_scans:
        try:
            job = scheduler.scheduler.get_job(scan.id)
            if job and job.next_run_time:
                next_runs.append({
                    "scan_id": scan.id,
                    "scan_name": scan.name,
                    "next_run": job.next_run_time.isoformat()
                })
        except:
            pass
    
    return {
        "scheduler_running": scheduler.is_running,
        "total_scheduled_scans": len(scans),
        "enabled_scans": len(enabled_scans),
        "disabled_scans": len(disabled_scans),
        "next_scheduled_runs": sorted(next_runs, key=lambda x: x["next_run"])[:5]
    }

# Schedule Configuration Helpers
@router.get("/scheduler/schedule-examples")
async def get_schedule_examples():
    """Get example schedule configurations"""
    return {
        "interval_examples": {
            "every_hour": {
                "schedule_type": "interval",
                "schedule_config": {"hours": 1}
            },
            "every_6_hours": {
                "schedule_type": "interval", 
                "schedule_config": {"hours": 6}
            },
            "daily": {
                "schedule_type": "interval",
                "schedule_config": {"days": 1}
            },
            "weekly": {
                "schedule_type": "interval",
                "schedule_config": {"weeks": 1}
            }
        },
        "cron_examples": {
            "daily_at_2am": {
                "schedule_type": "cron",
                "schedule_config": {"hour": 2, "minute": 0}
            },
            "weekdays_at_9am": {
                "schedule_type": "cron",
                "schedule_config": {"hour": 9, "minute": 0, "day_of_week": "mon-fri"}
            },
            "sundays_at_midnight": {
                "schedule_type": "cron",
                "schedule_config": {"hour": 0, "minute": 0, "day_of_week": "sun"}
            },
            "first_day_of_month": {
                "schedule_type": "cron",
                "schedule_config": {"hour": 3, "minute": 0, "day": 1}
            }
        }
    }
