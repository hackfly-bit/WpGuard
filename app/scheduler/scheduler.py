"""
WPGuard Scheduler Module
Automated scheduling and notification system
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel

from app.core.config import settings
from .notifications import NotificationManager

logger = logging.getLogger(__name__)

class ScheduledScan(BaseModel):
    """Scheduled scan configuration"""
    id: str
    name: str
    scan_type: str  # 'ftp' or 'upload'
    schedule_type: str  # 'interval' or 'cron'
    schedule_config: Dict
    enabled: bool = True
    
    # FTP Configuration (for FTP scans)
    ftp_config: Optional[Dict] = None
    
    # Notification settings
    notify_on_completion: bool = True
    notify_on_threats: bool = True
    notification_channels: List[str] = ["email"]
    
    # Scan settings
    include_malware_scan: bool = True
    include_integrity_check: bool = True
    
    created_at: datetime
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None

class ScanScheduler:
    """Manages scheduled scans and notifications"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.notification_manager = NotificationManager()
        self.scheduled_scans: Dict[str, ScheduledScan] = {}
        self.is_running = False
    
    async def start(self):
        """Start the scheduler"""
        try:
            self.scheduler.start()
            self.is_running = True
            await self.load_scheduled_scans()
            logger.info("Scan scheduler started successfully")
        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
            raise
    
    async def stop(self):
        """Stop the scheduler"""
        if self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Scan scheduler stopped")
    
    async def load_scheduled_scans(self):
        """Load scheduled scans from database/config"""
        # For now, we'll store scheduled scans in memory
        # In production, these should be persisted in database
        pass
    
    def add_scheduled_scan(self, scan_config: ScheduledScan) -> bool:
        """Add a new scheduled scan"""
        try:
            if scan_config.schedule_type == "interval":
                trigger = IntervalTrigger(**scan_config.schedule_config)
            elif scan_config.schedule_type == "cron":
                trigger = CronTrigger(**scan_config.schedule_config)
            else:
                raise ValueError(f"Invalid schedule type: {scan_config.schedule_type}")
            
            # Add job to scheduler
            self.scheduler.add_job(
                func=self._execute_scheduled_scan,
                trigger=trigger,
                id=scan_config.id,
                args=[scan_config],
                name=scan_config.name,
                replace_existing=True
            )
            
            self.scheduled_scans[scan_config.id] = scan_config
            logger.info(f"Added scheduled scan: {scan_config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add scheduled scan {scan_config.name}: {e}")
            return False
    
    def remove_scheduled_scan(self, scan_id: str) -> bool:
        """Remove a scheduled scan"""
        try:
            if scan_id in self.scheduled_scans:
                self.scheduler.remove_job(scan_id)
                del self.scheduled_scans[scan_id]
                logger.info(f"Removed scheduled scan: {scan_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove scheduled scan {scan_id}: {e}")
            return False
    
    def update_scheduled_scan(self, scan_config: ScheduledScan) -> bool:
        """Update an existing scheduled scan"""
        try:
            # Remove existing and add updated
            self.remove_scheduled_scan(scan_config.id)
            return self.add_scheduled_scan(scan_config)
        except Exception as e:
            logger.error(f"Failed to update scheduled scan {scan_config.id}: {e}")
            return False
    
    def get_scheduled_scans(self) -> List[ScheduledScan]:
        """Get all scheduled scans"""
        return list(self.scheduled_scans.values())
    
    def get_scheduled_scan(self, scan_id: str) -> Optional[ScheduledScan]:
        """Get a specific scheduled scan"""
        return self.scheduled_scans.get(scan_id)
    
    async def _execute_scheduled_scan(self, scan_config: ScheduledScan):
        """Execute a scheduled scan"""
        logger.info(f"Executing scheduled scan: {scan_config.name}")
        
        try:
            # Update last run time
            scan_config.last_run = datetime.utcnow()
            
            if scan_config.scan_type == "ftp":
                await self._execute_ftp_scan(scan_config)
            else:
                logger.warning(f"Unsupported scan type: {scan_config.scan_type}")
                
        except Exception as e:
            logger.error(f"Failed to execute scheduled scan {scan_config.name}: {e}")
            
            # Send failure notification
            if scan_config.notify_on_completion:
                await self.notification_manager.send_notification(
                    channels=scan_config.notification_channels,                    subject=f"WPGuard: Scheduled Scan Failed - {scan_config.name}",
                    message=f"Scheduled scan '{scan_config.name}' failed with error: {str(e)}",
                    scan_id=None,
                    severity="error"
                )
    
    async def _execute_ftp_scan(self, scan_config: ScheduledScan):
        """Execute an FTP-based scheduled scan"""
        if not scan_config.ftp_config:
            raise ValueError("FTP configuration required for FTP scan")
        
        # Generate scan ID
        scan_id = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{scan_config.id[:8]}"
        
        try:
            # Import here to avoid circular imports
            from app.api.ftp import connect_ftp_internal
            
            # Connect to FTP and download files
            ftp_result = await connect_ftp_internal(scan_config.ftp_config, scan_id)
            
            if not ftp_result.get("success"):
                raise Exception(f"FTP connection failed: {ftp_result.get('error')}")
            
            # Execute scan
            scan_result = await self._perform_scan(scan_id, scan_config)
              # Send notifications
            await self._send_scan_notifications(scan_config, scan_result, scan_id)
            
            logger.info(f"Scheduled scan completed: {scan_config.name} (ID: {scan_id})")
            
        except Exception as e:
            logger.error(f"FTP scan failed for {scan_config.name}: {e}")
            raise
    
    async def _perform_scan(self, scan_id: str, scan_config: ScheduledScan) -> Dict:
        """Perform the actual security scan"""
        results = {
            "scan_id": scan_id,
            "total_files": 0,
            "suspicious_files": 0,
            "changed_files": 0,
            "new_files": 0,
            "deleted_files": 0,
            "findings": [],
            "completed_at": None
        }
        
        try:
            # Get extracted files path
            scan_dir = f"{settings.TEMP_DIR}/{scan_id}/extracted"
            
            # Initialize scanners with local imports to avoid circular imports
            if scan_config.include_integrity_check:
                from app.scanner.integrity import IntegrityChecker
                integrity_checker = IntegrityChecker()
                integrity_results = await integrity_checker.check_integrity(scan_id, scan_dir)
                results.update({
                    "changed_files": len(integrity_results.get("changed_files", [])),
                    "new_files": len(integrity_results.get("new_files", [])),
                    "deleted_files": len(integrity_results.get("deleted_files", []))
                })
            
            if scan_config.include_malware_scan:
                from app.scanner.malware import MalwareScanner
                malware_scanner = MalwareScanner()
                malware_results = await malware_scanner.scan_directory(scan_dir)
                results.update({
                    "suspicious_files": len(malware_results.get("suspicious_files", [])),
                    "findings": malware_results.get("findings", [])
                })
            
            results["completed_at"] = datetime.utcnow().isoformat()
            results["total_files"] = sum([
                results["changed_files"],
                results["new_files"],
                results["suspicious_files"]
            ])
            
            return results
            
        except Exception as e:
            logger.error(f"Scan execution failed for {scan_id}: {e}")
            raise
    
    async def _send_scan_notifications(self, scan_config: ScheduledScan, scan_result: Dict, scan_id: str):
        """Send notifications based on scan results"""
        try:
            has_threats = scan_result.get("suspicious_files", 0) > 0
            has_changes = (
                scan_result.get("changed_files", 0) > 0 or
                scan_result.get("new_files", 0) > 0 or
                scan_result.get("deleted_files", 0) > 0
            )
            
            # Determine if we should send notification
            should_notify = (
                (scan_config.notify_on_completion) or
                (scan_config.notify_on_threats and has_threats)
            )
            
            if not should_notify:
                return
            
            # Determine severity
            if has_threats:
                severity = "critical" if scan_result.get("suspicious_files", 0) > 5 else "warning"
            elif has_changes:
                severity = "info"
            else:
                severity = "success"
            
            # Create notification message
            subject = f"WPGuard: Scan Complete - {scan_config.name}"
            if has_threats:
                subject = f"🚨 WPGuard: Security Threats Detected - {scan_config.name}"
            elif has_changes:
                subject = f"⚠️ WPGuard: File Changes Detected - {scan_config.name}"
            
            message = self._format_scan_summary(scan_result, scan_config.name)
            
            # Send notification
            await self.notification_manager.send_notification(
                channels=scan_config.notification_channels,
                subject=subject,
                message=message,
                scan_id=scan_id,
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Failed to send notifications for scan {scan_id}: {e}")
    
    def _format_scan_summary(self, scan_result: Dict, scan_name: str) -> str:
        """Format scan results for notification"""
        summary = f"""
Scheduled Scan Results: {scan_name}
Scan ID: {scan_result.get('scan_id', 'Unknown')}

📊 Summary:
• Total Files Scanned: {scan_result.get('total_files', 0)}
• Suspicious Files: {scan_result.get('suspicious_files', 0)}
• Changed Files: {scan_result.get('changed_files', 0)}
• New Files: {scan_result.get('new_files', 0)}
• Deleted Files: {scan_result.get('deleted_files', 0)}

Completed: {scan_result.get('completed_at', 'Unknown')}

View detailed report: http://localhost:{settings.PORT}/reports/{scan_result.get('scan_id', '')}
        """.strip()
        
        # Add threat details if present
        findings = scan_result.get('findings', [])
        if findings:
            threat_summary = "\n\n🚨 Security Threats Detected:\n"
            for finding in findings[:5]:  # Show first 5 threats
                threat_summary += f"• {finding.get('file_path', 'Unknown')}: {finding.get('description', 'Unknown threat')}\n"
            
            if len(findings) > 5:
                threat_summary += f"... and {len(findings) - 5} more threats\n"
            
            summary += threat_summary
        
        return summary

# Global scheduler instance
scheduler_instance = ScanScheduler()

async def start_scheduler():
    """Start the global scheduler"""
    await scheduler_instance.start()

async def stop_scheduler():
    """Stop the global scheduler"""
    await scheduler_instance.stop()

def get_scheduler() -> ScanScheduler:
    """Get the global scheduler instance"""
    return scheduler_instance
