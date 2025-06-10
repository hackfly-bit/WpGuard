"""
WPGuard Notification System
Email, SMS, and webhook notifications
"""
import asyncio
import logging
import smtplib
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
import aiohttp
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger(__name__)

class NotificationChannel(BaseModel):
    """Notification channel configuration"""
    name: str
    type: str  # 'email', 'webhook', 'telegram'
    config: Dict
    enabled: bool = True

class EmailConfig(BaseModel):
    """Email configuration"""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    from_email: str
    to_emails: List[str]
    use_tls: bool = True

class WebhookConfig(BaseModel):
    """Webhook configuration"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    auth_token: Optional[str] = None

class TelegramConfig(BaseModel):
    """Telegram bot configuration"""
    bot_token: str
    chat_ids: List[str]

class NotificationManager:
    """Manages all notification channels and sending"""
    
    def __init__(self):
        self.channels: Dict[str, NotificationChannel] = {}
        self.load_default_channels()
    
    def load_default_channels(self):
        """Load default notification channels from settings"""
        # Email channel
        if hasattr(settings, 'EMAIL_ENABLED') and settings.EMAIL_ENABLED:
            email_config = {
                "smtp_host": getattr(settings, 'SMTP_HOST', 'smtp.gmail.com'),
                "smtp_port": getattr(settings, 'SMTP_PORT', 587),
                "smtp_user": getattr(settings, 'SMTP_USER', ''),
                "smtp_password": getattr(settings, 'SMTP_PASSWORD', ''),
                "from_email": getattr(settings, 'FROM_EMAIL', ''),
                "to_emails": getattr(settings, 'TO_EMAILS', []),
                "use_tls": getattr(settings, 'SMTP_USE_TLS', True)
            }
            
            if email_config["smtp_user"] and email_config["to_emails"]:
                self.channels["email"] = NotificationChannel(
                    name="Email",
                    type="email",
                    config=email_config,
                    enabled=True
                )
        
        # Webhook channel
        if hasattr(settings, 'WEBHOOK_ENABLED') and settings.WEBHOOK_ENABLED:
            webhook_config = {
                "url": getattr(settings, 'WEBHOOK_URL', ''),
                "method": getattr(settings, 'WEBHOOK_METHOD', 'POST'),
                "headers": getattr(settings, 'WEBHOOK_HEADERS', {}),
                "auth_token": getattr(settings, 'WEBHOOK_AUTH_TOKEN', None)
            }
            
            if webhook_config["url"]:
                self.channels["webhook"] = NotificationChannel(
                    name="Webhook",
                    type="webhook",
                    config=webhook_config,
                    enabled=True
                )
        
        # Telegram channel
        if hasattr(settings, 'TELEGRAM_ENABLED') and settings.TELEGRAM_ENABLED:
            telegram_config = {
                "bot_token": getattr(settings, 'TELEGRAM_BOT_TOKEN', ''),
                "chat_ids": getattr(settings, 'TELEGRAM_CHAT_IDS', [])
            }
            
            if telegram_config["bot_token"] and telegram_config["chat_ids"]:
                self.channels["telegram"] = NotificationChannel(
                    name="Telegram",
                    type="telegram",
                    config=telegram_config,
                    enabled=True
                )
    
    def add_channel(self, channel: NotificationChannel):
        """Add a notification channel"""
        self.channels[channel.name.lower()] = channel
        logger.info(f"Added notification channel: {channel.name}")
    
    def remove_channel(self, channel_name: str):
        """Remove a notification channel"""
        if channel_name.lower() in self.channels:
            del self.channels[channel_name.lower()]
            logger.info(f"Removed notification channel: {channel_name}")
    
    def get_channels(self) -> List[NotificationChannel]:
        """Get all notification channels"""
        return list(self.channels.values())
    
    def get_enabled_channels(self) -> List[NotificationChannel]:
        """Get enabled notification channels"""
        return [channel for channel in self.channels.values() if channel.enabled]
    
    async def send_notification(
        self,
        channels: List[str],
        subject: str,
        message: str,
        scan_id: Optional[str] = None,
        severity: str = "info"
    ) -> Dict[str, bool]:
        """Send notification to specified channels"""
        results = {}
        
        for channel_name in channels:
            channel = self.channels.get(channel_name.lower())
            if not channel or not channel.enabled:
                results[channel_name] = False
                continue
            
            try:
                if channel.type == "email":
                    success = await self._send_email(channel, subject, message, scan_id, severity)
                elif channel.type == "webhook":
                    success = await self._send_webhook(channel, subject, message, scan_id, severity)
                elif channel.type == "telegram":
                    success = await self._send_telegram(channel, subject, message, scan_id, severity)
                else:
                    success = False
                    logger.warning(f"Unsupported notification type: {channel.type}")
                
                results[channel_name] = success
                
            except Exception as e:
                logger.error(f"Failed to send notification via {channel_name}: {e}")
                results[channel_name] = False
        
        return results
    
    async def _send_email(
        self,
        channel: NotificationChannel,
        subject: str,
        message: str,
        scan_id: Optional[str],
        severity: str
    ) -> bool:
        """Send email notification"""
        try:
            config = EmailConfig(**channel.config)
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = config.from_email
            msg['To'] = ', '.join(config.to_emails)
            msg['Subject'] = subject
            
            # Add severity indicator to subject
            severity_indicators = {
                "critical": "🚨",
                "warning": "⚠️",
                "info": "ℹ️",
                "success": "✅",
                "error": "❌"
            }
            
            if severity in severity_indicators:
                msg['Subject'] = f"{severity_indicators[severity]} {subject}"
            
            # Format message with HTML
            html_message = self._format_email_html(message, scan_id, severity)
            msg.attach(MIMEText(html_message, 'html'))
            
            # Send email
            def send_sync():
                with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
                    if config.use_tls:
                        server.starttls()
                    server.login(config.smtp_user, config.smtp_password)
                    server.send_message(msg)
            
            # Run in thread to avoid blocking
            await asyncio.get_event_loop().run_in_executor(None, send_sync)
            
            logger.info(f"Email sent successfully to {len(config.to_emails)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def _send_webhook(
        self,
        channel: NotificationChannel,
        subject: str,
        message: str,
        scan_id: Optional[str],
        severity: str
    ) -> bool:
        """Send webhook notification"""
        try:
            config = WebhookConfig(**channel.config)
            
            payload = {
                "timestamp": datetime.utcnow().isoformat(),
                "service": "WPGuard",
                "subject": subject,
                "message": message,
                "severity": severity,
                "scan_id": scan_id
            }
            
            headers = {"Content-Type": "application/json"}
            headers.update(config.headers)
            
            if config.auth_token:
                headers["Authorization"] = f"Bearer {config.auth_token}"
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=config.method,
                    url=config.url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status < 400:
                        logger.info(f"Webhook sent successfully to {config.url}")
                        return True
                    else:
                        logger.error(f"Webhook failed with status {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False
    
    async def _send_telegram(
        self,
        channel: NotificationChannel,
        subject: str,
        message: str,
        scan_id: Optional[str],
        severity: str
    ) -> bool:
        """Send Telegram notification"""
        try:
            config = TelegramConfig(**channel.config)
            
            # Format message for Telegram
            telegram_message = f"*{subject}*\n\n{message}"
            
            # Add severity emoji
            severity_emojis = {
                "critical": "🚨",
                "warning": "⚠️",
                "info": "ℹ️",
                "success": "✅",
                "error": "❌"
            }
            
            if severity in severity_emojis:
                telegram_message = f"{severity_emojis[severity]} {telegram_message}"
            
            success_count = 0
            for chat_id in config.chat_ids:
                try:
                    url = f"https://api.telegram.org/bot{config.bot_token}/sendMessage"
                    payload = {
                        "chat_id": chat_id,
                        "text": telegram_message,
                        "parse_mode": "Markdown"
                    }
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, json=payload) as response:
                            if response.status == 200:
                                success_count += 1
                            else:
                                logger.error(f"Telegram send failed for chat {chat_id}: {response.status}")
                
                except Exception as e:
                    logger.error(f"Failed to send telegram to chat {chat_id}: {e}")
            
            if success_count > 0:
                logger.info(f"Telegram sent successfully to {success_count}/{len(config.chat_ids)} chats")
                return True
            else:
                return False
        
        except Exception as e:
            logger.error(f"Failed to send telegram: {e}")
            return False
    
    def _format_email_html(self, message: str, scan_id: Optional[str], severity: str) -> str:
        """Format message as HTML email"""
        # Color scheme based on severity
        colors = {
            "critical": "#dc2626",
            "warning": "#ea580c",
            "info": "#2563eb",
            "success": "#16a34a",
            "error": "#dc2626"
        }
        
        color = colors.get(severity, "#2563eb")
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .message {{ background-color: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid {color}; margin: 20px 0; }}
        .footer {{ background-color: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
        .button {{ display: inline-block; background-color: {color}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 10px 0; }}
        pre {{ background-color: #f1f3f4; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WPGuard Security Scanner</h1>
        </div>
        <div class="content">
            <div class="message">
                <pre>{message}</pre>
            </div>
        """
        
        if scan_id:
            html += f"""
            <p>
                <a href="http://localhost:{settings.PORT}/reports/{scan_id}" class="button">
                    View Detailed Report
                </a>
            </p>
            """
        
        html += """
        </div>
        <div class="footer">
            <p>This notification was sent by WPGuard - WordPress Security Scanner</p>
            <p>Generated at """ + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC") + """</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html

    async def test_notifications(self) -> Dict[str, bool]:
        """Test all enabled notification channels"""
        test_results = {}
        
        for channel_name, channel in self.channels.items():
            if not channel.enabled:
                continue
            
            try:
                success = await self.send_notification(
                    channels=[channel_name],
                    subject="WPGuard Test Notification",
                    message="This is a test notification from WPGuard. If you receive this, your notification channel is working correctly.",
                    scan_id=None,
                    severity="info"
                )
                
                test_results[channel_name] = success.get(channel_name, False)
                
            except Exception as e:
                logger.error(f"Test notification failed for {channel_name}: {e}")
                test_results[channel_name] = False
        
        return test_results
