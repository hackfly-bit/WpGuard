"""
Configuration settings for WPGuard application
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # Server configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # File paths
    TEMP_DIR: str = "temp"
    SNAPSHOTS_DIR: str = "snapshots"
    REPORTS_DIR: str = "reports"
    UPLOAD_MAX_SIZE: int = 100 * 1024 * 1024  # 100MB
    
    # Database
    DATABASE_URL: str = "sqlite:///./wpguard.db"
    
    # FTP settings
    FTP_TIMEOUT: int = 30
    
    # Scanner settings
    SCAN_EXTENSIONS: list = [".php", ".js", ".html", ".htm", ".css"]
    SUSPICIOUS_PATTERNS: list = [
        r"eval\s*\(",
        r"base64_decode\s*\(",
        r"system\s*\(",
        r"shell_exec\s*\(",
        r"exec\s*\(",
        r"passthru\s*\(",
        r"file_get_contents\s*\(",
        r"file_put_contents\s*\(",
        r"fopen\s*\(",
        r"fwrite\s*\(",
        r"curl_exec\s*\(",
        r"preg_replace\s*\(.*\/e",
        r"assert\s*\(",
        r"create_function\s*\(",
        r"\$_POST\[",
        r"\$_GET\[",
        r"\$_REQUEST\[",
        r"\$_COOKIE\[",
        r"unescape\s*\(",
        r"String\.fromCharCode\s*\(",
        r"atob\s*\(",
        r"btoa\s*\(",
    ]
      # Notification settings
    EMAIL_ENABLED: bool = False
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    
    TELEGRAM_ENABLED: bool = False
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    
    model_config = {"env_file": ".env", "case_sensitive": True}

# Global settings instance
settings = Settings()
