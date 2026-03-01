"""
Configuration settings for SecureScan Pro
"""
from pydantic_settings import BaseSettings
from typing import Optional, List
import secrets


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "SecureScan Pro API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"
    
    # Supabase
    SUPABASE_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_KEY: str
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    
    # Security
    # Generate a secure random key if not provided (safe default for dev)
    # In production, this MUST be set via environment variable
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # SSL Verification for Scanners
    # Default to True for security. Set to False only for testing against self-signed certs.
    VERIFY_SSL: bool = True

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10  # Stricter for auth endpoints
    RATE_LIMIT_SCAN_PER_MINUTE: int = 5   # Stricter for scan endpoints
    
    # Threat Intelligence & Scanning
    CVE_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: Optional[str] = None
    THREAT_SYNC_INTERVAL: int = 3600  # 1 hour
    
    # External integrations
    SHODAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    OPENVAS_HOST: str = "localhost"
    OPENVAS_PORT: int = 9390

    # AI / LLM
    # Get a free key at: https://aistudio.google.com/app/apikey
    GEMINI_API_KEY: Optional[str] = None

    # Email (SendGrid) — free tier: 100 emails/day
    # Sign up at: https://signup.sendgrid.com/
    SENDGRID_API_KEY: Optional[str] = None
    SENDGRID_FROM_EMAIL: str = "noreply@securescanpro.com"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore" # Allow extra fields in .env


settings = Settings()

