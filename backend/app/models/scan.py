"""
Scan model for Supabase
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
import uuid
import re
from ipaddress import ip_address, ip_network


# Private/internal IP ranges that should not be scanned (SSRF protection)
PRIVATE_NETWORKS = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('127.0.0.0/8'),
    ip_network('169.254.0.0/16'),
    ip_network('0.0.0.0/8'),
]

BLOCKED_HOSTS = ['localhost', 'internal', 'intranet', 'corp', 'private']


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range"""
    try:
        ip = ip_address(ip_str)
        return any(ip in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_scan_target(url: str) -> str:
    """Validate and sanitize scan target URL"""
    from urllib.parse import urlparse
    
    # Basic URL format validation
    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}'
        r'|localhost'
        r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        raise ValueError(f"Invalid URL format: {url}")
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    if not hostname:
        raise ValueError("URL must contain a valid hostname")
    
    # Block internal/private hostnames
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_HOSTS:
        if blocked in hostname_lower:
            raise ValueError(f"Scanning internal hosts is not allowed: {hostname}")
    
    # Check if hostname is an IP and if it's private
    if is_private_ip(hostname):
        raise ValueError(f"Scanning private IP addresses is not allowed: {hostname}")
    
    return url


class ScanTarget(BaseModel):
    """Validated scan target"""
    target: str
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        return validate_scan_target(v)


class ScanOptions(BaseModel):
    """Scan configuration options"""
    scan_depth: str = "medium"
    port_range: Optional[str] = None
    user_agent: Optional[str] = None
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    proxy_url: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    scan_modules: Optional[list] = None
    schedule_freq: Optional[str] = None
    schedule_time: Optional[datetime] = None
    webhook_url: Optional[str] = None
    email_notify: bool = False


class Scan(BaseModel):
    """Scan document model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    scan_type: str = "full"
    status: str = "queued"  # queued, running, completed, failed, cancelled
    security_score: Optional[int] = None
    vulnerabilities_found: int = 0
    scan_options: ScanOptions
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: Optional[str] = None  # user_id
    error_message: Optional[str] = None
    
    class Config:
        populate_by_name = True


class ScanCreate(BaseModel):
    """Schema for creating a new scan"""
    target: str  # Can be URL or domain
    scan_type: List[str] = ["full"]
    scan_options: Optional[ScanOptions] = None
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate scan target to prevent SSRF attacks"""
        # Add https:// if no scheme provided
        if not v.startswith(('http://', 'https://')):
            v = f"https://{v}"
        return validate_scan_target(v)
    
    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v: List[str]) -> List[str]:
        """Validate scan types"""
        allowed_types = ['full', 'quick', 'ssl', 'headers', 'ports', 'vulnerabilities', 'recon']
        for scan_type in v:
            if scan_type not in allowed_types:
                raise ValueError(f"Invalid scan type: {scan_type}. Allowed: {allowed_types}")
        return v


class ScanUpdate(BaseModel):
    """Schema for updating a scan"""
    status: Optional[str] = None
    security_score: Optional[int] = None
    vulnerabilities_found: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

