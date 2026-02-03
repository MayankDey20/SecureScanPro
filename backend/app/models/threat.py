"""
Threat Intelligence model for Supabase
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
import uuid


class Threat(BaseModel):
    """Threat Intelligence document model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    cvss_score: float
    published_date: datetime
    affected_products: List[str] = []
    references: List[str] = []
    category: str  # Injection, XSS, Authentication, etc.
    trending: bool = False
    exploit_available: bool = False
    synced_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True


class ThreatCreate(BaseModel):
    """Schema for creating/updating a threat"""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    published_date: datetime
    affected_products: List[str] = []
    references: List[str] = []
    category: str
    trending: bool = False
    exploit_available: bool = False


class ThreatStats(BaseModel):
    """Threat statistics"""
    total: int
    critical: int
    high: int
    medium: int
    low: int
    trending: int
    with_exploits: int
    category_breakdown: dict

