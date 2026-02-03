"""
User model for Supabase (PostgreSQL)
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
import uuid


class User(BaseModel):
    """User document model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    hashed_password: str
    role: str = "user"  # user, admin
    api_key: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True
    
    class Config:
        populate_by_name = True


class UserCreate(BaseModel):
    """Schema for creating a new user"""
    email: EmailStr
    password: str
    role: str = "user"


class UserResponse(BaseModel):
    """Schema for user response (without password)"""
    id: str
    email: str
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool

