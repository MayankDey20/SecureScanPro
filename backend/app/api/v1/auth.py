"""
Authentication API endpoints using Supabase
"""
from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.supabase_client import get_supabase
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["authentication"])
limiter = Limiter(key_func=get_remote_address)


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@router.post("/register", response_model=TokenResponse)
@limiter.limit(f"{settings.RATE_LIMIT_AUTH_PER_MINUTE}/minute")
async def register(request: Request, user_data: UserRegister):
    """Register a new user using Supabase Auth"""
    supabase = get_supabase()
    
    try:
        # Create user in Supabase Auth
        response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password,
            "options": {
                "data": {
                    "full_name": user_data.full_name or user_data.email.split("@")[0],
                }
            }
        })
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed"
            )
        
        # Create user profile in database
        profile_data = {
            "id": response.user.id,
            "email": user_data.email,
            "full_name": user_data.full_name or user_data.email.split("@")[0],
            "role": "user",
            "created_at": datetime.utcnow().isoformat(),
            "settings": {
                "theme": "dark",
                "notifications": {
                    "email": True,
                    "browser": True,
                    "sms": False
                },
                "default_scan_depth": "medium",
                "auto_save": True
            }
        }
        
        supabase.table("profiles").insert(profile_data).execute()
        
        user_response = {
            "id": response.user.id,
            "email": response.user.email,
            "full_name": user_data.full_name or user_data.email.split("@")[0],
            "role": "user",
            "created_at": datetime.utcnow().isoformat(),
        }
        
        return TokenResponse(
            access_token=response.session.access_token if response.session else "",
            refresh_token=response.session.refresh_token if response.session else "",
            user=user_response
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login user using Supabase Auth"""
    supabase = get_supabase()
    
    try:
        # Sign in with Supabase Auth
        response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password,
        })
        
        if not response.user or not response.session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Get user profile from database
        profile_result = supabase.table("profiles").select("*").eq("id", response.user.id).execute()
        
        profile = profile_result.data[0] if profile_result.data else {}
        
        user_response = {
            "id": response.user.id,
            "email": response.user.email,
            "full_name": profile.get("full_name", response.user.email.split("@")[0]),
            "role": profile.get("role", "user"),
            "created_at": response.user.created_at,
            "last_login": datetime.utcnow().isoformat(),
            "settings": profile.get("settings", {})
        }
        
        return TokenResponse(
            access_token=response.session.access_token,
            refresh_token=response.session.refresh_token,
            user=user_response
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token using Supabase"""
    supabase = get_supabase()
    
    try:
        response = supabase.auth.refresh_session(request.refresh_token)
        
        if not response.session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user profile
        profile_result = supabase.table("profiles").select("*").eq("id", response.user.id).execute()
        profile = profile_result.data[0] if profile_result.data else {}
        
        user_response = {
            "id": response.user.id,
            "email": response.user.email,
            "full_name": profile.get("full_name", response.user.email.split("@")[0]),
            "role": profile.get("role", "user"),
        }
        
        return TokenResponse(
            access_token=response.session.access_token,
            refresh_token=response.session.refresh_token,
            user=user_response
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return current_user
