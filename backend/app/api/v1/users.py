"""
User management API endpoints for Supabase
"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

from app.core.supabase_client import get_supabase
from app.core.dependencies import get_current_user
from app.core.security import get_password_hash

router = APIRouter(prefix="/users", tags=["users"])


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class SettingsUpdate(BaseModel):
    theme: Optional[str] = None
    notifications: Optional[dict] = None
    default_scan_depth: Optional[str] = None
    auto_save: Optional[bool] = None


@router.get("/me")
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user.get("full_name", current_user["email"].split("@")[0]),
        "role": current_user.get("role", "user"),
        "created_at": current_user.get("created_at"),
        "last_login": current_user.get("last_login"),
        "settings": current_user.get("settings", {})
    }


@router.put("/me")
async def update_profile(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    supabase = get_supabase()
    update_data = {}
    
    if user_update.full_name is not None:
        update_data["full_name"] = user_update.full_name
    
    if user_update.email is not None:
        # Check if email is already taken
        existing = supabase.table("profiles").select("id").eq("email", user_update.email).neq("id", current_user["id"]).execute()
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        update_data["email"] = user_update.email
    
    if update_data:
        supabase.table("profiles").update(update_data).eq("id", current_user["id"]).execute()
    
    # Return updated user
    updated = supabase.table("profiles").select("*").eq("id", current_user["id"]).execute()
    updated_user = updated.data[0] if updated.data else current_user
    
    return {
        "id": updated_user["id"],
        "email": updated_user["email"],
        "full_name": updated_user.get("full_name", updated_user["email"].split("@")[0]),
        "role": updated_user.get("role", "user"),
    }


@router.post("/me/password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Change user password via Supabase Auth"""
    try:
        supabase = get_supabase()
        
        # Supabase handles password change through Auth API
        # Note: This requires the user's access token
        result = supabase.auth.update_user({
            "password": password_data.new_password
        })
        
        return {"message": "Password updated successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update password: {str(e)}"
        )


@router.get("/me/settings")
async def get_settings(current_user: dict = Depends(get_current_user)):
    """Get user settings"""
    return current_user.get("settings", {
        "theme": "dark",
        "notifications": {
            "email": True,
            "browser": True,
            "sms": False
        },
        "default_scan_depth": "medium",
        "auto_save": True
    })


@router.put("/me/settings")
async def update_settings(
    settings_update: SettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user settings"""
    supabase = get_supabase()
    current_settings = current_user.get("settings", {})
    
    if settings_update.theme is not None:
        current_settings["theme"] = settings_update.theme
    
    if settings_update.notifications is not None:
        current_settings["notifications"] = {
            **current_settings.get("notifications", {}),
            **settings_update.notifications
        }
    
    if settings_update.default_scan_depth is not None:
        current_settings["default_scan_depth"] = settings_update.default_scan_depth
    
    if settings_update.auto_save is not None:
        current_settings["auto_save"] = settings_update.auto_save
    
    supabase.table("profiles").update({"settings": current_settings}).eq("id", current_user["id"]).execute()
    
    return {"settings": current_settings, "message": "Settings updated successfully"}

