"""
FastAPI dependencies for authentication using Supabase
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from app.core.supabase_client import get_supabase

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user from Supabase"""
    token = credentials.credentials
    supabase = get_supabase()
    
    try:
        # Verify token with Supabase
        user_response = supabase.auth.get_user(token)
        
        if not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        
        # Get user profile from database
        profile_result = supabase.table("profiles").select("*").eq("id", user_response.user.id).execute()
        
        if profile_result.data:
            profile = profile_result.data[0]
        else:
            # Create basic profile if doesn't exist
            profile = {
                "id": user_response.user.id,
                "email": user_response.user.email,
                "full_name": user_response.user.email.split("@")[0],
                "role": "user",
            }
        
        return {
            "id": user_response.user.id,
            "email": user_response.user.email,
            **profile
        }
        
    except Exception as e:
        # Log the error but do not expose details or grant access
        print(f"Auth verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))):
    """Get current user if authenticated, otherwise None"""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except:
        return None


def get_supabase_client():
    """Dependency to get Supabase client"""
    return get_supabase()
