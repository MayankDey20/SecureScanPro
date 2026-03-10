"""
FastAPI dependencies — JWT-based authentication (no Supabase).
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from jose import JWTError, jwt

from app.core.config import settings
from app.core.supabase_client import get_supabase

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Decode and verify JWT, then load user profile from PostgreSQL."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        if payload.get("type") not in (None, "access"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sb = get_supabase()
    profile_result = sb.table("profiles").select("*").eq("id", user_id).execute()

    if profile_result.data:
        profile = profile_result.data[0]
    else:
        profile = {
            "id": user_id,
            "email": payload.get("email", ""),
            "full_name": payload.get("email", "").split("@")[0],
            "role": payload.get("role", "user"),
        }

    return {
        "id": user_id,
        "email": profile.get("email", payload.get("email", "")),
        **profile,
    }


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Optional[dict]:
    """Return current user if authenticated, else None."""
    if not credentials:
        return None
    try:
        return await get_current_user(credentials)
    except Exception:
        return None


def get_supabase_client():
    """Legacy dependency — returns the DB shim."""
    return get_supabase()
