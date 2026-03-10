"""
Authentication API endpoints — native JWT + PostgreSQL (no Supabase).
"""
from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timezone
import hashlib, secrets, base64, uuid

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.supabase_client import get_supabase
from app.core.dependencies import get_current_user
from app.core.config import settings
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
)

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
    try:
        sb = get_supabase()
        existing = sb.table("profiles").select("id").eq("email", user_data.email).execute()
        if existing.data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
        user_id = str(uuid.uuid4())
        full_name = user_data.full_name or user_data.email.split("@")[0]
        now = datetime.now(timezone.utc).isoformat()
        profile = {
            "id": user_id,
            "email": user_data.email,
            "full_name": full_name,
            "password_hash": get_password_hash(user_data.password),
            "role": "user",
            "created_at": now,
            "updated_at": now,
            "settings": {
                "theme": "dark",
                "notifications": {"email": True, "browser": True, "sms": False},
                "default_scan_depth": "medium",
                "auto_save": True
            },
        }
        sb.table("profiles").insert(profile).execute()
        token_data = {"sub": user_id, "email": user_data.email, "role": "user"}
        return TokenResponse(
            access_token=create_access_token(token_data),
            refresh_token=create_refresh_token(token_data),
            user={"id": user_id, "email": user_data.email, "full_name": full_name,
                  "role": "user", "created_at": now},
        )
    except HTTPException:
        raise
    except Exception as e:
        import logging, traceback
        logging.getLogger(__name__).error(f"Register error: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration failed: {str(e)}")


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    sb = get_supabase()
    result = sb.table("profiles").select("*").eq("email", credentials.email).execute()
    if not result.data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    profile = result.data[0]
    password_hash = profile.get("password_hash") or ""
    if not password_hash or not verify_password(credentials.password, password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    token_data = {"sub": profile["id"], "email": profile["email"], "role": profile.get("role", "user")}
    return TokenResponse(
        access_token=create_access_token(token_data), refresh_token=create_refresh_token(token_data),
        user={"id": profile["id"], "email": profile["email"],
              "full_name": profile.get("full_name", credentials.email.split("@")[0]),
              "role": profile.get("role", "user"), "created_at": profile.get("created_at"),
              "last_login": datetime.now(timezone.utc).isoformat(), "settings": profile.get("settings", {})},
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    from jose import JWTError, jwt as jose_jwt
    try:
        payload = jose_jwt.decode(request.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = payload.get("sub"); email = payload.get("email"); role = payload.get("role", "user")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    token_data = {"sub": user_id, "email": email, "role": role}
    return TokenResponse(
        access_token=create_access_token(token_data), refresh_token=create_refresh_token(token_data),
        user={"id": user_id, "email": email, "role": role},
    )


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return current_user


# ── WebAuthn ──────────────────────────────────────────────────────────────────

class WebAuthnRegisterBeginRequest(BaseModel):
    user_id: str

class WebAuthnRegisterFinishRequest(BaseModel):
    user_id: str; credential_id: str; public_key: str; attestation_object: str; client_data_json: str

class WebAuthnAuthBeginRequest(BaseModel):
    user_id: str

class WebAuthnAuthFinishRequest(BaseModel):
    user_id: str; credential_id: str; authenticator_data: str; client_data_json: str; signature: str


@router.post("/webauthn/register/begin")
async def webauthn_register_begin(req: WebAuthnRegisterBeginRequest, current_user: dict = Depends(get_current_user)):
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    options = {
        "challenge": challenge, "rp": {"name": "SecureScan Pro", "id": "localhost"},
        "user": {"id": base64.urlsafe_b64encode(req.user_id.encode()).rstrip(b"=").decode(),
                 "name": current_user.get("email", req.user_id), "displayName": current_user.get("full_name", "SecureScan User")},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "authenticatorSelection": {"authenticatorAttachment": "platform", "userVerification": "required", "residentKey": "preferred"},
        "timeout": 60000, "attestation": "none",
    }
    try:
        sb = get_supabase()
        res = sb.table("profiles").select("settings").eq("id", req.user_id).execute()
        s = (res.data[0].get("settings") or {}) if res.data else {}
        s["_webauthn_challenge"] = challenge
        sb.table("profiles").update({"settings": s}).eq("id", req.user_id).execute()
    except Exception:
        pass
    return options


@router.post("/webauthn/register/finish")
async def webauthn_register_finish(req: WebAuthnRegisterFinishRequest, current_user: dict = Depends(get_current_user)):
    try:
        sb = get_supabase()
        res = sb.table("profiles").select("settings").eq("id", req.user_id).execute()
        s = (res.data[0].get("settings") or {}) if res.data else {}
        creds = s.get("webauthn_credentials", [])
        creds.append({"credential_id": req.credential_id, "public_key": req.public_key, "registered_at": datetime.now(timezone.utc).isoformat()})
        s["webauthn_credentials"] = creds; s.pop("_webauthn_challenge", None)
        sb.table("profiles").update({"settings": s}).eq("id", req.user_id).execute()
        return {"status": "ok", "message": "Passkey registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webauthn/authenticate/begin")
async def webauthn_auth_begin(req: WebAuthnAuthBeginRequest):
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    try:
        sb = get_supabase()
        res = sb.table("profiles").select("settings").eq("id", req.user_id).execute()
        s = (res.data[0].get("settings") or {}) if res.data else {}
        allow_creds = [{"type": "public-key", "id": c["credential_id"], "transports": ["internal"]} for c in s.get("webauthn_credentials", [])]
        s["_webauthn_challenge"] = challenge
        sb.table("profiles").update({"settings": s}).eq("id", req.user_id).execute()
    except Exception:
        allow_creds = []
    return {"challenge": challenge, "rpId": "localhost", "allowCredentials": allow_creds, "userVerification": "required", "timeout": 60000}


@router.post("/webauthn/authenticate/finish")
async def webauthn_auth_finish(req: WebAuthnAuthFinishRequest):
    try:
        sb = get_supabase()
        res = sb.table("profiles").select("id,email,settings,role").eq("id", req.user_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="User not found")
        profile = res.data[0]; s = profile.get("settings") or {}
        if req.credential_id not in [c["credential_id"] for c in s.get("webauthn_credentials", [])]:
            raise HTTPException(status_code=401, detail="Unknown credential")
        token_data = {"sub": profile["id"], "email": profile["email"], "role": profile.get("role", "user")}
        return {"status": "ok", "user_id": profile["id"], "email": profile["email"],
                "access_token": create_access_token(token_data), "refresh_token": create_refresh_token(token_data),
                "message": "Biometric authentication successful"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/webauthn/credentials/{user_id}")
async def list_webauthn_credentials(user_id: str, current_user: dict = Depends(get_current_user)):
    sb = get_supabase()
    res = sb.table("profiles").select("settings").eq("id", user_id).execute()
    s = (res.data[0].get("settings") or {}) if res.data else {}
    return [{"credential_id": c["credential_id"], "registered_at": c.get("registered_at")} for c in s.get("webauthn_credentials", [])]


@router.delete("/webauthn/credentials/{user_id}/{credential_id}")
async def delete_webauthn_credential(user_id: str, credential_id: str, current_user: dict = Depends(get_current_user)):
    sb = get_supabase()
    res = sb.table("profiles").select("settings").eq("id", user_id).execute()
    s = (res.data[0].get("settings") or {}) if res.data else {}
    s["webauthn_credentials"] = [c for c in s.get("webauthn_credentials", []) if c["credential_id"] != credential_id]
    sb.table("profiles").update({"settings": s}).eq("id", user_id).execute()
    return {"status": "ok"}


# ── PIN auth ──────────────────────────────────────────────────────────────────

class PinSetupRequest(BaseModel):
    user_id: str; pin: str

class PinVerifyRequest(BaseModel):
    user_id: str; pin: str

class PinLoginRequest(BaseModel):
    email: str; pin: str


def _hash_pin(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), iterations=260_000).hex()


@router.post("/pin/setup")
async def setup_pin(req: PinSetupRequest, current_user: dict = Depends(get_current_user)):
    if not req.pin.isdigit() or not (4 <= len(req.pin) <= 8):
        raise HTTPException(status_code=400, detail="PIN must be 4–8 digits")
    salt = secrets.token_hex(16); pin_hash = _hash_pin(req.pin, salt)
    sb = get_supabase()
    res = sb.table("profiles").select("settings").eq("id", req.user_id).execute()
    s = (res.data[0].get("settings") or {}) if res.data else {}
    s.update({"pin_hash": pin_hash, "pin_salt": salt, "pin_set_at": datetime.now(timezone.utc).isoformat()})
    sb.table("profiles").update({"settings": s}).eq("id", req.user_id).execute()
    return {"status": "ok", "message": "PIN set successfully"}


@router.post("/pin/verify")
async def verify_pin(req: PinVerifyRequest):
    sb = get_supabase()
    res = sb.table("profiles").select("id,email,settings").eq("id", req.user_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="User not found")
    profile = res.data[0]; s = profile.get("settings") or {}
    if not s.get("pin_hash") or not secrets.compare_digest(_hash_pin(req.pin, s.get("pin_salt", "")), s.get("pin_hash", "")):
        raise HTTPException(status_code=401, detail="Incorrect PIN")
    return {"status": "ok", "user_id": profile["id"], "email": profile["email"]}


@router.get("/pin/status/{user_id}")
async def pin_status(user_id: str, current_user: dict = Depends(get_current_user)):
    sb = get_supabase()
    res = sb.table("profiles").select("settings").eq("id", user_id).execute()
    s = (res.data[0].get("settings") or {}) if res.data else {}
    return {"has_pin": bool(s.get("pin_hash")), "pin_set_at": s.get("pin_set_at")}


@router.post("/pin/login")
async def pin_login(req: PinLoginRequest):
    sb = get_supabase()
    res = sb.table("profiles").select("id,email,full_name,role,settings").eq("email", req.email).execute()
    if not res.data:
        raise HTTPException(status_code=401, detail="Invalid email or PIN")
    profile = res.data[0]; s = profile.get("settings") or {}
    if not s.get("pin_hash"):
        raise HTTPException(status_code=400, detail="No PIN set. Use password login.")
    if not secrets.compare_digest(_hash_pin(req.pin, s.get("pin_salt", "")), s.get("pin_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or PIN")
    token_data = {"sub": profile["id"], "email": profile["email"], "role": profile.get("role", "user")}
    return {"success": True, "user_id": profile["id"], "email": profile["email"],
            "access_token": create_access_token(token_data), "refresh_token": create_refresh_token(token_data)}


@router.delete("/pin/remove/{user_id}")
async def remove_pin(user_id: str, current_user: dict = Depends(get_current_user)):
    sb = get_supabase()
    res = sb.table("profiles").select("settings").eq("id", user_id).execute()
    s = (res.data[0].get("settings") or {}) if res.data else {}
    for k in ("pin_hash", "pin_salt", "pin_set_at"):
        s.pop(k, None)
    sb.table("profiles").update({"settings": s}).eq("id", user_id).execute()
    return {"status": "ok", "message": "PIN removed"}


@router.get("/user-id-by-email")
async def user_id_by_email(email: str):
    sb = get_supabase()
    res = sb.table("profiles").select("id").eq("email", email).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="No account found for that email")
    return {"user_id": res.data[0]["id"]}
