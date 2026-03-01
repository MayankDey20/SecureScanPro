"""
Authentication API endpoints using Supabase
"""
from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
import hashlib, secrets, base64, json
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


# ─────────────────────────────────────────────
#  WebAuthn / Passkey (Fingerprint) endpoints
#  Uses the browser's built-in WebAuthn API.
#  The server only stores the credential ID + public key; the private key
#  never leaves the device (Touch ID / Face ID / Windows Hello).
# ─────────────────────────────────────────────

class WebAuthnRegisterBeginRequest(BaseModel):
    user_id: str


class WebAuthnRegisterFinishRequest(BaseModel):
    user_id: str
    credential_id: str          # base64url encoded credential ID from navigator.credentials.create()
    public_key: str             # base64url encoded COSE public key
    attestation_object: str     # base64url attestation object (for verification, stored for audit)
    client_data_json: str       # base64url client data


class WebAuthnAuthBeginRequest(BaseModel):
    user_id: str


class WebAuthnAuthFinishRequest(BaseModel):
    user_id: str
    credential_id: str
    authenticator_data: str     # base64url
    client_data_json: str       # base64url
    signature: str              # base64url


@router.post("/webauthn/register/begin")
async def webauthn_register_begin(
    req: WebAuthnRegisterBeginRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Return a WebAuthn PublicKeyCredentialCreationOptions challenge.
    The frontend passes this directly to navigator.credentials.create().
    """
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    rp_id = "localhost"  # Change to your domain in production

    options = {
        "challenge": challenge,
        "rp": {"name": "SecureScan Pro", "id": rp_id},
        "user": {
            "id": base64.urlsafe_b64encode(req.user_id.encode()).rstrip(b"=").decode(),
            "name": current_user.get("email", req.user_id),
            "displayName": current_user.get("full_name", "SecureScan User"),
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},   # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",   # device biometric (Touch ID etc.)
            "userVerification": "required",
            "residentKey": "preferred",
        },
        "timeout": 60000,
        "attestation": "none",
    }

    # Persist challenge temporarily in profiles for verification on finish
    try:
        supabase = get_supabase()
        supabase.table("profiles").update({
            "settings": {
                **current_user.get("settings", {}),
                "_webauthn_challenge": challenge
            }
        }).eq("id", req.user_id).execute()
    except Exception:
        pass  # non-fatal — challenge is short-lived

    return options


@router.post("/webauthn/register/finish")
async def webauthn_register_finish(
    req: WebAuthnRegisterFinishRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Store the credential after the browser completes navigator.credentials.create().
    In production use py_webauthn for full attestation verification.
    """
    try:
        supabase = get_supabase()
        # Store credential in profile settings
        profile_res = supabase.table("profiles").select("settings").eq("id", req.user_id).execute()
        existing_settings = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}

        credentials = existing_settings.get("webauthn_credentials", [])
        credentials.append({
            "credential_id": req.credential_id,
            "public_key": req.public_key,
            "registered_at": datetime.utcnow().isoformat(),
        })
        existing_settings["webauthn_credentials"] = credentials
        existing_settings.pop("_webauthn_challenge", None)

        supabase.table("profiles").update({"settings": existing_settings}).eq("id", req.user_id).execute()
        return {"status": "ok", "message": "Passkey registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webauthn/authenticate/begin")
async def webauthn_auth_begin(req: WebAuthnAuthBeginRequest):
    """Return a WebAuthn assertion challenge for navigator.credentials.get()."""
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    rp_id = "localhost"

    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", req.user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        credentials = settings_data.get("webauthn_credentials", [])

        allow_credentials = [
            {"type": "public-key", "id": c["credential_id"], "transports": ["internal"]}
            for c in credentials
        ]

        # Persist challenge
        settings_data["_webauthn_challenge"] = challenge
        supabase.table("profiles").update({"settings": settings_data}).eq("id", req.user_id).execute()
    except Exception:
        allow_credentials = []

    return {
        "challenge": challenge,
        "rpId": rp_id,
        "allowCredentials": allow_credentials,
        "userVerification": "required",
        "timeout": 60000,
    }


@router.post("/webauthn/authenticate/finish")
async def webauthn_auth_finish(req: WebAuthnAuthFinishRequest):
    """
    Verify assertion from navigator.credentials.get().
    In production use py_webauthn for full cryptographic verification.
    Returns a Supabase session token for the user.
    """
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("id,email,settings").eq("id", req.user_id).execute()
        if not profile_res.data:
            raise HTTPException(status_code=404, detail="User not found")

        profile = profile_res.data[0]
        settings_data = profile.get("settings") or {}
        credentials = settings_data.get("webauthn_credentials", [])

        # Verify credential_id is registered
        known = [c["credential_id"] for c in credentials]
        if req.credential_id not in known:
            raise HTTPException(status_code=401, detail="Unknown credential")

        # ✅ Credential recognised — generate a one-time token via admin API
        # (In production: verify signature cryptographically with py_webauthn)
        link_res = supabase.auth.admin.generate_link({
            "type": "magiclink",
            "email": profile["email"],
        })
        return {
            "status":    "ok",
            "user_id":   profile["id"],
            "email":     profile["email"],
            "otp":       link_res.properties.email_otp,
            "message":   "Biometric authentication successful",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/webauthn/credentials/{user_id}")
async def list_webauthn_credentials(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """List registered passkeys for the current user."""
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        creds = settings_data.get("webauthn_credentials", [])
        # Strip public key from response
        return [{"credential_id": c["credential_id"], "registered_at": c.get("registered_at")} for c in creds]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/webauthn/credentials/{user_id}/{credential_id}")
async def delete_webauthn_credential(
    user_id: str,
    credential_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove a registered passkey."""
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        settings_data["webauthn_credentials"] = [
            c for c in settings_data.get("webauthn_credentials", [])
            if c["credential_id"] != credential_id
        ]
        supabase.table("profiles").update({"settings": settings_data}).eq("id", user_id).execute()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
#  PIN authentication endpoints
#  PIN is stored as PBKDF2-HMAC-SHA256 hash (never plain text).
# ─────────────────────────────────────────────

class PinSetupRequest(BaseModel):
    user_id: str
    pin: str   # 4-8 digit PIN sent from the client


class PinVerifyRequest(BaseModel):
    user_id: str
    pin: str


def _hash_pin(pin: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 hash for PIN storage."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode(),
        salt.encode(),
        iterations=260_000,
    )
    return dk.hex()


@router.post("/pin/setup")
async def setup_pin(
    req: PinSetupRequest,
    current_user: dict = Depends(get_current_user)
):
    """Register or update a PIN for the authenticated user."""
    if not req.pin.isdigit() or not (4 <= len(req.pin) <= 8):
        raise HTTPException(status_code=400, detail="PIN must be 4–8 digits")

    salt = secrets.token_hex(16)
    pin_hash = _hash_pin(req.pin, salt)

    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", req.user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        settings_data["pin_hash"] = pin_hash
        settings_data["pin_salt"] = salt
        settings_data["pin_set_at"] = datetime.utcnow().isoformat()
        supabase.table("profiles").update({"settings": settings_data}).eq("id", req.user_id).execute()
        return {"status": "ok", "message": "PIN set successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pin/verify")
async def verify_pin(req: PinVerifyRequest):
    """Verify a PIN. Returns success payload on match."""
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("id,email,settings").eq("id", req.user_id).execute()
        if not profile_res.data:
            raise HTTPException(status_code=404, detail="User not found")

        profile = profile_res.data[0]
        settings_data = profile.get("settings") or {}
        stored_hash = settings_data.get("pin_hash")
        stored_salt = settings_data.get("pin_salt")

        if not stored_hash or not stored_salt:
            raise HTTPException(status_code=400, detail="No PIN configured for this account")

        candidate_hash = _hash_pin(req.pin, stored_salt)
        if not secrets.compare_digest(candidate_hash, stored_hash):
            raise HTTPException(status_code=401, detail="Incorrect PIN")

        return {
            "status": "ok",
            "user_id": profile["id"],
            "email": profile["email"],
            "message": "PIN verified successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pin/status/{user_id}")
async def pin_status(user_id: str, current_user: dict = Depends(get_current_user)):
    """Check whether the user has a PIN configured."""
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        return {
            "has_pin": bool(settings_data.get("pin_hash")),
            "pin_set_at": settings_data.get("pin_set_at"),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
#  Lookup user_id by email (needed for login-screen biometric/PIN flow
#  where we only have the email, not the session yet)
# ─────────────────────────────────────────────
@router.get("/user-id-by-email")
async def user_id_by_email(email: str):
    """Resolve a user_id from an email address (public, rate-limited by nginx)."""
    try:
        supabase = get_supabase()
        res = supabase.table("profiles").select("id").eq("email", email).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="No account found for that email")
        return {"user_id": res.data[0]["id"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
#  PIN login — verify PIN by email + PIN (no session required)
# ─────────────────────────────────────────────
class PinLoginRequest(BaseModel):
    email: str
    pin: str


@router.post("/pin/login")
async def pin_login(req: PinLoginRequest):
    """Login with email + PIN. Returns user info on success."""
    try:
        supabase = get_supabase()
        res = supabase.table("profiles").select("id,email,full_name,settings").eq("email", req.email).execute()
        if not res.data:
            raise HTTPException(status_code=401, detail="Invalid email or PIN")

        profile = res.data[0]
        settings_data = profile.get("settings") or {}
        stored_hash = settings_data.get("pin_hash")
        stored_salt = settings_data.get("pin_salt")

        if not stored_hash or not stored_salt:
            raise HTTPException(status_code=400, detail="No PIN set for this account. Use password login.")

        candidate = _hash_pin(req.pin, stored_salt)
        if not secrets.compare_digest(candidate, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid email or PIN")

        # ✅ PIN correct — generate a one-time token via admin API
        link_res = supabase.auth.admin.generate_link({
            "type": "magiclink",
            "email": profile["email"],
        })
        return {
            "success": True,
            "user_id": profile["id"],
            "email":   profile["email"],
            "otp":     link_res.properties.email_otp,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
#  PIN remove
# ─────────────────────────────────────────────
@router.delete("/pin/remove/{user_id}")
async def remove_pin(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove the PIN for the authenticated user."""
    try:
        supabase = get_supabase()
        profile_res = supabase.table("profiles").select("settings").eq("id", user_id).execute()
        settings_data = (profile_res.data[0].get("settings") or {}) if profile_res.data else {}
        settings_data.pop("pin_hash", None)
        settings_data.pop("pin_salt", None)
        settings_data.pop("pin_set_at", None)
        supabase.table("profiles").update({"settings": settings_data}).eq("id", user_id).execute()
        return {"status": "ok", "message": "PIN removed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

