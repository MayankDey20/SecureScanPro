"""
Authenticated Scanning Module for SecureScan Pro
Supports various authentication methods for scanning protected pages
"""
import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
import json

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration"""
    auth_type: str  # basic, bearer, cookie, form, oauth2, api_key
    credentials: Dict[str, Any] = field(default_factory=dict)
    
    # For form-based auth
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
    success_indicator: Optional[str] = None  # Text/element that indicates successful login
    failure_indicator: Optional[str] = None
    
    # For OAuth2
    token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = None
    
    # Session management
    session_timeout: int = 1800  # 30 minutes
    re_auth_on_failure: bool = True


class AuthenticatedScanner:
    """
    Handles authentication and maintains sessions for scanning
    """
    
    def __init__(self):
        self.session_cookies: Dict[str, str] = {}
        self.auth_headers: Dict[str, str] = {}
        self.is_authenticated: bool = False
        self.auth_config: Optional[AuthConfig] = None
        
    async def authenticate(self, config: AuthConfig) -> Tuple[bool, str]:
        """
        Authenticate using the provided configuration
        Returns (success, message)
        """
        self.auth_config = config
        
        handlers = {
            "basic": self._auth_basic,
            "bearer": self._auth_bearer,
            "cookie": self._auth_cookie,
            "form": self._auth_form,
            "oauth2": self._auth_oauth2,
            "api_key": self._auth_api_key,
            "ntlm": self._auth_ntlm,
            "digest": self._auth_digest
        }
        
        handler = handlers.get(config.auth_type)
        if not handler:
            return False, f"Unsupported authentication type: {config.auth_type}"
        
        try:
            success, message = await handler(config)
            self.is_authenticated = success
            return success, message
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False, str(e)
    
    async def _auth_basic(self, config: AuthConfig) -> Tuple[bool, str]:
        """HTTP Basic Authentication"""
        import base64
        
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")
        
        if not username:
            return False, "Username is required for Basic auth"
        
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.auth_headers["Authorization"] = f"Basic {credentials}"
        
        return True, "Basic authentication configured"
    
    async def _auth_bearer(self, config: AuthConfig) -> Tuple[bool, str]:
        """Bearer Token Authentication"""
        token = config.credentials.get("token", "")
        
        if not token:
            return False, "Token is required for Bearer auth"
        
        self.auth_headers["Authorization"] = f"Bearer {token}"
        
        return True, "Bearer token configured"
    
    async def _auth_cookie(self, config: AuthConfig) -> Tuple[bool, str]:
        """Cookie-based Authentication"""
        cookies = config.credentials.get("cookies", {})
        
        if not cookies:
            return False, "Cookies are required for Cookie auth"
        
        self.session_cookies.update(cookies)
        
        return True, f"Session cookies configured: {len(cookies)} cookies"
    
    async def _auth_form(self, config: AuthConfig) -> Tuple[bool, str]:
        """Form-based Authentication (login form)"""
        if not config.login_url:
            return False, "Login URL is required for form auth"
        
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=30.0) as client:
            # First, get the login page to extract CSRF token if present
            try:
                login_page = await client.get(config.login_url)
                soup = BeautifulSoup(login_page.text, "html.parser")
                
                # Find login form
                form = soup.find("form")
                if not form:
                    return False, "No form found on login page"
                
                # Build form data
                form_data = {}
                
                # Extract all hidden fields (including CSRF tokens)
                for hidden in form.find_all("input", type="hidden"):
                    name = hidden.get("name")
                    value = hidden.get("value", "")
                    if name:
                        form_data[name] = value
                
                # Find username/password fields
                username_field = self._find_username_field(form)
                password_field = self._find_password_field(form)
                
                if username_field:
                    form_data[username_field] = username
                else:
                    # Default field names
                    for field_name in ["username", "email", "user", "login"]:
                        form_data[field_name] = username
                        break
                
                if password_field:
                    form_data[password_field] = password
                else:
                    form_data["password"] = password
                
                # Add any additional form fields from config
                extra_fields = config.credentials.get("extra_fields", {})
                form_data.update(extra_fields)
                
                # Determine form action URL
                action = form.get("action", "")
                if action:
                    submit_url = urljoin(config.login_url, action)
                else:
                    submit_url = config.login_url
                
                # Determine form method
                method = form.get("method", "post").lower()
                
                # Submit the form
                if method == "post":
                    response = await client.post(submit_url, data=form_data)
                else:
                    response = await client.get(submit_url, params=form_data)
                
                # Check for successful login
                success = await self._verify_login_success(response, config)
                
                if success:
                    # Store session cookies
                    self.session_cookies = {k: v for k, v in client.cookies.items()}
                    return True, f"Form authentication successful. {len(self.session_cookies)} session cookies obtained"
                else:
                    return False, "Login failed - success indicator not found or failure indicator detected"
                
            except Exception as e:
                logger.error(f"Form authentication error: {e}")
                return False, f"Form authentication error: {str(e)}"
    
    async def _auth_oauth2(self, config: AuthConfig) -> Tuple[bool, str]:
        """OAuth2 Client Credentials flow"""
        if not config.token_url:
            return False, "Token URL is required for OAuth2"
        
        client_id = config.client_id or config.credentials.get("client_id", "")
        client_secret = config.client_secret or config.credentials.get("client_secret", "")
        
        if not client_id or not client_secret:
            return False, "Client ID and Secret are required for OAuth2"
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            try:
                # Request access token
                data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret
                }
                
                if config.scope:
                    data["scope"] = config.scope
                
                response = await client.post(config.token_url, data=data)
                
                if response.status_code == 200:
                    token_data = response.json()
                    access_token = token_data.get("access_token")
                    
                    if access_token:
                        self.auth_headers["Authorization"] = f"Bearer {access_token}"
                        return True, "OAuth2 authentication successful"
                    else:
                        return False, "No access token in response"
                else:
                    return False, f"OAuth2 token request failed: {response.status_code}"
                    
            except Exception as e:
                return False, f"OAuth2 error: {str(e)}"
    
    async def _auth_api_key(self, config: AuthConfig) -> Tuple[bool, str]:
        """API Key Authentication"""
        api_key = config.credentials.get("api_key", "")
        header_name = config.credentials.get("header_name", "X-API-Key")
        key_prefix = config.credentials.get("prefix", "")
        
        if not api_key:
            return False, "API key is required"
        
        key_value = f"{key_prefix}{api_key}" if key_prefix else api_key
        self.auth_headers[header_name] = key_value
        
        return True, f"API key configured in header: {header_name}"
    
    async def _auth_ntlm(self, config: AuthConfig) -> Tuple[bool, str]:
        """NTLM Authentication (Windows)"""
        # Note: Full NTLM support requires httpx-ntlm or similar
        domain = config.credentials.get("domain", "")
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")
        
        if not username or not password:
            return False, "Username and password required for NTLM"
        
        # Store for use with NTLM-capable client
        self.auth_config = config
        
        return True, "NTLM credentials configured (requires NTLM-capable HTTP client)"
    
    async def _auth_digest(self, config: AuthConfig) -> Tuple[bool, str]:
        """HTTP Digest Authentication"""
        username = config.credentials.get("username", "")
        password = config.credentials.get("password", "")
        
        if not username or not password:
            return False, "Username and password required for Digest auth"
        
        # Store for httpx DigestAuth
        self.auth_config = config
        
        return True, "Digest authentication configured"
    
    def _find_username_field(self, form) -> Optional[str]:
        """Find the username/email field in a form"""
        # Look for common username field patterns
        patterns = [
            {"type": "email"},
            {"type": "text", "name": re.compile(r"(user|email|login|account)", re.I)},
            {"name": re.compile(r"(user|email|login|account)", re.I)},
            {"id": re.compile(r"(user|email|login|account)", re.I)},
            {"autocomplete": "username"},
            {"autocomplete": "email"}
        ]
        
        for pattern in patterns:
            field = form.find("input", pattern)
            if field and field.get("name"):
                return field.get("name")
        
        return None
    
    def _find_password_field(self, form) -> Optional[str]:
        """Find the password field in a form"""
        password_field = form.find("input", {"type": "password"})
        if password_field:
            return password_field.get("name", "password")
        return None
    
    async def _verify_login_success(self, response: httpx.Response, config: AuthConfig) -> bool:
        """Verify if login was successful"""
        content = response.text
        
        # Check for failure indicators
        if config.failure_indicator:
            if config.failure_indicator.lower() in content.lower():
                return False
        
        # Common failure patterns
        failure_patterns = [
            "invalid password", "incorrect password", "wrong password",
            "invalid credentials", "login failed", "authentication failed",
            "invalid username", "user not found", "account not found"
        ]
        
        content_lower = content.lower()
        for pattern in failure_patterns:
            if pattern in content_lower:
                return False
        
        # Check for success indicator
        if config.success_indicator:
            return config.success_indicator.lower() in content_lower
        
        # Common success patterns
        success_patterns = [
            "logout", "sign out", "log out", "dashboard", "welcome",
            "my account", "profile", "settings"
        ]
        
        for pattern in success_patterns:
            if pattern in content_lower:
                return True
        
        # If redirected away from login page, likely successful
        if "login" not in str(response.url).lower():
            return True
        
        return False
    
    def get_authenticated_client(self) -> httpx.AsyncClient:
        """Get an HTTP client configured with authentication"""
        return httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            headers=self.auth_headers,
            cookies=self.session_cookies,
            timeout=30.0
        )
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        return self.auth_headers.copy()
    
    def get_session_cookies(self) -> Dict[str, str]:
        """Get session cookies"""
        return self.session_cookies.copy()
    
    async def verify_session(self, check_url: str) -> bool:
        """Verify if session is still valid"""
        async with self.get_authenticated_client() as client:
            try:
                response = await client.get(check_url)
                
                # Check if redirected to login
                if "login" in str(response.url).lower():
                    return False
                
                # Check for session expiry indicators
                expiry_patterns = ["session expired", "please login", "sign in"]
                content_lower = response.text.lower()
                
                for pattern in expiry_patterns:
                    if pattern in content_lower:
                        return False
                
                return True
                
            except Exception:
                return False
    
    async def re_authenticate(self) -> Tuple[bool, str]:
        """Re-authenticate using stored config"""
        if not self.auth_config:
            return False, "No authentication configuration stored"
        
        # Clear existing auth
        self.session_cookies.clear()
        self.auth_headers.clear()
        self.is_authenticated = False
        
        return await self.authenticate(self.auth_config)


class AuthenticatedScanSession:
    """
    Manages a complete authenticated scanning session
    """
    
    def __init__(self):
        self.authenticator = AuthenticatedScanner()
        self.session_valid = False
    
    async def setup_session(self, auth_config: Dict) -> Tuple[bool, str]:
        """Setup authenticated session from config dict"""
        config = AuthConfig(
            auth_type=auth_config.get("type", ""),
            credentials=auth_config.get("credentials", {}),
            login_url=auth_config.get("login_url"),
            logout_url=auth_config.get("logout_url"),
            success_indicator=auth_config.get("success_indicator"),
            failure_indicator=auth_config.get("failure_indicator"),
            token_url=auth_config.get("token_url"),
            client_id=auth_config.get("client_id"),
            client_secret=auth_config.get("client_secret"),
            scope=auth_config.get("scope")
        )
        
        success, message = await self.authenticator.authenticate(config)
        self.session_valid = success
        
        return success, message
    
    async def make_authenticated_request(
        self, 
        url: str, 
        method: str = "GET",
        data: Dict = None,
        json_data: Dict = None,
        headers: Dict = None
    ) -> httpx.Response:
        """Make an authenticated HTTP request"""
        if not self.session_valid:
            raise Exception("Session not authenticated")
        
        async with self.authenticator.get_authenticated_client() as client:
            if headers:
                client.headers.update(headers)
            
            if method.upper() == "GET":
                return await client.get(url)
            elif method.upper() == "POST":
                return await client.post(url, data=data, json=json_data)
            elif method.upper() == "PUT":
                return await client.put(url, data=data, json=json_data)
            elif method.upper() == "DELETE":
                return await client.delete(url)
            else:
                raise ValueError(f"Unsupported method: {method}")
    
    async def crawl_authenticated(self, start_url: str, max_pages: int = 50) -> Dict:
        """Crawl pages with authentication"""
        from app.scanners.crawler import WebCrawler, CrawlConfig
        
        config = CrawlConfig(
            max_pages=max_pages,
            headers=self.authenticator.get_auth_headers(),
            cookies=self.authenticator.get_session_cookies()
        )
        
        crawler = WebCrawler(config)
        return await crawler.crawl(start_url)
    
    async def scan_authenticated(self, target: str, scan_types: List[str] = None) -> Dict:
        """Run vulnerability scan with authentication"""
        from app.scanners.nuclei_scanner import AdvancedVulnScanner
        
        scanner = AdvancedVulnScanner()
        
        # Configure scanner with auth
        if scanner.nuclei.config:
            scanner.nuclei.config.headers.update(self.authenticator.get_auth_headers())
        
        # Also configure custom checks
        scanner.custom_checks.headers.update(self.authenticator.get_auth_headers())
        
        return await scanner.scan(target, scan_types)
