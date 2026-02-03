# SecureScan Pro - Security Best Practices

## Legal & Ethical Guidelines

### ⚠️ CRITICAL: Authorized Use Only

**SecureScan Pro MUST ONLY be used for:**
- ✅ Websites you own
- ✅ Systems you have explicit written permission to test
- ✅ Bug bounty programs with clear rules of engagement
- ✅ Educational purposes in controlled environments

**NEVER use this tool for:**
- ❌ Unauthorized penetration testing
- ❌ Attacking third-party systems
- ❌ Malicious activities
- ❌ Testing without proper authorization

### Legal Compliance

- Obtain written permission before scanning any system
- Comply with local laws and regulations (CFAA, GDPR, etc.)
- Respect robots.txt and security.txt files
- Follow responsible disclosure practices
- Maintain audit logs of all scanning activities

## Application Security

### 1. Authentication & Authorization

**JWT Token Security:**
```python
# Strong secret keys (minimum 32 characters)
SECRET_KEY = os.getenv('SECRET_KEY')  # Never hardcode!
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Token validation
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

**API Key Management:**
```python
# Generate secure API keys
import secrets
api_key = secrets.token_urlsafe(32)

# Hash before storage
hashed_key = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt())

# Implement key rotation
API_KEY_ROTATION_DAYS = 90
```

**Role-Based Access Control (RBAC):**
```python
class UserRole(enum.Enum):
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

def require_role(required_role: UserRole):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = get_current_user()
            if user.role != required_role:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

### 2. Input Validation & Sanitization

**Pydantic Schema Validation:**
```python
from pydantic import BaseModel, HttpUrl, validator

class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: str
    
    @validator('scan_type')
    def validate_scan_type(cls, v):
        allowed_types = ['full', 'quick', 'custom']
        if v not in allowed_types:
            raise ValueError(f'scan_type must be one of {allowed_types}')
        return v
    
    @validator('target_url')
    def validate_url(cls, v):
        # Prevent scanning internal/private networks
        if v.host in ['localhost', '127.0.0.1', '0.0.0.0']:
            raise ValueError('Cannot scan localhost')
        if v.host.startswith('192.168.') or v.host.startswith('10.'):
            raise ValueError('Cannot scan private networks')
        return v
```

**SQL Injection Prevention:**
```python
# ALWAYS use parameterized queries
# ✅ GOOD
result = await db.execute(
    "SELECT * FROM scans WHERE user_id = :user_id",
    {"user_id": user_id}
)

# ❌ BAD - Never do this!
# result = await db.execute(f"SELECT * FROM scans WHERE user_id = {user_id}")
```

**XSS Prevention:**
```python
from html import escape

def sanitize_output(text: str) -> str:
    """Escape HTML to prevent XSS"""
    return escape(text)

# In API responses
return {
    "message": sanitize_output(user_input)
}
```

### 3. Rate Limiting

**Implementation:**
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/scan/start")
@limiter.limit("10/minute")
async def start_scan(request: Request):
    # Endpoint logic
    pass

# Per-user rate limiting
@limiter.limit("60/minute", key_func=lambda: get_current_user().id)
async def user_endpoint():
    pass
```

**Redis-based Rate Limiting:**
```python
async def check_rate_limit(user_id: str, limit: int, window: int):
    """
    Check if user has exceeded rate limit
    
    Args:
        user_id: User identifier
        limit: Maximum requests allowed
        window: Time window in seconds
    """
    key = f"rate_limit:{user_id}"
    current = await redis.incr(key)
    
    if current == 1:
        await redis.expire(key, window)
    
    if current > limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
```

### 4. Secure Configuration

**Environment Variables:**
```bash
# NEVER commit .env files to version control
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.env" >> .gitignore

# Use strong, unique secrets
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
DATABASE_PASSWORD=$(openssl rand -base64 24)
```

**Configuration Management:**
```python
from pydantic import BaseSettings, SecretStr

class Settings(BaseSettings):
    # Secrets are SecretStr to prevent accidental logging
    secret_key: SecretStr
    jwt_secret_key: SecretStr
    database_password: SecretStr
    
    # Public configuration
    api_workers: int = 4
    debug: bool = False
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()
```

### 5. Database Security

**Connection Security:**
```python
# Use SSL for database connections
DATABASE_URL = "postgresql://user:pass@host:5432/db?sslmode=require"

# Connection pooling with limits
engine = create_async_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,  # Verify connections
    pool_recycle=3600,   # Recycle connections every hour
)
```

**Encryption at Rest:**
```sql
-- Enable PostgreSQL encryption
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET archive_mode = on;

-- Encrypt sensitive columns
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Store encrypted data
INSERT INTO users (email, password) 
VALUES ('user@example.com', crypt('password', gen_salt('bf')));
```

**Row-Level Security:**
```sql
-- Enable RLS
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY user_scans_policy ON scans
    FOR ALL
    USING (user_id = current_user_id());
```

### 6. API Security Headers

**FastAPI Middleware:**
```python
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response
```

### 7. Logging & Monitoring

**Secure Logging:**
```python
import logging
import json

# Don't log sensitive data
def sanitize_log_data(data: dict) -> dict:
    """Remove sensitive fields from logs"""
    sensitive_fields = ['password', 'token', 'api_key', 'secret']
    return {
        k: '***REDACTED***' if k in sensitive_fields else v
        for k, v in data.items()
    }

# Structured logging
logger.info(
    "scan_started",
    extra={
        "scan_id": scan_id,
        "target": sanitize_url(target),
        "user_id": user_id
    }
)
```

**Audit Trail:**
```python
async def log_audit_event(
    user_id: str,
    action: str,
    resource: str,
    result: str
):
    """Log security-relevant events"""
    await db.execute(
        """
        INSERT INTO audit_log (user_id, action, resource, result, ip_address, timestamp)
        VALUES (:user_id, :action, :resource, :result, :ip, NOW())
        """,
        {
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "result": result,
            "ip": get_client_ip()
        }
    )
```

### 8. Dependency Security

**Regular Updates:**
```bash
# Check for vulnerabilities
pip install safety
safety check

# Update dependencies
pip list --outdated
pip install -U package_name

# Use Dependabot (GitHub)
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/backend"
    schedule:
      interval: "weekly"
```

**Lock Dependencies:**
```bash
# Generate requirements with exact versions
pip freeze > requirements.txt

# Use pip-tools for better management
pip install pip-tools
pip-compile requirements.in
```

### 9. Secrets Management

**AWS Secrets Manager:**
```python
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name: str) -> dict:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except ClientError as e:
        logger.error(f"Failed to retrieve secret: {e}")
        raise
```

**HashiCorp Vault:**
```python
import hvac

client = hvac.Client(url='https://vault.example.com')
client.token = os.getenv('VAULT_TOKEN')

secret = client.secrets.kv.v2.read_secret_version(
    path='securescan/database'
)
db_password = secret['data']['data']['password']
```

### 10. Incident Response

**Detection:**
```python
# Detect suspicious activity
async def detect_anomalies(user_id: str):
    # Check for unusual scan patterns
    recent_scans = await get_recent_scans(user_id, hours=1)
    
    if len(recent_scans) > 100:
        await alert_security_team(
            f"User {user_id} initiated {len(recent_scans)} scans in 1 hour"
        )
    
    # Check for privilege escalation attempts
    failed_auth_attempts = await count_failed_auth(user_id, hours=24)
    if failed_auth_attempts > 10:
        await lock_account(user_id)
```

**Automated Response:**
```python
async def handle_security_incident(incident_type: str, details: dict):
    # Log incident
    logger.critical(f"Security incident: {incident_type}", extra=details)
    
    # Send alerts
    await send_pagerduty_alert(incident_type, details)
    await send_slack_alert(incident_type, details)
    
    # Take action
    if incident_type == "brute_force":
        await block_ip(details['ip_address'])
    elif incident_type == "sql_injection":
        await quarantine_request(details['request_id'])
```

## Deployment Security

### Docker Security

```dockerfile
# Use official, minimal base images
FROM python:3.11-slim

# Run as non-root user
RUN useradd -m -u 1000 app
USER app

# Read-only filesystem where possible
VOLUME /app/data
RUN chmod -R 555 /app

# Scan for vulnerabilities
# Use: docker scan securescan-api
```

### Network Security

**Firewall Rules:**
```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

**Network Segmentation:**
```yaml
# docker-compose.yml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access

services:
  api:
    networks:
      - frontend
      - backend
  
  postgres:
    networks:
      - backend  # Only internal access
```

## Security Checklist

### Pre-Deployment

- [ ] All secrets stored securely (not in code)
- [ ] Environment variables properly configured
- [ ] SSL/TLS certificates valid and configured
- [ ] Database encrypted at rest and in transit
- [ ] Strong password policies enforced
- [ ] Rate limiting configured
- [ ] Input validation on all endpoints
- [ ] Output encoding for XSS prevention
- [ ] SQL injection protection verified
- [ ] CSRF protection enabled
- [ ] Security headers configured
- [ ] Dependency vulnerabilities checked
- [ ] Docker images scanned for vulnerabilities
- [ ] Firewall rules configured
- [ ] Monitoring and alerting set up
- [ ] Incident response plan documented
- [ ] Backup and recovery procedures tested

### Post-Deployment

- [ ] Regular security updates applied
- [ ] Penetration testing performed
- [ ] Security logs reviewed weekly
- [ ] Access controls audited monthly
- [ ] Disaster recovery tested quarterly
- [ ] Security training completed
- [ ] Compliance requirements met
- [ ] Third-party audits scheduled

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email: security@securescan.pro
3. Include detailed description and steps to reproduce
4. Allow 90 days for remediation before public disclosure

**Bug Bounty:**
- In scope: API, web application, infrastructure
- Out of scope: DoS, social engineering, physical attacks
- Rewards: $100 - $10,000 based on severity

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Security Resources](https://www.sans.org/security-resources/)

---

**Security is everyone's responsibility. Stay vigilant!**
