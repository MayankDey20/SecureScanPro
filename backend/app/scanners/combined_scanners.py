import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ApiScanner:
    async def scan(self, target: str) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        endpoints = [
            '/api', '/api/v1', '/swagger.json', '/openapi.json', 
            '/docs', '/redoc', '/graphql', '/graphiql'
        ]
        
        found_endpoints = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for endpoint in endpoints:
                url = f"{target.rstrip('/')}{endpoint}"
                try:
                    resp = await client.get(url)
                    if resp.status_code in [200, 401, 403]:
                        found_endpoints.append({
                            "path": endpoint,
                            "status": resp.status_code,
                            "url": url
                        })
                except Exception:
                    continue
                    
        return {
            "status": "completed",
            "scanner": "api_discovery",
            "data": {"endpoints": found_endpoints}
        }

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target

class AuthScanner:
    async def scan(self, target: str) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        # Check for administrative paths explicitly without auth
        sensitive_paths = ['/admin', '/dashboard', '/profile', '/settings', '/config']
        
        findings = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for path in sensitive_paths:
                url = f"{target.rstrip('/')}{path}"
                try:
                    resp = await client.get(url, follow_redirects=False)
                    # If we get a 200 OK on /admin without auth, that's bad (usually). 
                    # Or if we don't get redirected to login (302).
                    if resp.status_code == 200:
                        # Simple heuristic: check if page looks like a login page
                        if 'login' not in resp.text.lower() and 'sign in' not in resp.text.lower():
                             findings.append({
                                "type": "Unprotected Sensitive Path",
                                "severity": "Medium",
                                "path": path,
                                "status": resp.status_code
                            })
                except Exception:
                    continue
        
        return {
            "status": "completed",
            "scanner": "auth_check",
            "data": {"findings": findings}
        }
    
    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target

class ContentScanner:
    async def scan(self, target: str) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        findings = []
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            try:
                resp = await client.get(target)
                text = resp.text.lower()
                
                # Check for sensitive keywords
                keywords = ['api_key', 'aws_access_key', 'private_key', 'password="']
                for kw in keywords:
                    if kw in text:
                        findings.append({
                            "type": "Sensitive Information Leak",
                            "severity": "High",
                            "detail": f"Found sensitive keyword: {kw}"
                        })
                
                # Check for valid emails (simple regex or heuristic)
                if 'mailto:' in text:
                     findings.append({
                        "type": "Email Exposure",
                        "severity": "Info",
                        "detail": "Email addresses found in source"
                    })
                    
            except Exception as e:
                pass
                
        return {
            "status": "completed",
            "scanner": "content_inspection",
            "data": {"findings": findings}
        }

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
