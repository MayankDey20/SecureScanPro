import httpx
import logging
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class VulnScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'SecureScan-Pro/1.0 (Security Scanner)'
        }
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform basic active vulnerability scanning
        """
        results = {
            "sqli_detected": False,
            "xss_detected": False,
            "findings": []
        }
        
        target = self._ensure_protocol(target)
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # 1. Basic SQLi Probe (Error-based)
            sqli_payloads = ["'", "\"", " OR 1=1"]
            for payload in sqli_payloads:
                try:
                    # Append to URL
                    test_url = f"{target}{payload}"
                    resp = await client.get(test_url, headers=self.headers)
                    if any(error in resp.text.lower() for error in ['sql syntax', 'mysql_fetch', 'ora-01756']):
                        results['findings'].append({
                            "type": "SQL Injection",
                            "severity": "High",
                            "detail": f"Potential SQL error detected with payload: {payload}",
                            "location": test_url
                        })
                        results['sqli_detected'] = True
                        break # Stop after first positive
                except Exception:
                    pass

            # 2. Basic XSS Probe (Reflected)
            xss_payload = "<script>alert('scan')</script>"
            try:
                # Add as generic query param ?q=
                test_url = f"{target}?q={xss_payload}"
                resp = await client.get(test_url, headers=self.headers)
                if xss_payload in resp.text:
                   results['findings'].append({
                        "type": "Reflected XSS",
                        "severity": "High",
                        "detail": "XSS payload reflected in response",
                        "location": test_url
                    })
                   results['xss_detected'] = True
            except Exception:
                pass

        return {
            "status": "completed",
            "scanner": "vuln_active",
            "data": results
        }

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
