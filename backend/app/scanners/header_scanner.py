import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class HeaderScanner:
    """Security Headers Scanner"""
    
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "Enforces HTTPS connections.",
            "severity": "Medium"
        },
        "Content-Security-Policy": {
            "description": "Mitigates XSS and data injection attacks.",
            "severity": "High"
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks.",
            "severity": "Medium"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing.",
            "severity": "Low"
        },
        "Referrer-Policy": {
            "description": "Controls how much referral information is shared.",
            "severity": "Low"
        },
        "Permissions-Policy": {
            "description": "Controls access to browser features.",
            "severity": "Low"
        }
    }

    async def scan(self, target_url: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        results = {
            "headers_present": {},
            "headers_missing": [],
            "vulnerabilities": [],
            "score_deduction": 0
        }
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(target_url)
                headers = response.headers
                
                # Check for each security header
                for header, info in self.SECURITY_HEADERS.items():
                    # Case insensitive check
                    found_key = next((k for k in headers.keys() if k.lower() == header.lower()), None)
                    
                    if found_key:
                        results["headers_present"][header] = headers[found_key]
                    else:
                        results["headers_missing"].append(header)
                        results["score_deduction"] += 10 if info["severity"] == "High" else 5
                        
                        results["vulnerabilities"].append({
                            "type": "missing_header",
                            "severity": info["severity"],
                            "title": f"Missing Security Header: {header}",
                            "description": f"{header} is missing. {info['description']}"
                        })
                
                # Check for information leakage headers
                leakage_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
                for header in leakage_headers:
                     found_key = next((k for k in headers.keys() if k.lower() == header.lower()), None)
                     if found_key:
                        results["vulnerabilities"].append({
                            "type": "info_leakage",
                            "severity": "Low",
                            "title": "Server Information Leakage",
                            "description": f"Server is exposing technology details via {header} header: {headers[found_key]}"
                        })
                        results["score_deduction"] += 5

        except Exception as e:
            logger.error(f"Header scan failed for {target_url}: {e}")
            results["error"] = str(e)
            
        return results
