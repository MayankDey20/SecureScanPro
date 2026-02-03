import httpx
import logging
from typing import Dict, Any
import base64
from app.services.providers.base import ScanProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalProvider(ScanProvider):
    """VirusTotal API Provider"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    async def get_provider_name(self) -> str:
        return "VirusTotal"
    
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Check URL/Domain/IP reputation"""
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key missing"}
            
        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY
        }
        
        try:
            async with httpx.AsyncClient() as client:
                # Detect if target is IP or URL
                import re
                is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
                
                if is_ip:
                    url = f"{self.BASE_URL}/ip_addresses/{target}"
                    response = await client.get(url, headers=headers, timeout=10.0)
                else:
                    # Assume domain
                    url = f"{self.BASE_URL}/domains/{target}"
                    response = await client.get(url, headers=headers, timeout=10.0)
                
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    return {
                        "provider": "VirusTotal",
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "reputation": data.get('reputation', 0),
                        "tags": data.get('tags', [])
                    }
                elif response.status_code == 404:
                     return {"provider": "VirusTotal", "message": "Target not found in VT database"}
                else:
                    return {"provider": "VirusTotal", "error": f"API Error: {response.text}"}
                    
        except Exception as e:
            logger.error(f"VirusTotal scan failed: {e}")
            return {"provider": "VirusTotal", "error": str(e)}
