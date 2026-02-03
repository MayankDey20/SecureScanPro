import httpx
import logging
from typing import Dict, Any
from app.services.providers.base import ScanProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

class ShodanProvider(ScanProvider):
    """Shodan API Provider"""
    
    BASE_URL = "https://api.shodan.io"
    
    async def get_provider_name(self) -> str:
        return "Shodan"
    
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Check exposed services for an IP"""
        if not settings.SHODAN_API_KEY:
            logger.warning("Shodan API key not configured")
            return {"error": "API key missing"}
            
        try:
            async with httpx.AsyncClient() as client:
                # Shodan Host API
                url = f"{self.BASE_URL}/shodan/host/{target}?key={settings.SHODAN_API_KEY}"
                response = await client.get(url, timeout=10.0)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "provider": "Shodan",
                        "ip": data.get("ip_str"),
                        "os": data.get("os"),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", [])
                    }
                elif response.status_code == 404:
                     return {"provider": "Shodan", "message": "IP not found in Shodan database"}
                else:
                    logger.error(f"Shodan API error: {response.status_code}")
                    return {"provider": "Shodan", "error": f"API Error: {response.text}"}
                    
        except Exception as e:
            logger.error(f"Shodan scan failed: {e}")
            return {"provider": "Shodan", "error": str(e)}
