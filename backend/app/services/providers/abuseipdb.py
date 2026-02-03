import httpx
import logging
from typing import Dict, Any
from app.services.providers.base import ScanProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

class AbuseIPDBProvider(ScanProvider):
    """AbuseIPDB API Provider"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    async def get_provider_name(self) -> str:
        return "AbuseIPDB"
    
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Check IP reputation"""
        if not settings.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured")
            return {"error": "API key missing"}
            
        try:
            headers = {
                'Key': settings.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': target,
                'maxAgeInDays': '90'
            }
            
            async with httpx.AsyncClient() as client:
                url = f"{self.BASE_URL}/check"
                response = await client.get(url, headers=headers, params=params, timeout=10.0)
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    return {
                        "provider": "AbuseIPDB",
                        "ip": data.get("ipAddress"),
                        "abuse_confidence_score": data.get("abuseConfidenceScore"),
                        "total_reports": data.get("totalReports"),
                        "last_reported": data.get("lastReportedAt"),
                        "is_whitelisted": data.get("isWhitelisted"),
                        "usage_type": data.get("usageType")
                    }
                else:
                    return {"provider": "AbuseIPDB", "error": f"API Error: {response.text}"}
                    
        except Exception as e:
            logger.error(f"AbuseIPDB scan failed: {e}")
            return {"provider": "AbuseIPDB", "error": str(e)}
