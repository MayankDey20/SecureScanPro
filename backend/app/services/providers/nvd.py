import httpx
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.services.providers.base import ThreatProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

class NVDProvider(ThreatProvider):
    """NIST NVD API Provider (v2.0)"""
    
    # NVD API 2.0 URL
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    async def get_provider_name(self) -> str:
        return "NVD"
    
    async def fetch_latest_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Fetch latest Critical/High vulnerabilities from NVD
        """
        threats = []
        
        # Calculate date range (last 7 days to keep it relevant)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Format dates for NVD API (ISO 8601)
        # NVD requires strict formatting: YYYY-MM-DDThh:mm:ss.000
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": limit,
            "cvssV3Severity": "CRITICAL", # Focus on critical first
            "noRejected": "true"
        }
        
        headers = {}
        # If API key is configured, add it (NVD raises rate limit with key)
        # if settings.NVD_API_KEY: 
        #     headers["apiKey"] = settings.NVD_API_KEY
            
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info(f"Fetching threats from NVD: {self.BASE_URL}")
                response = await client.get(self.BASE_URL, params=params, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    for item in vulnerabilities:
                        cve = item.get("cve", {})
                        threat = self._normalize_cve(cve)
                        if threat:
                            threats.append(threat)
                else:
                    logger.error(f"NVD API Error: {response.status_code} - {response.text}")
                    
        except Exception as e:
            logger.error(f"Failed to fetch from NVD: {str(e)}")
            
        return threats

    def _normalize_cve(self, cve: Dict) -> Dict:
        """Convert NVD CVE JSON to our internal Threat dictionary format"""
        try:
            cve_id = cve.get("id")
            
            # Extract description (English)
            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")
            
            # Extract CVSS Metrics (V3.1 preferred, then V3.0)
            metrics = cve.get("metrics", {})
            cvss_data = {}
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            
            if not cvss_data:
                # If no V3 score, might be V2 or something else, skip for now to keep high quality
                return None
                
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN").lower()
            
            # Extract published date
            published = cve.get("published", datetime.utcnow().isoformat())
            
            # Categorize based on description
            category = self._categorize_threat(description)
            
            return {
                "cve_id": cve_id,
                "title": f"{cve_id}: Critical Vulnerability", # NVD doesn't strictly have "titles" like "Log4J", so we compose it
                "description": description,
                "severity": severity,
                "cvss_score": score,
                "published_date": published,
                "category": category,
                "references": self._extract_references(cve.get("references", [])),
                "affected_products": [], # Extracting CPEs is complex, skipping for MVP
                "trending": score >= 9.0 # Assume anything > 9.0 is "trending" or critical enough
            }
        except Exception as e:
            logger.warning(f"Error normalizing CVE {cve.get('id', 'unknown')}: {e}")
            return None

    def _categorize_threat(self, description: str) -> str:
        desc = description.lower()
        if "sql" in desc or "injection" in desc: return "Injection"
        if "xss" in desc or "script" in desc: return "XSS"
        if "buffer" in desc or "overflow" in desc: return "Memory Corruption"
        if "privilege" in desc: return "Privilege Escalation"
        if "denial" in desc or "dos" in desc: return "DoS"
        if "code execution" in desc: return "RCE"
        return "Vulnerability"

    def _extract_references(self, refs: List[Dict]) -> List[str]:
        return [r.get("url") for r in refs[:3]] # Top 3 refs
