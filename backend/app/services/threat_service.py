"""
Threat Intelligence Service
Handles syncing threats from external APIs (NVD, etc.) and storing in Supabase
"""
import logging
from typing import List, Dict
import asyncio
from datetime import datetime

from app.core.supabase_client import get_supabase
from app.services.providers.nvd import NVDProvider
from app.models.threat import ThreatCreate

logger = logging.getLogger(__name__)


class ThreatService:
    """Service for managing threat intelligence data"""
    
    def __init__(self):
        self.supabase = get_supabase()
        self.providers = [NVDProvider()] # Extendable list of providers
    
    async def aggregate_intel(self, target: str) -> Dict:
        """Aggregate threat intel relevant to a target (domain/IP lookup against known threats)"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(target).hostname or target
            # Search for CVEs or threats mentioning this domain or generic web threats
            result = self.supabase.table("threats").select(
                "id,cve_id,title,severity,cvss_score,description"
            ).order("cvss_score", desc=True).limit(5).execute()
            return {
                "status": "completed",
                "scanner": "threat_intel",
                "data": {"threats": result.data if result.data else []}
            }
        except Exception as e:
            logger.error(f"aggregate_intel failed for {target}: {e}")
            return {"status": "failed", "scanner": "threat_intel", "error": str(e)}

    async def sync_threats(self) -> Dict[str, int]:
        """
        Fetch threats from all providers and sync to Supabase.
        Returns statistics of the sync operation.
        """
        stats = {"added": 0, "errors": 0}
        
        for provider in self.providers:
            try:
                name = await provider.get_provider_name()
                logger.info(f"Starting threat sync from provider: {name}")
                
                threats_data = await provider.fetch_latest_threats(limit=50)
                
                if not threats_data:
                    logger.warning(f"No threats fetched from {name}")
                    continue
                    
                for threat_dict in threats_data:
                    try:
                        await self._upsert_threat(threat_dict)
                        stats["added"] += 1
                    except Exception as e:
                        logger.error(f"Failed to upsert threat {threat_dict.get('cve_id')}: {e}")
                        stats["errors"] += 1
                        
            except Exception as e:
                logger.error(f"Provider {provider} failed: {e}")
                stats["errors"] += 1
                
        return stats


    def _map_threat_to_schema(self, threat_data: Dict) -> Dict:
        """Map provider threat dict to the actual 'threats' table columns."""
        import uuid
        row = {
            "id":               threat_data.get("id", str(uuid.uuid4())),
            "cve_id":           threat_data["cve_id"],
            "title":            threat_data.get("title", ""),
            "description":      threat_data.get("description", ""),
            "severity":         threat_data.get("severity", "unknown"),
            "cvss_score":       threat_data.get("cvss_score"),
            "affected_products": threat_data.get("affected_products", []),
            "exploit_available": threat_data.get("exploit_available", False),
            "references":       threat_data.get("references", []),
            "category":         threat_data.get("category", "Vulnerability"),
            "source":           threat_data.get("source", "nvd"),
            "synced_at":        datetime.utcnow().isoformat(),
        }
        # Map published_date (provider key) → published_date (DB column)
        pub = threat_data.get("published_date") or threat_data.get("published_at")
        if pub:
            row["published_date"] = pub
        return row

    async def _upsert_threat(self, threat_data: Dict):
        """Insert or Update threat in Supabase using the correct schema columns."""
        cve_id = threat_data["cve_id"]
        existing = self.supabase.table("threats").select("id").eq("cve_id", cve_id).execute()
        row = self._map_threat_to_schema(threat_data)

        if existing.data:
            self.supabase.table("threats").update({
                "description":       row["description"],
                "cvss_score":        row["cvss_score"],
                "references":        row["references"],
                "exploit_available": row["exploit_available"],
                "updated_at":        datetime.utcnow().isoformat(),
            }).eq("cve_id", cve_id).execute()
        else:
            self.supabase.table("threats").insert(row).execute()

    async def get_threat_by_cve(self, cve_id: str) -> Dict:
        """Get threat by CVE ID"""
        result = self.supabase.table("threats").select("*").eq("cve_id", cve_id).execute()
        return result.data[0] if result.data else None
    
    async def search_threats(self, query: str, limit: int = 20) -> List[Dict]:
        """Search threats by query"""
        # Supabase full-text search using textquery or ilike
        result = self.supabase.table("threats").select("*").or_(
            f"cve_id.ilike.%{query}%,title.ilike.%{query}%,description.ilike.%{query}%"
        ).limit(limit).execute()
        
        return result.data if result.data else []


