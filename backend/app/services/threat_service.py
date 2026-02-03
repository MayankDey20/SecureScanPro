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
                
                threats_data = await provider.fetch_latest_threats(limit=20)
                
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


    async def _upsert_threat(self, threat_data: Dict):
        """Insert or Update threat in Supabase"""
        # Check if exists by CVE ID
        existing = self.supabase.table("threats").select("id").eq("cve_id", threat_data["cve_id"]).execute()
        
        if existing.data:
            # Update (optional: usually CVEs don't change much, but updated describes happen)
            # For now, we update basic fields that might change
            self.supabase.table("threats").update({
                "description": threat_data["description"],
                "cvss_score": threat_data["cvss_score"],
                "references": threat_data["references"],
                "updated_at": datetime.utcnow().isoformat()
            }).eq("cve_id", threat_data["cve_id"]).execute()
        else:
            # Insert
            # Ensure ID is generated if not provided
            if "id" not in threat_data:
                import uuid
                threat_data["id"] = str(uuid.uuid4())
            
            # Ensure optional fields have defaults
            if "exploit_available" not in threat_data:
                threat_data["exploit_available"] = False
            
            if "synced_at" not in threat_data:
                threat_data["synced_at"] = datetime.utcnow().isoformat()

            self.supabase.table("threats").insert(threat_data).execute()

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


