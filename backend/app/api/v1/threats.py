"""
Threat Intelligence API endpoints for Supabase
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from datetime import datetime

from app.core.supabase_client import get_supabase
from app.models.threat import Threat, ThreatCreate, ThreatStats
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=List[Threat])
async def list_threats(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    trending: Optional[bool] = None
):
    """List threats with pagination and filtering"""
    try:
        supabase = get_supabase()
        
        # Build query
        query = supabase.table("threats").select("*")
        
        if severity:
            query = query.eq("severity", severity)
        if category:
            query = query.eq("category", category)
        if trending is not None:
            query = query.eq("trending", trending)
        
        # Fetch threats
        result = query.order("published_date", desc=True).range(skip, skip + limit - 1).execute()
        
        return result.data if result.data else []
    except Exception as e:
        # Fallback for demo/development if Supabase fails (e.g. invalid keys)
        print(f"Supabase connection failed: {e}. Returning mock data.")
        from datetime import datetime
        return [
            {
                "id": "mock-1",
                "cve_id": "CVE-2024-3094",
                "title": "XZ Utils Backdoor",
                "description": "Malicious code in xz-utils liblzma results in compromised SSH access.",
                "severity": "critical",
                "published_date": datetime.utcnow().isoformat(),
                "cvss_score": 10.0,
                "category": "Supply Chain",
                "affected_products": ["xz-utils"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
                "trending": True
            },
            {
                "id": "mock-2",
                "cve_id": "CVE-2024-21413",
                "title": "Microsoft Outlook RCE",
                "description": "Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link).",
                "severity": "critical",
                "published_date": datetime.utcnow().isoformat(),
                "cvss_score": 9.8,
                "category": "RCE",
                "affected_products": ["Microsoft Outlook"],
                "trending": True
            },
            {
                "id": "mock-3",
                "cve_id": "CVE-2024-23222",
                "title": "WebKit Remote Code Execution",
                "description": "Apple WebKit Type Confusion enabling arbitrary code execution.",
                "severity": "critical",
                "published_date": datetime.utcnow().isoformat(),
                "cvss_score": 9.6,
                "category": "RCE",
                "affected_products": ["iOS", "macOS"],
                "trending": False
            }
        ]


@router.get("/{threat_id}", response_model=Threat)
async def get_threat(threat_id: str):
    """Get threat details by ID"""
    try:
        supabase = get_supabase()
        
        result = supabase.table("threats").select("*").eq("id", threat_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        return result.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat: {str(e)}")


@router.post("/sync", status_code=202)
async def sync_threats_intelligence():
    """Trigger manual threat intelligence sync from external APIs"""
    try:
        service = ThreatService()
        # In a real app, use BackgroundTasks. For this demo, we await it to see results.
        stats = await service.sync_threats()
        return {"status": "success", "message": "Threat intelligence synced", "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary", response_model=ThreatStats)
async def get_threat_stats():
    """Get threat statistics"""
    try:
        supabase = get_supabase()
        
        # Get total count
        total_result = supabase.table("threats").select("id", count="exact").execute()
        total = total_result.count if total_result.count else 0
        
        # Get counts by severity
        critical_result = supabase.table("threats").select("id", count="exact").eq("severity", "critical").execute()
        critical = critical_result.count if critical_result.count else 0
        
        high_result = supabase.table("threats").select("id", count="exact").eq("severity", "high").execute()
        high = high_result.count if high_result.count else 0
        
        medium_result = supabase.table("threats").select("id", count="exact").eq("severity", "medium").execute()
        medium = medium_result.count if medium_result.count else 0
        
        low_result = supabase.table("threats").select("id", count="exact").eq("severity", "low").execute()
        low = low_result.count if low_result.count else 0
        
        # Get trending and exploit counts
        trending_result = supabase.table("threats").select("id", count="exact").eq("trending", True).execute()
        trending = trending_result.count if trending_result.count else 0
        
        exploits_result = supabase.table("threats").select("id", count="exact").eq("exploit_available", True).execute()
        with_exploits = exploits_result.count if exploits_result.count else 0
        
        # Get category breakdown
        categories_result = supabase.table("threats").select("category").execute()
        category_breakdown = {}
        if categories_result.data:
            for threat in categories_result.data:
                cat = threat.get("category", "Unknown")
                category_breakdown[cat] = category_breakdown.get(cat, 0) + 1
        
        return ThreatStats(
            total=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            trending=trending,
            with_exploits=with_exploits,
            category_breakdown=category_breakdown
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat stats: {str(e)}")

