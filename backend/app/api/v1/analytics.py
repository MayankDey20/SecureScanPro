from fastapi import APIRouter
from app.core.supabase_client import get_supabase
from typing import Dict, Any, List

router = APIRouter(prefix="/analytics", tags=["analytics"])

@router.get("/trends")
async def get_trends(period: str = "30d") -> Dict[str, Any]:
    """
    Get security trends based on scan history.
    """
    sb = get_supabase()
    
    # Fetch recent scans
    # In a real app we'd filter by date 'period', here we just take last 50
    result = sb.table("scans").select("created_at, security_score, id").order("created_at", desc=True).limit(50).execute()
    scans = result.data or []
    
    # Reverse to show chronological order for trends
    scans.reverse()
    
    scores = [s.get("security_score", 0) or 0 for s in scans]
    
    return {
        "period": period,
        "labels": [s["created_at"][:10] for s in scans], # Dates
        "securityScores": scores,
        "scanCounts": len(scans)
    }
