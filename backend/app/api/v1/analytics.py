from fastapi import APIRouter
from app.core.supabase_client import get_supabase
from typing import Dict, Any
from collections import defaultdict

router = APIRouter(prefix="/analytics", tags=["analytics"])

@router.get("/trends")
async def get_trends(period: str = "30d") -> Dict[str, Any]:
    """
    Get security trends based on scan history.
    Aggregates multiple scans per day into a single averaged data point.
    """
    sb = get_supabase()

    result = sb.table("scans").select("created_at, security_score, id, status").order("created_at", desc=False).limit(200).execute()
    scans = result.data or []

    # ── aggregate by date ──────────────────────────────────
    day_scores: Dict[str, list] = defaultdict(list)
    day_counts: Dict[str, int]  = defaultdict(int)
    day_vulns: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})

    for s in scans:
        date_key = (s.get("created_at") or "")[:10]   # "2026-02-21"
        if not date_key:
            continue
        
        # Security Score
        score = s.get("security_score")
        if score is not None:
            day_scores[date_key].append(score)
        
        # Scan Count
        day_counts[date_key] += 1
        
        # Vulnerabilities by day
        vc = s.get("vulnerabilities_count")
        if isinstance(vc, dict):
            for k in day_vulns[date_key]:
                day_vulns[date_key][k] += int(vc.get(k, 0))
        elif isinstance(vc, (int, float)):
            day_vulns[date_key]["medium"] += int(vc)

    # Sort by date
    sorted_dates = sorted(set(list(day_scores.keys()) + list(day_counts.keys()) + list(day_vulns.keys())))

    # Average score per day
    avg_scores = [
        round(sum(day_scores[d]) / len(day_scores[d])) if day_scores[d] else 0
        for d in sorted_dates
    ]

    scans_per_day = [day_counts[d] for d in sorted_dates]
    
    # Vulnerabilities by day array for frontend bars
    vulns_per_day = [day_vulns[d] for d in sorted_dates]

    # Overall vuln distribution 
    vuln_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in sorted_dates:
        for k in vuln_dist:
            vuln_dist[k] += day_vulns[d][k]

    # Top assets (already mostly correct, but let's ensure it uses day_vulns or similar logic if needed)
    asset_counts: Dict[str, int] = defaultdict(int)
    for s in scans:
        vc = s.get("vulnerabilities_count")
        target = s.get("target_url") or "unknown"
        count = 0
        if isinstance(vc, dict):
            count = sum(int(v) for v in vc.values())
        elif isinstance(vc, (int, float)):
            count = int(vc)
        if count > 0:
            asset_counts[target] += count

    top_assets = sorted(
        [{"name": k, "count": v} for k, v in asset_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:5]

    return {
        "period":                   period,
        "labels":                   sorted_dates,
        "securityScores":           avg_scores,
        "scansByDay":               scans_per_day,
        "vulnerabilitiesByDay":     vulns_per_day,
        "scanCounts":               len(scans),
        "vulnerabilityDistribution": vuln_dist,
        "topAssets":                top_assets,
    }
