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

    for s in scans:
        date_key = (s.get("created_at") or "")[:10]   # "2026-02-21"
        if not date_key:
            continue
        score = s.get("security_score")
        if score is not None:
            day_scores[date_key].append(score)
        day_counts[date_key] += 1

    # Sort by date
    sorted_dates = sorted(set(list(day_scores.keys()) + list(day_counts.keys())))

    # Average score per day (0 if no completed scans that day)
    avg_scores = [
        round(sum(day_scores[d]) / len(day_scores[d])) if day_scores[d] else 0
        for d in sorted_dates
    ]

    scans_per_day = [day_counts[d] for d in sorted_dates]

    # Vuln distribution from all scans
    vuln_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in scans:
        vc = s.get("vulnerabilities_count")
        if isinstance(vc, dict):
            for k in vuln_dist:
                vuln_dist[k] += int(vc.get(k, 0))
        elif isinstance(vc, (int, float)):
            vuln_dist["medium"] += int(vc)

    # Top assets by finding count
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
        "scanCounts":               len(scans),
        "vulnerabilityDistribution": vuln_dist,
        "topAssets":                top_assets,
    }
