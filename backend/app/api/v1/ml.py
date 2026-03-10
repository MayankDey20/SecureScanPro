"""
ML Threat Detection API — SecureScan Pro
==========================================
All new endpoints, all under /api/v1/ml.
Zero modifications to existing routers.

Endpoints:
  POST /api/v1/ml/train              — trigger model retrain (async via Celery)
  GET  /api/v1/ml/status             — model info + last training metadata
  POST /api/v1/ml/analyze/{scan_id}  — run ML analysis on a specific scan
  POST /api/v1/ml/analyze/inline     — run ML analysis on a raw scan payload
  GET  /api/v1/ml/forecast           — get cached or live attack forecast
  GET  /api/v1/ml/anomalies          — list recent scans flagged as anomalous
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.dependencies import get_current_user
from app.services.ml_threat_service import get_ml_service, MODEL_DIR, ISO_FOREST_PATH, XGB_MODEL_PATH, LSTM_MODEL_PATH
from app.core.supabase_client import get_supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ml", tags=["ml"])


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────

class TrainRequest(BaseModel):
    days: int = 90          # how many days of historical data to use


class InlineAnalyzeRequest(BaseModel):
    scan: Dict[str, Any]    # raw scan record (same shape as DB row)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _model_info() -> Dict[str, Any]:
    """Return metadata about each persisted model file."""
    info = {}
    for name, path in [
        ("isolation_forest", ISO_FOREST_PATH),
        ("xgboost",          XGB_MODEL_PATH),
        ("lstm_forecaster",  LSTM_MODEL_PATH),
    ]:
        if path.exists():
            stat = path.stat()
            info[name] = {
                "trained": True,
                "size_kb": round(stat.st_size / 1024, 1),
                "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        else:
            info[name] = {"trained": False}
    return info


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/train")
async def trigger_training(
    body: TrainRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Enqueue a background Celery task to retrain all ML models.
    Returns the Celery task ID immediately (non-blocking).
    """
    try:
        from app.tasks.ml_tasks import train_ml_models
        task = train_ml_models.apply_async(kwargs={"days": body.days})
        return {
            "task_id": task.id,
            "status": "queued",
            "message": f"Model training queued using last {body.days} days of data",
        }
    except Exception as e:
        logger.exception(f"[ML API] Train trigger failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def model_status(current_user: dict = Depends(get_current_user)):
    """
    Return info about each trained model — whether it exists,
    its size, and when it was last trained.
    """
    return {
        "models": _model_info(),
        "model_dir": str(MODEL_DIR),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/analyze/{scan_id}")
async def analyze_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Run ML analysis (anomaly detection + threat classification + forecast)
    on an existing scan by its ID.  Result is stored back to the DB.
    """
    try:
        from app.tasks.ml_tasks import run_ml_analysis_for_scan
        task = run_ml_analysis_for_scan.apply_async(args=[scan_id])
        return {
            "task_id": task.id,
            "scan_id": scan_id,
            "status": "queued",
            "message": "ML analysis queued — check scan record for ml_analysis field",
        }
    except Exception as e:
        logger.exception(f"[ML API] Analyze failed for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/inline")
async def analyze_inline(
    body: InlineAnalyzeRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Run ML analysis synchronously on a raw scan dict (no DB lookup needed).
    Useful for testing or analysing scans that haven't been persisted yet.
    """
    try:
        svc = get_ml_service()
        result = svc.full_analysis(body.scan)
        return result
    except Exception as e:
        logger.exception(f"[ML API] Inline analyze failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/forecast")
async def get_forecast(
    horizon_days: int = Query(default=7, ge=1, le=30),
    current_user: dict = Depends(get_current_user),
):
    """
    Return the ML attack volume forecast.
    Tries Redis cache first, then runs forecast live.
    """
    try:
        from app.core.config import settings

        # Try Redis cache first (populated by Celery task)
        try:
            import redis as redis_lib
            r = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
            cached = r.get("ml:threat_forecast")
            if cached:
                data = json.loads(cached)
                data["source"] = "cache"
                return data
        except Exception:
            pass

        # Live fallback
        svc = get_ml_service()
        result = svc.forecast_attacks(horizon_days=horizon_days)
        result["source"] = "live"
        return result

    except Exception as e:
        logger.exception(f"[ML API] Forecast failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomalies")
async def list_recent_anomalies(
    days: int = Query(default=30, ge=1, le=180),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    """
    Fetch recent completed scans, run Isolation Forest on each,
    and return those flagged as anomalous.
    """
    try:
        sb = get_supabase()
        svc = get_ml_service()
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        result = (
            sb.table("scans")
            .select("id,target,status,result,created_at,completed_at,ml_analysis")
            .eq("status", "completed")
            .gte("created_at", since)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        anomalies = []
        for scan in (result.data or []):
            # Use stored ml_analysis if available, otherwise run live
            stored = scan.get("ml_analysis") or {}
            anomaly_info = stored.get("anomaly_detection") or svc.detect_anomaly(scan)
            if anomaly_info.get("anomaly"):
                anomalies.append({
                    "scan_id":       scan.get("id"),
                    "target":        scan.get("target"),
                    "created_at":    scan.get("created_at"),
                    "anomaly_score": anomaly_info.get("anomaly_score"),
                    "interpretation":anomaly_info.get("interpretation"),
                    "threat_class":  (stored.get("threat_classification") or {}).get("threat_class"),
                })

        anomalies.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
        return {
            "anomalies": anomalies,
            "total": len(anomalies),
            "scans_checked": len(result.data or []),
            "days_window": days,
        }

    except Exception as e:
        logger.exception(f"[ML API] Anomaly list failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def ml_summary(current_user: dict = Depends(get_current_user)):
    """
    Dashboard-ready summary: model status + latest forecast + anomaly count.
    """
    try:
        svc = get_ml_service()
        forecast = svc.forecast_attacks(horizon_days=7)
        models   = _model_info()
        trained  = sum(1 for m in models.values() if m.get("trained"))

        return {
            "models_trained": trained,
            "models_total":   len(models),
            "forecast_7d":    forecast.get("forecast", []),
            "forecast_trend": forecast.get("trend", "unknown"),
            "models":         models,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception(f"[ML API] Summary failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
