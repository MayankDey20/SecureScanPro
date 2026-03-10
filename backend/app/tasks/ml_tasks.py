"""
ML Celery Tasks — SecureScan Pro
=================================
Background tasks for model training and post-scan ML analysis.
These are ADDITIVE — no existing tasks are modified.

Registered tasks:
  app.tasks.ml_tasks.train_ml_models          — full retrain (called by beat schedule)
  app.tasks.ml_tasks.run_ml_analysis_for_scan — post-scan hook
  app.tasks.ml_tasks.forecast_threat_volume   — standalone forecast task
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.celery_worker import celery_app
from app.core.supabase_client import get_supabase

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_completed_scans(days: int = 90) -> list:
    """Pull up to 2000 completed scans from the last `days` days."""
    try:
        sb = get_supabase()
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        result = (
            sb.table("scans")
            .select("id,status,result,started_at,completed_at,created_at")
            .eq("status", "completed")
            .gte("created_at", since)
            .order("created_at", desc=True)
            .limit(2000)
            .execute()
        )
        return result.data or []
    except Exception as e:
        logger.error(f"[ML] Failed to fetch scans: {e}")
        return []


def _fetch_daily_threat_counts(days: int = 60) -> list:
    """Return per-day threat counts as a plain list ordered oldest→newest."""
    try:
        sb = get_supabase()
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        result = (
            sb.table("threats")
            .select("published_date")
            .gte("published_date", since)
            .execute()
        )

        counts: dict = {}
        for row in result.data or []:
            day = (row.get("published_date") or "")[:10]
            if day:
                counts[day] = counts.get(day, 0) + 1

        today = datetime.now(timezone.utc).date()
        ordered = []
        for i in range(days - 1, -1, -1):
            d = (today - timedelta(days=i)).isoformat()
            ordered.append(counts.get(d, 0))
        return ordered
    except Exception as e:
        logger.error(f"[ML] Failed to fetch threat counts: {e}")
        return []


def _store_ml_result(scan_id: str, ml_result: Dict[str, Any]):
    """
    Persist the ML analysis result back to the `scans` table
    inside a dedicated `ml_analysis` JSON column (if it exists).
    Falls back gracefully if the column doesn't exist yet.
    """
    try:
        sb = get_supabase()
        sb.table("scans").update({"ml_analysis": ml_result}).eq("id", scan_id).execute()
    except Exception as e:
        # Column may not exist — non-fatal
        logger.debug(f"[ML] Could not persist ml_analysis for scan {scan_id}: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Task 1 — Full model retrain
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="app.tasks.ml_tasks.train_ml_models")
def train_ml_models(self, days: int = 90):
    """
    Retrain Isolation Forest, XGBoost, and LSTM from historical data.
    Typically triggered by the Celery Beat schedule (daily at 3 AM).
    Can also be triggered manually via POST /api/v1/ml/train.
    """
    logger.info("[ML] Starting model training...")
    try:
        from app.services.ml_threat_service import get_ml_service
        svc = get_ml_service()

        # --- Isolation Forest + XGBoost ---
        scans = _fetch_completed_scans(days=days)
        iso_xgb_result = svc.train_from_scans(scans)
        logger.info(f"[ML] IF+XGB training result: {iso_xgb_result}")

        # --- LSTM / Holt-Winters ---
        daily_counts = _fetch_daily_threat_counts(days=days)
        lstm_result = svc.train_lstm_from_threats(daily_counts)
        logger.info(f"[ML] LSTM training result: {lstm_result}")

        summary = {
            "isolation_forest_xgb": iso_xgb_result,
            "lstm_forecaster": lstm_result,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"[ML] Training complete: {summary}")
        return summary

    except Exception as e:
        logger.exception(f"[ML] Training failed: {e}")
        return {"error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# Task 2 — Post-scan ML analysis
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="app.tasks.ml_tasks.run_ml_analysis_for_scan")
def run_ml_analysis_for_scan(self, scan_id: str):
    """
    Fetch a completed scan from the DB and run all three ML models on it.
    Called automatically after every scan completes (see scan_tasks.py hook).
    Results are stored back into the `ml_analysis` column.
    """
    logger.info(f"[ML] Running analysis for scan {scan_id}")
    try:
        from app.services.ml_threat_service import get_ml_service

        sb = get_supabase()
        result = (
            sb.table("scans")
            .select("*")
            .eq("id", scan_id)
            .single()
            .execute()
        )
        scan = result.data
        if not scan:
            logger.warning(f"[ML] Scan {scan_id} not found")
            return {"error": "scan_not_found"}

        svc = get_ml_service()
        ml_result = svc.full_analysis(scan)

        _store_ml_result(scan_id, ml_result)
        logger.info(f"[ML] Analysis done for {scan_id}: risk={ml_result.get('ml_risk_level')}")
        return ml_result

    except Exception as e:
        logger.exception(f"[ML] Analysis failed for scan {scan_id}: {e}")
        return {"error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# Task 3 — Standalone forecast
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="app.tasks.ml_tasks.forecast_threat_volume")
def forecast_threat_volume(self, horizon_days: int = 14):
    """
    Generate a threat volume forecast and cache it in Redis for the dashboard.
    Runs daily after threat sync so the forecast is always fresh.
    """
    logger.info(f"[ML] Generating {horizon_days}-day threat forecast...")
    try:
        import redis as redis_lib
        from app.core.config import settings
        from app.services.ml_threat_service import get_ml_service

        svc = get_ml_service()
        forecast = svc.forecast_attacks(horizon_days=horizon_days)

        # Cache in Redis (TTL 25 hours) — dashboard reads this
        try:
            import json
            r = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
            r.setex("ml:threat_forecast", 25 * 3600, json.dumps(forecast))
            logger.info("[ML] Forecast cached in Redis")
        except Exception as re:
            logger.warning(f"[ML] Redis cache failed (non-fatal): {re}")

        return forecast

    except Exception as e:
        logger.exception(f"[ML] Forecast task failed: {e}")
        return {"error": str(e)}
