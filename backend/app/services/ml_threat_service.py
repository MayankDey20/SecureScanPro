"""
ML Threat Detection Service — SecureScan Pro
=============================================
Four complementary models, all non-blocking:

1. Isolation Forest   — anomaly detection on scan feature vectors
2. XGBoost Classifier — severity/threat-class classification from scan telemetry
3. LSTM Forecaster    — time-series prediction of future attack volume
4. Gemini Threat Intel Summariser (extends existing AIService)

Models are trained on-the-fly from historical scan + threat data stored in
PostgreSQL.  They are persisted to /app/ml_models/ (Docker volume) so they
survive restarts and only retrain when new data arrives.

No existing API, task, or service is modified.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pickle
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────
MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", str(Path(__file__).resolve().parent.parent.parent / "ml_models")))
MODEL_DIR.mkdir(parents=True, exist_ok=True)

ISO_FOREST_PATH  = MODEL_DIR / "isolation_forest.pkl"
XGB_MODEL_PATH   = MODEL_DIR / "xgb_classifier.pkl"
LSTM_MODEL_PATH  = MODEL_DIR / "lstm_forecaster.pkl"
SCALER_PATH      = MODEL_DIR / "feature_scaler.pkl"
LABEL_ENC_PATH   = MODEL_DIR / "label_encoder.pkl"

# ──────────────────────────────────────────────────────────────────────────────
# Feature helpers
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUS_MAP   = {"pending": 0, "running": 1, "completed": 2, "failed": 3}

def _scan_to_feature_vector(scan: Dict[str, Any]) -> np.ndarray:
    """
    Convert a scan record (from PostgreSQL `scans` table) to a fixed-length
    numeric feature vector suitable for Isolation Forest / XGBoost.

    Feature order (12 dims):
        0  vuln_count_total
        1  vuln_count_critical
        2  vuln_count_high
        3  vuln_count_medium
        4  vuln_count_low
        5  open_ports_count
        6  ssl_issues
        7  header_issues
        8  scan_duration_seconds
        9  status_encoded
        10 hour_of_day          (temporal)
        11 day_of_week          (temporal)
    """
    r = scan.get("result", {}) or {}
    mods = r.get("modules", {}) or {}

    vulns = mods.get("vuln", {}) or {}
    vuln_list = vulns.get("vulnerabilities", []) or []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vuln_list:
        s = (v.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    network = mods.get("network", {}) or {}
    open_ports = len(network.get("open_ports", []) or [])

    ssl_data = mods.get("ssl", {}) or {}
    ssl_issues = int(not ssl_data.get("valid", True)) + len(ssl_data.get("issues", []) or [])

    headers = mods.get("headers", {}) or {}
    header_issues = len(headers.get("missing", []) or [])

    started  = scan.get("started_at") or scan.get("created_at") or ""
    finished = scan.get("completed_at") or ""
    try:
        t0 = datetime.fromisoformat(started.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(finished.replace("Z", "+00:00")) if finished else datetime.now(timezone.utc)
        duration = max(0.0, (t1 - t0).total_seconds())
        hour_of_day = t0.hour
        day_of_week = t0.weekday()
    except Exception:
        duration = 0.0
        hour_of_day = 12
        day_of_week = 0

    status_enc = STATUS_MAP.get((scan.get("status") or "").lower(), 0)

    return np.array([
        float(sum(sev_counts.values())),
        float(sev_counts["critical"]),
        float(sev_counts["high"]),
        float(sev_counts["medium"]),
        float(sev_counts["low"]),
        float(open_ports),
        float(ssl_issues),
        float(header_issues),
        float(duration),
        float(status_enc),
        float(hour_of_day),
        float(day_of_week),
    ], dtype=np.float32)


def _threat_to_label(scan: Dict[str, Any]) -> str:
    """
    Derive a coarse threat label from a scan's vulnerability data.
    Used as the target class for XGBoost.
    """
    r = scan.get("result", {}) or {}
    mods = r.get("modules", {}) or {}
    vulns = (mods.get("vuln", {}) or {}).get("vulnerabilities", []) or []

    crit = sum(1 for v in vulns if (v.get("severity") or "").lower() == "critical")
    high = sum(1 for v in vulns if (v.get("severity") or "").lower() == "high")

    if crit >= 1:
        return "critical_threat"
    if high >= 2:
        return "high_threat"
    if high >= 1 or len(vulns) >= 5:
        return "medium_threat"
    if len(vulns) >= 1:
        return "low_threat"
    return "clean"


# ──────────────────────────────────────────────────────────────────────────────
# MLThreatService
# ──────────────────────────────────────────────────────────────────────────────

class MLThreatService:
    """
    Thin wrapper that loads / trains ML models lazily and exposes
    three analysis methods consumed by the REST API and Celery tasks.
    """

    def __init__(self):
        self._iso_forest   = None
        self._xgb          = None
        self._lstm_weights  = None   # stored as plain numpy arrays (no torch/keras dep)
        self._scaler       = None
        self._label_classes: List[str] = ["clean", "low_threat", "medium_threat", "high_threat", "critical_threat"]
        self._load_models()

    # ── Persistence ────────────────────────────────────────────────────────

    def _load_models(self):
        """Load persisted models if they exist."""
        try:
            if ISO_FOREST_PATH.exists():
                with open(ISO_FOREST_PATH, "rb") as f:
                    self._iso_forest = pickle.load(f)
                logger.info("Isolation Forest loaded from disk")
        except Exception as e:
            logger.warning(f"Could not load Isolation Forest: {e}")

        try:
            if XGB_MODEL_PATH.exists():
                with open(XGB_MODEL_PATH, "rb") as f:
                    self._xgb = pickle.load(f)
                logger.info("XGBoost classifier loaded from disk")
        except Exception as e:
            logger.warning(f"Could not load XGBoost: {e}")

        try:
            if SCALER_PATH.exists():
                with open(SCALER_PATH, "rb") as f:
                    self._scaler = pickle.load(f)
        except Exception as e:
            logger.warning(f"Could not load scaler: {e}")

        try:
            if LSTM_MODEL_PATH.exists():
                with open(LSTM_MODEL_PATH, "rb") as f:
                    self._lstm_weights = pickle.load(f)
                logger.info("LSTM weights loaded from disk")
        except Exception as e:
            logger.warning(f"Could not load LSTM: {e}")

    def _save_models(self):
        try:
            if self._iso_forest:
                with open(ISO_FOREST_PATH, "wb") as f:
                    pickle.dump(self._iso_forest, f)
            if self._xgb:
                with open(XGB_MODEL_PATH, "wb") as f:
                    pickle.dump(self._xgb, f)
            if self._scaler:
                with open(SCALER_PATH, "wb") as f:
                    pickle.dump(self._scaler, f)
            if self._lstm_weights:
                with open(LSTM_MODEL_PATH, "wb") as f:
                    pickle.dump(self._lstm_weights, f)
        except Exception as e:
            logger.warning(f"Model save failed (non-fatal): {e}")

    # ── Training ────────────────────────────────────────────────────────────

    def train_from_scans(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        (Re)train Isolation Forest + XGBoost from a list of completed scan records.
        Called by the Celery scheduled task.
        Returns a summary dict.
        """
        if len(scans) < 5:
            return {"status": "skipped", "reason": "insufficient_data", "scan_count": len(scans)}

        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        from sklearn.pipeline import Pipeline

        try:
            import xgboost as xgb
        except ImportError:
            xgb = None
            logger.warning("xgboost not installed — XGBoost training skipped")

        # Build feature matrix
        X = np.vstack([_scan_to_feature_vector(s) for s in scans])
        y_labels = [_threat_to_label(s) for s in scans]

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self._scaler = scaler

        # ── 1. Isolation Forest ──────────────────────────────────────────────
        contamination = min(0.15, max(0.01, sum(1 for l in y_labels if l in ("high_threat", "critical_threat")) / len(y_labels)))
        iso = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        iso.fit(X_scaled)
        self._iso_forest = iso

        # ── 2. XGBoost ──────────────────────────────────────────────────────
        xgb_trained = False
        if xgb is not None:
            le = LabelEncoder()
            le.fit(self._label_classes)
            y_enc = le.transform(y_labels)
            self._label_classes = list(le.classes_)

            # need at least 2 classes
            if len(set(y_enc)) >= 2:
                clf = xgb.XGBClassifier(
                    n_estimators=200,
                    max_depth=5,
                    learning_rate=0.1,
                    use_label_encoder=False,
                    eval_metric="mlogloss",
                    random_state=42,
                    verbosity=0,
                )
                clf.fit(X_scaled, y_enc)
                self._xgb = (clf, le)
                xgb_trained = True

        self._save_models()

        return {
            "status": "trained",
            "scan_count": len(scans),
            "iso_forest_contamination": round(contamination, 4),
            "xgb_trained": xgb_trained,
            "feature_dims": X.shape[1],
        }

    def train_lstm_from_threats(self, daily_counts: List[int]) -> Dict[str, Any]:
        """
        Train a lightweight numpy-only LSTM substitute (an Exponential Smoothing
        state machine) on daily threat count history.

        For production use, replace the body with a real Keras/PyTorch LSTM.
        The interface (input/output) stays identical so callers don't change.
        """
        if len(daily_counts) < 7:
            return {"status": "skipped", "reason": "need_at_least_7_days"}

        counts = np.array(daily_counts, dtype=np.float32)
        # Holt-Winters double exponential smoothing parameters (learned by grid search)
        best_alpha, best_beta, best_err = 0.3, 0.1, float("inf")
        for alpha in np.arange(0.1, 0.9, 0.1):
            for beta in np.arange(0.0, 0.5, 0.1):
                level = counts[0]
                trend = counts[1] - counts[0]
                errs = []
                for actual in counts[1:]:
                    pred = level + trend
                    errs.append((actual - pred) ** 2)
                    new_level = alpha * actual + (1 - alpha) * (level + trend)
                    trend = beta * (new_level - level) + (1 - beta) * trend
                    level = new_level
                rmse = float(np.sqrt(np.mean(errs)))
                if rmse < best_err:
                    best_err, best_alpha, best_beta = rmse, float(alpha), float(beta)

        # Re-run with best params to get final state
        level = counts[0]
        trend = counts[1] - counts[0]
        for actual in counts[1:]:
            new_level = best_alpha * actual + (1 - best_alpha) * (level + trend)
            trend = best_beta * (new_level - level) + (1 - best_beta) * trend
            level = new_level

        self._lstm_weights = {
            "alpha": best_alpha,
            "beta": best_beta,
            "level": float(level),
            "trend": float(trend),
            "rmse": round(best_err, 4),
            "trained_on": len(daily_counts),
        }
        self._save_models()
        return {"status": "trained", **self._lstm_weights}

    # ── Inference ───────────────────────────────────────────────────────────

    def detect_anomaly(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run Isolation Forest on a single scan result.
        Returns anomaly score + flag.
        """
        if self._iso_forest is None:
            return {"anomaly": False, "score": 0.0, "model": "not_trained", "reason": "Model not yet trained — run /api/v1/ml/train first"}

        fv = _scan_to_feature_vector(scan).reshape(1, -1)
        if self._scaler:
            fv = self._scaler.transform(fv)

        # decision_function: negative = more anomalous
        raw_score = float(self._iso_forest.decision_function(fv)[0])
        pred      = int(self._iso_forest.predict(fv)[0])  # -1 = anomaly, 1 = normal

        # Normalise to 0-100 anomaly score (higher = more anomalous)
        anomaly_score = round(max(0.0, min(100.0, (-raw_score + 0.5) * 100)), 1)
        is_anomaly    = pred == -1

        interpretation = (
            "Highly anomalous scan pattern — possible active attack or unusual target" if anomaly_score > 70
            else "Elevated anomaly signal — worth manual review" if anomaly_score > 40
            else "Within normal parameters"
        )

        return {
            "anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "raw_score": round(raw_score, 4),
            "interpretation": interpretation,
            "model": "isolation_forest",
        }

    def classify_threat(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run XGBoost classifier on a single scan result.
        Returns predicted threat class + per-class probabilities.
        """
        if self._xgb is None:
            return {"threat_class": "unknown", "confidence": 0.0, "model": "not_trained", "reason": "Model not yet trained"}

        clf, le = self._xgb
        fv = _scan_to_feature_vector(scan).reshape(1, -1)
        if self._scaler:
            fv = self._scaler.transform(fv)

        pred_enc  = clf.predict(fv)[0]
        proba     = clf.predict_proba(fv)[0]
        pred_label = le.inverse_transform([pred_enc])[0]
        confidence = round(float(proba[pred_enc]), 3)

        class_probs = {
            le.inverse_transform([i])[0]: round(float(p), 3)
            for i, p in enumerate(proba)
        }

        severity_hint = {
            "clean":          "No action required",
            "low_threat":     "Monitor — no immediate action needed",
            "medium_threat":  "Review findings within 48 hours",
            "high_threat":    "Remediate within 24 hours",
            "critical_threat":"Immediate remediation required",
        }.get(pred_label, "Review recommended")

        return {
            "threat_class": pred_label,
            "confidence": confidence,
            "class_probabilities": class_probs,
            "severity_hint": severity_hint,
            "model": "xgboost",
        }

    def forecast_attacks(self, horizon_days: int = 7) -> Dict[str, Any]:
        """
        Use the trained LSTM (Holt-Winters) weights to forecast
        daily threat counts for the next `horizon_days` days.
        """
        if self._lstm_weights is None:
            return {"forecast": [], "model": "not_trained", "reason": "Model not yet trained"}

        w = self._lstm_weights
        level = w["level"]
        trend = w["trend"]
        alpha = w["alpha"]
        beta  = w["beta"]

        forecast = []
        today = datetime.now(timezone.utc).date()
        for i in range(1, horizon_days + 1):
            predicted = max(0.0, level + trend * i)
            forecast.append({
                "date": (today + timedelta(days=i)).isoformat(),
                "predicted_count": round(predicted, 1),
            })

        # Simple trend direction
        delta = forecast[-1]["predicted_count"] - forecast[0]["predicted_count"]
        if delta > 2:
            trend_label = "increasing"
        elif delta < -2:
            trend_label = "decreasing"
        else:
            trend_label = "stable"

        return {
            "forecast": forecast,
            "trend": trend_label,
            "model_rmse": w.get("rmse"),
            "trained_on_days": w.get("trained_on"),
            "model": "holt_winters_lstm",
        }

    def full_analysis(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run all three models on a single scan and combine results.
        Used by the post-scan hook.
        """
        anomaly    = self.detect_anomaly(scan)
        threat_cls = self.classify_threat(scan)
        forecast   = self.forecast_attacks(horizon_days=7)

        risk_level = "low"
        if anomaly.get("anomaly") and threat_cls.get("threat_class") in ("high_threat", "critical_threat"):
            risk_level = "critical"
        elif anomaly.get("anomaly") or threat_cls.get("threat_class") in ("high_threat", "critical_threat"):
            risk_level = "high"
        elif threat_cls.get("threat_class") == "medium_threat":
            risk_level = "medium"

        return {
            "ml_risk_level": risk_level,
            "anomaly_detection": anomaly,
            "threat_classification": threat_cls,
            "attack_forecast": forecast,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
        }


# Module-level singleton (one instance per worker process)
_service_instance: Optional[MLThreatService] = None

def get_ml_service() -> MLThreatService:
    global _service_instance
    if _service_instance is None:
        _service_instance = MLThreatService()
    return _service_instance
