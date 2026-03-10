-- Migration: Add ml_analysis column to scans table
-- This is non-destructive — safe to run multiple times.
-- ml_analysis stores the output of the ML threat detection service as JSONB.

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS ml_analysis JSONB DEFAULT NULL;

-- Index on ml_risk_level for quick dashboard queries
CREATE INDEX IF NOT EXISTS idx_scans_ml_risk
    ON scans ((ml_analysis->>'ml_risk_level'))
    WHERE ml_analysis IS NOT NULL;
