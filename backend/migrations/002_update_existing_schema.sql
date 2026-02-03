-- SecureScan Pro - Update Existing Schema
-- Run this if you already have profiles, scans, and vulnerabilities tables

-- Enable UUID extension (if not already enabled)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- UPDATE SCANS TABLE (add missing columns)
-- ============================================

-- Add missing columns to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS target VARCHAR(500);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS security_score INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS current_phase VARCHAR(100);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_options JSONB DEFAULT '{}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerabilities_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_count INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Update target column from url if target is null
UPDATE scans SET target = url WHERE target IS NULL AND url IS NOT NULL;

-- ============================================
-- CREATE THREATS TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    cwe_ids VARCHAR(20)[],
    affected_products JSONB,
    published_date TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    exploit_available BOOLEAN DEFAULT false,
    "references" JSONB,
    category VARCHAR(100),
    source VARCHAR(50),
    synced_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS on threats
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;

-- Anyone can view threats (public data)
DROP POLICY IF EXISTS "Anyone can view threats" ON threats;
CREATE POLICY "Anyone can view threats" ON threats
    FOR SELECT USING (true);

-- Service role can do everything
DROP POLICY IF EXISTS "Service role full access to threats" ON threats;
CREATE POLICY "Service role full access to threats" ON threats
    FOR ALL USING (auth.role() = 'service_role');

-- ============================================
-- UPDATE PROFILES TABLE
-- ============================================

ALTER TABLE profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS team_id UUID;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- ============================================
-- UPDATE VULNERABILITIES TABLE
-- ============================================

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_score DECIMAL(3,1);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_vector VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vuln_type VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(20);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve_id VARCHAR(20);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS location VARCHAR(1000);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS parameter VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS method VARCHAR(10);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS "references" TEXT[];
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'open';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- ============================================
-- ADD SERVICE ROLE POLICIES
-- ============================================

-- Allow service role (backend API) full access to all tables
DROP POLICY IF EXISTS "Service role full access to scans" ON scans;
CREATE POLICY "Service role full access to scans" ON scans
    FOR ALL USING (auth.role() = 'service_role');

DROP POLICY IF EXISTS "Service role full access to profiles" ON profiles;
CREATE POLICY "Service role full access to profiles" ON profiles
    FOR ALL USING (auth.role() = 'service_role');

DROP POLICY IF EXISTS "Service role full access to vulnerabilities" ON vulnerabilities;
CREATE POLICY "Service role full access to vulnerabilities" ON vulnerabilities
    FOR ALL USING (auth.role() = 'service_role');

-- ============================================
-- CREATE INDEXES FOR PERFORMANCE
-- ============================================

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_threats_cve ON threats(cve_id);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);

-- ============================================
-- AUTO-CREATE PROFILE ON USER SIGNUP
-- ============================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name)
    VALUES (
        new.id, 
        new.email, 
        COALESCE(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1))
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        updated_at = NOW();
    RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop and recreate trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================
-- GRANT PERMISSIONS
-- ============================================

GRANT ALL ON scans TO service_role;
GRANT ALL ON threats TO service_role;
GRANT ALL ON profiles TO service_role;
GRANT ALL ON vulnerabilities TO service_role;

GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
