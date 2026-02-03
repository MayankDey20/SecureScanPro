-- SecureScan Pro - Initial Database Schema
-- Migration 001: Core Tables
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- ORGANIZATIONS & TEAMS
-- ============================================

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan VARCHAR(50) DEFAULT 'free', -- free, pro, enterprise
    max_users INTEGER DEFAULT 5,
    max_scans_per_month INTEGER DEFAULT 100,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- USER PROFILES (extends Supabase auth.users)
-- ============================================

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    avatar_url TEXT,
    role VARCHAR(50) DEFAULT 'user', -- superadmin, admin, analyst, user, viewer
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
    settings JSONB DEFAULT '{
        "theme": "dark",
        "notifications": {
            "email": true,
            "browser": true,
            "slack": false
        },
        "default_scan_depth": "medium"
    }',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ASSETS (Domains, IPs, Applications)
-- ============================================

CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- domain, subdomain, ip, application, api
    target VARCHAR(500) NOT NULL,
    environment VARCHAR(50) DEFAULT 'production', -- production, staging, development
    criticality VARCHAR(20) DEFAULT 'medium', -- critical, high, medium, low
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    last_scan_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_assets_org ON assets(organization_id);
CREATE INDEX idx_assets_target ON assets(target);

-- ============================================
-- SCANS
-- ============================================

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50)[] DEFAULT '{full}',
    status VARCHAR(50) DEFAULT 'pending', -- pending, queued, running, completed, failed, cancelled
    progress INTEGER DEFAULT 0,
    current_phase VARCHAR(100),
    security_score INTEGER,
    
    -- Scan configuration
    scan_options JSONB DEFAULT '{
        "scan_depth": "medium",
        "follow_redirects": true,
        "max_depth": 3,
        "max_pages": 100,
        "timeout": 300,
        "user_agent": "SecureScan-Pro/1.0"
    }',
    
    -- Authentication for authenticated scanning
    auth_config JSONB, -- {type: "basic|bearer|cookie|form", credentials: {...}}
    
    -- Results summary
    vulnerabilities_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}',
    findings_count INTEGER DEFAULT 0,
    
    -- Timing
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    
    -- Metadata
    triggered_by VARCHAR(50) DEFAULT 'manual', -- manual, scheduled, api, webhook
    created_by UUID REFERENCES profiles(id),
    error_message TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scans_org ON scans(organization_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_target ON scans(target);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- ============================================
-- SCAN PROGRESS (for real-time tracking)
-- ============================================

CREATE TABLE IF NOT EXISTS scan_progress (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    phase VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'running',
    progress INTEGER DEFAULT 0,
    message TEXT,
    details JSONB,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_scan_progress_scan ON scan_progress(scan_id);

-- ============================================
-- VULNERABILITIES
-- ============================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    
    -- Vulnerability details
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    
    -- Classification
    vuln_type VARCHAR(100), -- sqli, xss, csrf, ssrf, etc.
    cwe_id VARCHAR(20),
    cve_id VARCHAR(20),
    owasp_category VARCHAR(50),
    
    -- Location
    location VARCHAR(1000),
    parameter VARCHAR(255),
    method VARCHAR(10),
    evidence TEXT,
    
    -- Remediation
    recommendation TEXT,
    references TEXT[],
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'open', -- open, confirmed, false_positive, accepted_risk, remediated
    status_changed_by UUID REFERENCES profiles(id),
    status_changed_at TIMESTAMPTZ,
    status_notes TEXT,
    
    -- Deduplication
    fingerprint VARCHAR(64), -- hash for dedup
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_org ON vulnerabilities(organization_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_fingerprint ON vulnerabilities(fingerprint);

-- ============================================
-- THREATS (CVE Intelligence)
-- ============================================

CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    
    -- Classification
    cwe_ids VARCHAR(20)[],
    affected_products JSONB,
    
    -- Metadata
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    
    -- Exploit info
    exploit_available BOOLEAN DEFAULT false,
    exploit_urls TEXT[],
    
    -- References
    references JSONB,
    
    -- Source tracking
    source VARCHAR(50), -- nvd, mitre, etc.
    synced_at TIMESTAMPTZ DEFAULT NOW(),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_threats_cve ON threats(cve_id);
CREATE INDEX idx_threats_severity ON threats(severity);

-- ============================================
-- SCHEDULED SCANS
-- ============================================

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    
    name VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Target configuration
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50)[] DEFAULT '{full}',
    scan_options JSONB DEFAULT '{}',
    auth_config JSONB,
    
    -- Schedule configuration
    schedule_type VARCHAR(50) NOT NULL, -- once, daily, weekly, monthly, cron
    cron_expression VARCHAR(100),
    timezone VARCHAR(50) DEFAULT 'UTC',
    
    -- Next/Last run
    next_run_at TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,
    last_scan_id UUID REFERENCES scans(id),
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    run_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    
    -- Notifications
    notify_on_completion BOOLEAN DEFAULT true,
    notify_on_critical BOOLEAN DEFAULT true,
    notification_channels JSONB DEFAULT '{"email": true}',
    
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scheduled_scans_next ON scheduled_scans(next_run_at) WHERE is_active = true;

-- ============================================
-- REPORTS
-- ============================================

CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL, -- executive, technical, compliance, full
    format VARCHAR(20) NOT NULL, -- pdf, html, json, csv
    
    -- Report content
    content_url TEXT, -- S3/storage URL
    content_size INTEGER,
    
    -- Generation
    status VARCHAR(50) DEFAULT 'pending', -- pending, generating, completed, failed
    generated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    
    -- Metadata
    parameters JSONB, -- Report generation parameters
    
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- NOTIFICATIONS
-- ============================================

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
    
    type VARCHAR(50) NOT NULL, -- scan_complete, critical_vuln, scheduled_report, etc.
    title VARCHAR(255) NOT NULL,
    message TEXT,
    
    -- Related entities
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    
    -- Delivery
    channels VARCHAR(50)[] DEFAULT '{in_app}', -- in_app, email, slack, webhook
    delivered_channels VARCHAR(50)[] DEFAULT '{}',
    
    -- Status
    is_read BOOLEAN DEFAULT false,
    read_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id, is_read);

-- ============================================
-- AUDIT LOG
-- ============================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    
    action VARCHAR(100) NOT NULL, -- scan.created, vuln.status_changed, user.login, etc.
    resource_type VARCHAR(50), -- scan, vulnerability, asset, user
    resource_id UUID,
    
    -- Details
    old_values JSONB,
    new_values JSONB,
    metadata JSONB,
    
    -- Request info
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);

-- ============================================
-- INTEGRATIONS (Webhooks, Slack, etc.)
-- ============================================

CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- webhook, slack, teams, jira, pagerduty
    
    -- Configuration
    config JSONB NOT NULL, -- {url, token, channel, etc.}
    
    -- Events to trigger
    events VARCHAR(100)[] DEFAULT '{scan.completed, vulnerability.critical}',
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    last_triggered_at TIMESTAMPTZ,
    failure_count INTEGER DEFAULT 0,
    
    created_by UUID REFERENCES profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ROW LEVEL SECURITY POLICIES
-- ============================================

-- Enable RLS
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can read/update their own profile
CREATE POLICY "Users can view own profile" ON profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON profiles FOR UPDATE USING (auth.uid() = id);

-- Organization-based policies (users can access their org's data)
CREATE POLICY "Org members can view org" ON organizations FOR SELECT 
    USING (id IN (SELECT organization_id FROM profiles WHERE id = auth.uid()));

CREATE POLICY "Org members can view assets" ON assets FOR SELECT 
    USING (organization_id IN (SELECT organization_id FROM profiles WHERE id = auth.uid()));

CREATE POLICY "Org members can view scans" ON scans FOR SELECT 
    USING (organization_id IN (SELECT organization_id FROM profiles WHERE id = auth.uid()));

CREATE POLICY "Org members can view vulnerabilities" ON vulnerabilities FOR SELECT 
    USING (organization_id IN (SELECT organization_id FROM profiles WHERE id = auth.uid()));

-- Users can create scans for their org
CREATE POLICY "Org members can create scans" ON scans FOR INSERT 
    WITH CHECK (organization_id IN (SELECT organization_id FROM profiles WHERE id = auth.uid()));

-- ============================================
-- FUNCTIONS & TRIGGERS
-- ============================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to calculate scan duration
CREATE OR REPLACE FUNCTION calculate_scan_duration()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND NEW.started_at IS NOT NULL THEN
        NEW.duration_seconds = EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at))::INTEGER;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER calc_scan_duration BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION calculate_scan_duration();

-- ============================================
-- SEED DATA
-- ============================================

-- Insert default organization for new users
INSERT INTO organizations (id, name, slug, plan) 
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default', 'free')
ON CONFLICT DO NOTHING;
