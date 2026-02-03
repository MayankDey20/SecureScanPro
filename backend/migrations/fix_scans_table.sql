-- Quick fix for existing scans table
-- Run this in Supabase SQL Editor if you already have a scans table

-- Add missing columns to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS security_score INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS target VARCHAR(500);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_type VARCHAR(50)[] DEFAULT '{full}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id UUID;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_options JSONB DEFAULT '{}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerabilities_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_count INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE scans ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Create threats table if not exists
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    published_date TIMESTAMPTZ,
    category VARCHAR(100),
    references JSONB,
    source VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create profiles table if not exists (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255),
    full_name VARCHAR(255),
    avatar_url TEXT,
    role VARCHAR(50) DEFAULT 'user',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create a trigger to auto-create profile on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name)
    VALUES (new.id, new.email, new.raw_user_meta_data->>'full_name')
    ON CONFLICT (id) DO NOTHING;
    RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop trigger if exists and recreate
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Enable Row Level Security
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- RLS Policies for scans
DROP POLICY IF EXISTS "Users can view their own scans" ON scans;
CREATE POLICY "Users can view their own scans" ON scans
    FOR SELECT USING (auth.uid() = user_id OR auth.uid() = created_by);

DROP POLICY IF EXISTS "Users can insert their own scans" ON scans;
CREATE POLICY "Users can insert their own scans" ON scans
    FOR INSERT WITH CHECK (auth.uid() = user_id OR auth.uid() = created_by);

DROP POLICY IF EXISTS "Users can update their own scans" ON scans;
CREATE POLICY "Users can update their own scans" ON scans
    FOR UPDATE USING (auth.uid() = user_id OR auth.uid() = created_by);

-- RLS Policies for threats (public read)
DROP POLICY IF EXISTS "Anyone can view threats" ON threats;
CREATE POLICY "Anyone can view threats" ON threats
    FOR SELECT USING (true);

-- RLS Policies for profiles
DROP POLICY IF EXISTS "Users can view their own profile" ON profiles;
CREATE POLICY "Users can view their own profile" ON profiles
    FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update their own profile" ON profiles;
CREATE POLICY "Users can update their own profile" ON profiles
    FOR UPDATE USING (auth.uid() = id);

-- Grant service role full access (for backend API)
GRANT ALL ON scans TO service_role;
GRANT ALL ON threats TO service_role;
GRANT ALL ON profiles TO service_role;
