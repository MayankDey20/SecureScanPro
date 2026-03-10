-- Migration 004: Fix profiles table for native JWT auth (no Supabase Auth)
-- Run this in the Supabase SQL Editor:
-- https://supabase.com/dashboard/project/gdcooiiderywiekarpvt/sql

-- ============================================================
-- STEP 1: Drop the FK constraint that ties profiles to auth.users
-- Our app uses native JWT — profiles are standalone, not linked to Supabase Auth.
-- ============================================================
ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_id_fkey;
ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_user_id_fkey;

-- Also ensure the id column has its own default so we can insert freely
ALTER TABLE profiles ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- ============================================================
-- STEP 2: Add all columns required by the native auth system
-- ============================================================
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS team_id UUID;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{
    "theme": "dark",
    "notifications": {"email": true, "browser": true, "sms": false},
    "default_scan_depth": "medium",
    "auto_save": true
}';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- ============================================================
-- DISABLE RLS on all app tables
-- Access control is handled by FastAPI JWT middleware, not RLS.
-- The backend uses the service role key which bypasses RLS anyway,
-- but disabling it makes intent explicit and avoids surprises.
-- ============================================================
ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities DISABLE ROW LEVEL SECURITY;

-- Drop any existing RLS policies on profiles that could block inserts
DROP POLICY IF EXISTS "Users can insert their own profile." ON profiles;
DROP POLICY IF EXISTS "Users can update own profile." ON profiles;
DROP POLICY IF EXISTS "Public profiles are viewable by everyone." ON profiles;
DROP POLICY IF EXISTS "profiles_insert_policy" ON profiles;
DROP POLICY IF EXISTS "profiles_select_policy" ON profiles;
DROP POLICY IF EXISTS "profiles_update_policy" ON profiles;
DROP POLICY IF EXISTS "profiles_delete_policy" ON profiles;
