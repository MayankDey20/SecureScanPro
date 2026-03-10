-- Migration 003: Replace Supabase auth with native JWT auth
-- Drops the Supabase auth.users FK and adds password_hash column.
-- Safe to run multiple times (IF NOT EXISTS / DO blocks).

-- 1. Drop the FK constraint that references auth.users (Supabase-only)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'profiles_id_fkey'
          AND table_name = 'profiles'
    ) THEN
        ALTER TABLE profiles DROP CONSTRAINT profiles_id_fkey;
    END IF;
END $$;

-- 2. Recreate profiles as a standalone table if it doesn't exist yet
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255),
    avatar_url TEXT,
    role VARCHAR(50) DEFAULT 'user',
    organization_id UUID,
    team_id UUID,
    settings JSONB DEFAULT '{}',
    password_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

-- 3. Add password_hash to existing table if column is missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'profiles' AND column_name = 'password_hash'
    ) THEN
        ALTER TABLE profiles ADD COLUMN password_hash TEXT;
    END IF;
END $$;

-- 4. Make sure email has a unique index
CREATE UNIQUE INDEX IF NOT EXISTS profiles_email_idx ON profiles(email);
