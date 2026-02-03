# Supabase Migration Guide

Run these SQL files in the Supabase SQL Editor, in order:

1) `backend/migrations/001_initial_schema.sql`
2) `backend/migrations/002_update_existing_schema.sql`
3) `backend/migrations/fix_scans_table.sql`

If you are deploying to production, ensure your RLS policies and service key
permissions match your security requirements before going live.
