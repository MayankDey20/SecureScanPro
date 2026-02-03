#!/bin/bash

# SecureScan Pro - Supabase Setup Script

echo "🚀 SecureScan Pro - Supabase Migration Setup"
echo "=============================================="
echo ""

# Check if .env files exist
if [ ! -f "backend/.env" ]; then
    echo "⚠️  Backend .env file not found!"
    echo "Creating from example..."
    cp backend/.env.example backend/.env
    echo "✅ Created backend/.env"
    echo "📝 Please edit backend/.env and add your Supabase credentials"
    echo ""
fi

if [ ! -f "frontend/.env" ]; then
    echo "⚠️  Frontend .env file not found!"
    echo "Creating from example..."
    cp frontend/.env.example frontend/.env
    echo "✅ Created frontend/.env"
    echo "📝 Please edit frontend/.env and add your Supabase credentials"
    echo ""
fi

echo "📋 Next Steps:"
echo "1. Create a Supabase project at https://supabase.com"
echo "2. Copy your Supabase URL and API keys"
echo "3. Edit backend/.env with your credentials"
echo "4. Edit frontend/.env with your credentials"
echo "5. Run the SQL setup in Supabase SQL Editor (see SUPABASE_MIGRATION.md)"
echo "6. Run: docker-compose up --build"
echo ""
echo "📖 For detailed instructions, see SUPABASE_MIGRATION.md"
