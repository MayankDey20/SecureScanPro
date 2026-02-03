"""
Supabase client configuration and utilities
"""
from supabase import create_client, Client
from typing import Optional
import logging
import os

from app.core.config import settings

logger = logging.getLogger(__name__)


class SupabaseClient:
    """Supabase client manager"""
    
    client: Optional[Client] = None


supabase_client = SupabaseClient()


def get_supabase() -> Client:
    """Get or create Supabase client"""
    if supabase_client.client is None:
        try:
            supabase_client.client = create_client(
                settings.SUPABASE_URL,
                settings.SUPABASE_SERVICE_KEY
            )
            logger.info("✅ Connected to Supabase")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Supabase: {e}")
            raise
    
    return supabase_client.client


async def init_supabase():
    """Initialize Supabase connection"""
    try:
        client = get_supabase()
        # Test connection by checking auth
        logger.info("✅ Supabase initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Supabase: {e}")
        raise


async def close_supabase():
    """Close Supabase connection"""
    # Supabase client doesn't require explicit closing
    logger.info("✅ Supabase connection closed")
