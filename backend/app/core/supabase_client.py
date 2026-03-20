"""
Database client — Supabase EXCLUSIVE.

All queries go directly to Supabase using the official supabase-py SDK.
PostgreSQL fallback has been removed. SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
must be set in the environment.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Supabase client singleton ────────────────────────────────────────────────
_supabase_client = None


def _init_supabase_client():
    global _supabase_client
    url = settings.SUPABASE_URL
    key = settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY
    if not url or not key:
        raise RuntimeError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env"
        )
    from supabase import create_client
    _supabase_client = create_client(url, key)
    logger.info("✅ Supabase client initialised with service role key — RLS bypassed")


def _get_client():
    """Lazy accessor — initialises on first call so import never crashes."""
    global _supabase_client
    if _supabase_client is None:
        _init_supabase_client()
    return _supabase_client


# ═══════════════════════════════════════════════════════════════════════════
# Thin result wrapper (keeps call-site API identical)
# ═══════════════════════════════════════════════════════════════════════════

class _Result:
    def __init__(self, data: list, count: Optional[int] = None):
        self.data = data
        self.count = count


# ═══════════════════════════════════════════════════════════════════════════
# Synchronous query builder (wraps supabase-py chain)
# Used by: API endpoints (via get_supabase()), Celery tasks
# ═══════════════════════════════════════════════════════════════════════════

class _Query:
    """Synchronous Supabase query builder."""

    def __init__(self, table: str):
        self._ref = _get_client().table(table)
        self._ops: list = []

    def _chain(self, method, *args, **kwargs):
        self._ops.append((method, args, kwargs))
        return self

    # ── builder methods ──────────────────────────────────────────────────
    def select(self, cols="*", count=None):
        if count:
            return self._chain("select", cols, count=count)
        return self._chain("select", cols)

    def insert(self, data):            return self._chain("insert", data)
    def update(self, data):            return self._chain("update", data)
    def delete(self):                  return self._chain("delete")
    def upsert(self, data):            return self._chain("upsert", data)
    def eq(self, col, val):            return self._chain("eq", col, val)
    def neq(self, col, val):           return self._chain("neq", col, val)
    def gt(self, col, val):            return self._chain("gt", col, val)
    def gte(self, col, val):           return self._chain("gte", col, val)
    def lt(self, col, val):            return self._chain("lt", col, val)
    def lte(self, col, val):           return self._chain("lte", col, val)
    def ilike(self, col, pat):         return self._chain("ilike", col, pat)
    def in_(self, col, vals):          return self._chain("in_", col, vals)
    def or_(self, expr):               return self._chain("or_", expr)
    def order(self, col, desc=False):  return self._chain("order", col, desc=desc)
    def limit(self, n):                return self._chain("limit", n)
    def offset(self, n):               return self._chain("offset", n)
    def single(self):                  return self._chain("single")
    def range(self, start, end):       return self._chain("range", start, end)

    def execute(self) -> _Result:
        q = self._ref
        for method, args, kwargs in self._ops:
            q = getattr(q, method)(*args, **kwargs)
        r = q.execute()
        data = r.data if hasattr(r, "data") else []
        count = getattr(r, "count", None)
        return _Result(data=data if data is not None else [], count=count)


# ═══════════════════════════════════════════════════════════════════════════
# Async query builder — wraps _Query in executor so FastAPI await works
# ═══════════════════════════════════════════════════════════════════════════

class _AsyncQuery:
    """Async wrapper — delegates to _Query.execute() in a thread executor."""

    def __init__(self, table: str):
        self._table = table
        self._ops: list = []

    def _chain(self, method, *args, **kwargs):
        self._ops.append((method, args, kwargs))
        return self

    def select(self, cols="*", count=None):
        if count:
            return self._chain("select", cols, count=count)
        return self._chain("select", cols)

    def insert(self, data):            return self._chain("insert", data)
    def update(self, data):            return self._chain("update", data)
    def delete(self):                  return self._chain("delete")
    def upsert(self, data):            return self._chain("upsert", data)
    def eq(self, col, val):            return self._chain("eq", col, val)
    def neq(self, col, val):           return self._chain("neq", col, val)
    def gt(self, col, val):            return self._chain("gt", col, val)
    def gte(self, col, val):           return self._chain("gte", col, val)
    def lt(self, col, val):            return self._chain("lt", col, val)
    def lte(self, col, val):           return self._chain("lte", col, val)
    def ilike(self, col, pat):         return self._chain("ilike", col, pat)
    def in_(self, col, vals):          return self._chain("in_", col, vals)
    def or_(self, expr):               return self._chain("or_", expr)
    def order(self, col, desc=False):  return self._chain("order", col, desc=desc)
    def limit(self, n):                return self._chain("limit", n)
    def offset(self, n):               return self._chain("offset", n)
    def single(self):                  return self._chain("single")
    def range(self, start, end):       return self._chain("range", start, end)

    async def execute(self) -> _Result:
        import asyncio
        q = _Query(self._table)
        for method, args, kwargs in self._ops:
            getattr(q, method)(*args, **kwargs)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, q.execute)


# ═══════════════════════════════════════════════════════════════════════════
# Public shim classes (keep existing call-sites working unchanged)
# ═══════════════════════════════════════════════════════════════════════════

class _AuthShim:
    """Stub — auth is handled by our own JWT system (security.py)."""
    @staticmethod
    def sign_up(payload): raise NotImplementedError("Use /auth/register endpoint")
    @staticmethod
    def sign_in_with_password(payload): raise NotImplementedError("Use /auth/login endpoint")
    @staticmethod
    def get_user(token): raise NotImplementedError("Use JWT verification in dependencies.py")
    @staticmethod
    def refresh_session(token): raise NotImplementedError("Use /auth/refresh endpoint")
    class admin:
        @staticmethod
        def generate_link(payload): raise NotImplementedError("Supabase admin API not used")
    @staticmethod
    def update_user(payload): raise NotImplementedError("Use /users/me/password")


class SupabaseCompatSync:
    """
    Synchronous shim — returned by get_supabase().
    Used by: auth.py, scan.py, and all other API endpoints and Celery tasks.
    """
    auth = _AuthShim()

    def table(self, name: str) -> _Query:
        return _Query(name)


class SupabaseCompatAsync:
    """
    Async shim — returned by get_supabase_async().
    Used by FastAPI endpoints that prefer async/await.
    """
    auth = _AuthShim()

    def table(self, name: str) -> _AsyncQuery:
        return _AsyncQuery(name)


# ── Public API ───────────────────────────────────────────────────────────────

def get_supabase() -> SupabaseCompatSync:
    """Return synchronous Supabase client shim (for endpoints and Celery tasks)."""
    return SupabaseCompatSync()


def get_supabase_async() -> SupabaseCompatAsync:
    """Return async Supabase client shim (for async FastAPI endpoints)."""
    return SupabaseCompatAsync()


# Legacy aliases kept so existing imports don't break
pg_engine = None
AsyncSessionLocal = None


# ── Lifecycle hooks (called from main.py) ───────────────────────────────────

async def init_supabase():
    """Verify Supabase connectivity on startup (non-fatal, 10 s timeout)."""
    import asyncio
    try:
        client = _get_client()
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: client.table("profiles").select("id").limit(1).execute()
            ),
            timeout=10.0
        )
        logger.info("✅ Supabase connected — exclusive data store")
    except asyncio.TimeoutError:
        logger.warning("⚠️  Supabase connectivity check timed out (10 s) — continuing")
    except Exception as e:
        logger.warning(f"⚠️  Supabase connectivity check failed: {e} — continuing")


async def close_supabase():
    """No-op — supabase-py uses httpx which manages its own connection pool."""
    logger.info("✅ Supabase client closed")
