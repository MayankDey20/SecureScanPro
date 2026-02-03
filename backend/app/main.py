"""
SecureScan Pro - FastAPI Main Application
Enterprise-grade website security scanner backend
"""

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging
import time
import asyncio

from app.core.supabase_client import init_supabase, close_supabase
from app.core.config import settings
from app.core.websocket_manager import ws_manager, RedisPubSubManager
from app.api.v1 import (
    auth, threats, scan, users, reports, analytics, ai,
    scheduled_scans, teams, notifications, vulnerabilities
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

# Redis Pub/Sub for distributed WebSocket updates
redis_pubsub = RedisPubSubManager(settings.REDIS_URL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("🚀 SecureScan Pro starting up...")
    # Connect to Supabase
    await init_supabase()
    logger.info("✅ Supabase connected")
    
    # Connect to Redis for WebSocket pub/sub
    await redis_pubsub.connect()
    await redis_pubsub.start_listener()
    logger.info("✅ Redis pub/sub connected")
    
    logger.info("✅ Background workers started")
    yield
    logger.info("🛑 SecureScan Pro shutting down...")
    
    # Disconnect Redis
    await redis_pubsub.disconnect()
    
    # Close Supabase connection
    await close_supabase()
    logger.info("✅ All connections closed")

# Create FastAPI application
app = FastAPI(
    title="SecureScan Pro API",
    description="Enterprise-grade website security scanning platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware Configuration

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip Compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Request ID and Timing Middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add request processing time and request ID"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Request-ID"] = str(id(request))
    return response

# Exception Handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }
    )

# Root Endpoint
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "SecureScan Pro API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/api/docs",
        "endpoints": {
            "scans": "/api/v1/scan",
            "reports": "/api/v1/reports",
            "analytics": "/api/v1/analytics",
            "webhooks": "/api/v1/webhooks"
        }
    }

# Health Check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {
            "api": "operational",
            "database": "supabase",
            "cache": "operational",
            "workers": "operational"
        }
    }

# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix=settings.API_V1_STR)
app.include_router(scan.router, prefix="/api/v1")
app.include_router(threats.router, prefix="/api/v1")
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(analytics.router, prefix=settings.API_V1_STR)
app.include_router(ai.router, prefix=settings.API_V1_STR)
app.include_router(scheduled_scans.router, prefix=settings.API_V1_STR)
app.include_router(teams.router, prefix=settings.API_V1_STR)
app.include_router(notifications.router, prefix=settings.API_V1_STR)
app.include_router(vulnerabilities.router, prefix=settings.API_V1_STR)

# WebSocket endpoint for real-time scan progress
@app.websocket("/api/v1/scan/{scan_id}/live")
async def websocket_scan_live(websocket: WebSocket, scan_id: str):
    """WebSocket for live scan updates"""
    await ws_manager.connect(websocket, scan_id)
    
    # Subscribe to Redis channel for this scan
    await redis_pubsub.subscribe_to_scan(scan_id)
    
    try:
        # Send current progress if available
        current_progress = ws_manager.get_progress(scan_id)
        if current_progress:
            await websocket.send_json(current_progress)
        
        # Keep connection alive and handle client messages
        while True:
            try:
                # Wait for client messages (ping/pong or commands)
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0  # Send keepalive every 30s
                )
                
                # Handle client commands
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif data.get("type") == "get_progress":
                    progress = ws_manager.get_progress(scan_id)
                    if progress:
                        await websocket.send_json(progress)
                        
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_json({"type": "keepalive"})
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        await redis_pubsub.unsubscribe_from_scan(scan_id)
        await ws_manager.disconnect(websocket)


# WebSocket endpoint for organization-wide notifications
@app.websocket("/api/v1/notifications/live")
async def websocket_notifications(websocket: WebSocket):
    """WebSocket for real-time notifications"""
    await websocket.accept()
    
    try:
        while True:
            # Placeholder for notification streaming
            await asyncio.sleep(30)
            await websocket.send_json({"type": "keepalive"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Notification WebSocket error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
