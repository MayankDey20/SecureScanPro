"""
WebSocket Manager for Real-Time Scan Progress
Provides live updates during security scans
"""
import asyncio
import json
import logging
from typing import Dict, Set, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from fastapi import WebSocket, WebSocketDisconnect
import redis.asyncio as redis

logger = logging.getLogger(__name__)


@dataclass
class ScanProgress:
    """Scan progress data structure"""
    scan_id: str
    status: str = "pending"
    progress: int = 0
    current_phase: str = ""
    phase_progress: int = 0
    message: str = ""
    findings_count: int = 0
    urls_scanned: int = 0
    errors: list = field(default_factory=list)
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "phase_progress": self.phase_progress,
            "message": self.message,
            "findings_count": self.findings_count,
            "urls_scanned": self.urls_scanned,
            "errors": self.errors,
            "started_at": self.started_at,
            "updated_at": self.updated_at
        }


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates
    """
    
    def __init__(self):
        # Map of scan_id -> set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Map of WebSocket -> scan_id
        self.connection_scans: Dict[WebSocket, str] = {}
        # Current progress for each scan
        self.scan_progress: Dict[str, ScanProgress] = {}
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept a new WebSocket connection for a scan"""
        await websocket.accept()
        
        async with self._lock:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = set()
            
            self.active_connections[scan_id].add(websocket)
            self.connection_scans[websocket] = scan_id
        
        logger.info(f"WebSocket connected for scan {scan_id}")
        
        # Send current progress if available
        if scan_id in self.scan_progress:
            await self.send_personal_message(
                self.scan_progress[scan_id].to_dict(),
                websocket
            )
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        async with self._lock:
            scan_id = self.connection_scans.get(websocket)
            
            if scan_id and scan_id in self.active_connections:
                self.active_connections[scan_id].discard(websocket)
                
                # Clean up empty sets
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]
            
            if websocket in self.connection_scans:
                del self.connection_scans[websocket]
        
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def send_personal_message(self, message: Dict, websocket: WebSocket):
        """Send a message to a specific WebSocket"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
    
    async def broadcast_to_scan(self, scan_id: str, message: Dict):
        """Broadcast a message to all connections watching a scan"""
        async with self._lock:
            connections = self.active_connections.get(scan_id, set()).copy()
        
        disconnected = []
        
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)
    
    async def update_progress(
        self,
        scan_id: str,
        status: str = None,
        progress: int = None,
        current_phase: str = None,
        phase_progress: int = None,
        message: str = None,
        findings_count: int = None,
        urls_scanned: int = None,
        error: str = None
    ):
        """Update scan progress and broadcast to connected clients"""
        async with self._lock:
            if scan_id not in self.scan_progress:
                self.scan_progress[scan_id] = ScanProgress(
                    scan_id=scan_id,
                    started_at=datetime.now(timezone.utc).isoformat()
                )
            
            progress_data = self.scan_progress[scan_id]
            
            if status is not None:
                progress_data.status = status
            if progress is not None:
                progress_data.progress = progress
            if current_phase is not None:
                progress_data.current_phase = current_phase
            if phase_progress is not None:
                progress_data.phase_progress = phase_progress
            if message is not None:
                progress_data.message = message
            if findings_count is not None:
                progress_data.findings_count = findings_count
            if urls_scanned is not None:
                progress_data.urls_scanned = urls_scanned
            if error is not None:
                progress_data.errors.append(error)
            
            progress_data.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Broadcast update
        await self.broadcast_to_scan(scan_id, progress_data.to_dict())
    
    def get_progress(self, scan_id: str) -> Optional[Dict]:
        """Get current progress for a scan"""
        if scan_id in self.scan_progress:
            return self.scan_progress[scan_id].to_dict()
        return None
    
    def clear_scan(self, scan_id: str):
        """Clear progress data for a completed scan"""
        if scan_id in self.scan_progress:
            del self.scan_progress[scan_id]


# Global connection manager instance
ws_manager = ConnectionManager()


class RedisPubSubManager:
    """
    Redis Pub/Sub manager for distributed WebSocket updates
    Allows Celery workers to publish progress updates
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
        self._listener_task: Optional[asyncio.Task] = None
    
    async def connect(self):
        """Connect to Redis"""
        self.redis = redis.from_url(self.redis_url)
        self.pubsub = self.redis.pubsub()
        
    async def disconnect(self):
        """Disconnect from Redis"""
        if self._listener_task:
            self._listener_task.cancel()
        if self.pubsub:
            await self.pubsub.close()
        if self.redis:
            await self.redis.close()
    
    async def subscribe_to_scan(self, scan_id: str):
        """Subscribe to updates for a specific scan"""
        channel = f"scan:{scan_id}:progress"
        await self.pubsub.subscribe(channel)
    
    async def unsubscribe_from_scan(self, scan_id: str):
        """Unsubscribe from scan updates"""
        channel = f"scan:{scan_id}:progress"
        await self.pubsub.unsubscribe(channel)
    
    async def publish_progress(self, scan_id: str, progress_data: Dict):
        """Publish progress update (call from Celery worker)"""
        channel = f"scan:{scan_id}:progress"
        message = json.dumps(progress_data)
        await self.redis.publish(channel, message)
    
    async def start_listener(self):
        """Start listening for progress updates"""
        self._listener_task = asyncio.create_task(self._listen())
    
    async def _listen(self):
        """Listen for Redis pub/sub messages and forward to WebSockets"""
        try:
            async for message in self.pubsub.listen():
                if message["type"] == "message":
                    channel = message["channel"].decode()
                    data = json.loads(message["data"])
                    
                    # Extract scan_id from channel
                    # Channel format: scan:{scan_id}:progress
                    parts = channel.split(":")
                    if len(parts) >= 2:
                        scan_id = parts[1]
                        await ws_manager.broadcast_to_scan(scan_id, data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Redis listener error: {e}")


# For use in Celery tasks (synchronous Redis client)
class SyncProgressPublisher:
    """
    Synchronous progress publisher for Celery tasks
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        import redis as sync_redis
        self.redis = sync_redis.from_url(redis_url)
    
    def publish(self, scan_id: str, progress_data: Dict):
        """Publish progress update"""
        channel = f"scan:{scan_id}:progress"
        message = json.dumps(progress_data)
        self.redis.publish(channel, message)
    
    def update_progress(
        self,
        scan_id: str,
        status: str = None,
        progress: int = None,
        current_phase: str = None,
        message: str = None,
        findings_count: int = None,
        **kwargs
    ):
        """Helper to publish progress update"""
        data = {
            "scan_id": scan_id,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if status is not None:
            data["status"] = status
        if progress is not None:
            data["progress"] = progress
        if current_phase is not None:
            data["current_phase"] = current_phase
        if message is not None:
            data["message"] = message
        if findings_count is not None:
            data["findings_count"] = findings_count
        
        data.update(kwargs)
        self.publish(scan_id, data)


# Scan phases with weights for progress calculation
SCAN_PHASES = {
    "initializing": {"weight": 5, "order": 1},
    "crawling": {"weight": 20, "order": 2},
    "ssl_scan": {"weight": 10, "order": 3},
    "header_scan": {"weight": 10, "order": 4},
    "port_scan": {"weight": 15, "order": 5},
    "vuln_scan": {"weight": 25, "order": 6},
    "nuclei_scan": {"weight": 10, "order": 7},
    "finalizing": {"weight": 5, "order": 8}
}


def calculate_overall_progress(completed_phases: list, current_phase: str, phase_progress: int) -> int:
    """
    Calculate overall scan progress based on completed phases
    """
    total_weight = sum(p["weight"] for p in SCAN_PHASES.values())
    completed_weight = sum(
        SCAN_PHASES[phase]["weight"] 
        for phase in completed_phases 
        if phase in SCAN_PHASES
    )
    
    # Add partial progress of current phase
    if current_phase in SCAN_PHASES:
        current_weight = SCAN_PHASES[current_phase]["weight"]
        completed_weight += (current_weight * phase_progress) / 100
    
    return int((completed_weight / total_weight) * 100)
