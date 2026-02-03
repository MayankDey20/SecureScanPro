from app.celery_worker import celery_app
import asyncio
from datetime import datetime, timezone
from app.services.scan_service import ScanService
from app.core.supabase_client import get_supabase

@celery_app.task(bind=True)
def run_scan_task(self, scan_id: str, target: str, scan_types: list):
    """
    Celery task to run a scan in the background.
    Since ScanService is async, we need to run it in an event loop.
    """
    try:
        scan_service = ScanService()
        
        # Use asyncio.run() for proper async execution in sync context
        result = asyncio.run(
            scan_service.run_scan(scan_id, target, scan_types)
        )
        
        # Save results to Supabase
        sb = get_supabase()
        sb.table("scans").update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "results": result
        }).eq("id", scan_id).execute()
        
        return result
    except Exception as e:
        # Log failure
        try:
            sb = get_supabase()
            sb.table("scans").update({
                "status": "failed",
                "error_message": str(e)
            }).eq("id", scan_id).execute()
        except Exception:
            pass # Fail silently if DB is unreachable
        return {"error": str(e), "scan_id": scan_id}
