from app.celery_worker import celery_app
import asyncio
from datetime import datetime, timezone
from app.services.scan_service import ScanService
from app.core.supabase_client import get_supabase
from typing import Optional

@celery_app.task(bind=True)
def run_scan_task(
    self,
    scan_id: str,
    target: str,
    scan_types: list,
    auth_config: Optional[dict] = None,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    scan_options: Optional[dict] = None,
):
    """
    Celery task to run a scan in the background.
    Since ScanService is async, we need to run it in an event loop.
    """
    try:
        scan_service = ScanService()
        
        # Use asyncio.run() for proper async execution in sync context
        result = asyncio.run(
            scan_service.run_scan(
                scan_id,
                target,
                scan_types,
                auth_config=auth_config,
                user_id=user_id,
                organization_id=organization_id,
                scan_options=scan_options,
            )
        )
        
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
    finally:
        # Fire-and-forget ML analysis after every scan (success or fail)
        # Runs as a separate Celery task so it never blocks the scan response
        try:
            from app.tasks.ml_tasks import run_ml_analysis_for_scan
            run_ml_analysis_for_scan.apply_async(args=[scan_id], countdown=5)
        except Exception:
            pass  # ML analysis is non-critical
