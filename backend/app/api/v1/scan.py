"""
Scan API endpoints for Supabase
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request
from typing import List, Optional
from datetime import datetime, timezone
import uuid
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.supabase_client import get_supabase
from app.core.dependencies import get_current_user
from app.core.config import settings
from app.models.scan import Scan, ScanCreate, ScanUpdate
# Import celery task
from app.tasks.scan_tasks import run_scan_task

router = APIRouter(prefix="/scan", tags=["scans"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/start")
@limiter.limit(f"{settings.RATE_LIMIT_SCAN_PER_MINUTE}/minute")
async def start_scan(
    request: Request,
    scan_data: ScanCreate, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Start a new security scan"""
    try:
        sb = get_supabase()
        # scan_service removed, utilizing Celery task
        
        # 1. Create scan record in Supabase
        scan_id = str(uuid.uuid4())
        new_scan = {
            "id": scan_id,
            "target": scan_data.target,
            "scan_type": scan_data.scan_type,
            "status": "pending",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "user_id": current_user.get("id", "anonymous")
        }
        
        # Insert into DB
        sb.table("scans").insert(new_scan).execute()
        
        # 2. Trigger Celery Task
        # We pass arguments as simple types (strings, lists)
        task = run_scan_task.delay(
            scan_id=scan_id, 
            target=scan_data.target, 
            scan_types=scan_data.scan_type # Expecting list of strings
        )
        
        return {
            "message": "Scan started successfully", 
            "scan_id": scan_id,
            "task_id": task.id
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    try:
        supabase = get_supabase()
        
        result = supabase.table("scans").select("*").eq("id", scan_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan = result.data[0]
        
        # Calculate progress (simplified)
        progress = 0
        if scan["status"] == "running":
            progress = 45  # TODO: Calculate actual progress
        elif scan["status"] == "completed":
            progress = 100
        
        return {
            "scanId": scan["id"],
            "status": scan["status"],
            "progress": progress,
            "currentPhase": "Vulnerability Detection" if scan["status"] == "running" else None,
            "startedAt": scan.get("started_at")
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")


@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get scan results"""
    try:
        supabase = get_supabase()
        
        # Get scan
        scan_result = supabase.table("scans").select("*").eq("id", scan_id).execute()
        
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan = scan_result.data[0]
        
        # Get vulnerabilities for this scan
        vulns_result = supabase.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
        vulnerabilities = vulns_result.data if vulns_result.data else []
        
        # Count by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            if severity in vuln_counts:
                vuln_counts[severity] += 1
        
        # Format vulnerabilities for response
        findings = []
        for vuln in vulnerabilities[:20]:  # Limit to 20 for response
            findings.append({
                "id": vuln["id"],
                "severity": vuln.get("severity"),
                "type": vuln.get("type"),
                "title": vuln.get("title"),
                "location": vuln.get("location"),
                "description": vuln.get("description"),
                "cve_id": vuln.get("cve_id")
            })
        
        return {
            "scanId": scan["id"],
            "status": scan["status"],
            "securityScore": scan.get("security_score"),
            "vulnerabilities": vuln_counts,
            "findings": findings
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")


@router.post("/batch")
async def start_batch_scan(data: dict, current_user: dict = Depends(get_current_user)):
    """Start batch scan"""
    try:
        urls = data.get("urls", [])
        
        if not urls or not isinstance(urls, list):
            raise HTTPException(status_code=400, detail="Invalid URLs list")
        
        if len(urls) > 50:
            raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch")
        
        supabase = get_supabase()
        
        # Create scans for each URL
        scan_ids = []
        for url in urls:
            scan_dict = {
                "id": str(uuid.uuid4()),
                "target_url": url,
                "scan_type": data.get("scan_type", "full"),
                "status": "queued",
                "security_score": None,
                "vulnerabilities_found": 0,
                "scan_options": data.get("scan_options", {}),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "started_at": None,
                "completed_at": None,
                "created_by": current_user["id"],
                "error_message": None
            }
            result = supabase.table("scans").insert(scan_dict).execute()
            if result.data:
                scan_ids.append(result.data[0]["id"])
        
        return {
            "batchId": f"batch-{datetime.now(timezone.utc).timestamp()}",
            "totalScans": len(urls),
            "scanIds": scan_ids,
            "status": "queued",
            "message": f"Batch scan of {len(urls)} URLs initiated"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start batch scan: {str(e)}")


@router.get("")
async def list_scans(skip: int = 0, limit: int = 20, current_user: dict = Depends(get_current_user)):
    """List scans"""
    try:
        supabase = get_supabase()
        
        # Filter by user
        result = supabase.table("scans").select("*").eq("created_by", current_user["id"]).order("created_at", desc=True).range(skip, skip + limit - 1).execute()
        
        scans = result.data if result.data else []
        
        # Format response
        formatted = []
        for scan in scans:
            formatted.append({
                "id": scan["id"],
                "target_url": scan["target_url"],
                "scan_type": scan["scan_type"],
                "status": scan["status"],
                "security_score": scan.get("security_score"),
                "vulnerabilities_found": scan.get("vulnerabilities_found", 0),
                "created_at": scan["created_at"]
            })
        
        return formatted
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)}")

