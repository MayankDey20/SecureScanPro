"""
Scheduled Scans API endpoints
Manage recurring security scans
"""
from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
import re

from app.core.dependencies import get_current_user, get_supabase_client
from app.core.config import settings
from app.models.scan import ScanTarget
from app.tasks.scheduled_tasks import (
    create_scheduled_scan,
    update_scheduled_scan,
    delete_scheduled_scan,
    toggle_scheduled_scan
)

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])


# Request/Response models
class ScheduleConfig(BaseModel):
    """Schedule configuration"""
    schedule_type: str = Field(..., description="Type: once, daily, weekly, monthly, cron")
    cron_expression: Optional[str] = Field(None, description="Cron expression for custom schedules")
    timezone: str = Field("UTC", description="Timezone for the schedule")
    
    @field_validator("schedule_type")
    @classmethod
    def validate_schedule_type(cls, v):
        valid_types = ["once", "daily", "weekly", "monthly", "cron"]
        if v not in valid_types:
            raise ValueError(f"Invalid schedule_type. Must be one of: {valid_types}")
        return v
    
    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v, info):
        if info.data.get("schedule_type") == "cron" and not v:
            raise ValueError("cron_expression required when schedule_type is 'cron'")
        if v:
            # Basic cron validation (5 or 6 parts)
            parts = v.split()
            if len(parts) not in [5, 6]:
                raise ValueError("Invalid cron expression. Expected 5 or 6 parts")
        return v


class ScheduledScanCreate(BaseModel):
    """Create scheduled scan request"""
    name: str = Field(..., min_length=1, max_length=255, description="Scan name")
    target: str = Field(..., description="Target URL or IP")
    scan_type: List[str] = Field(["full"], description="Types of scans to run")
    schedule: ScheduleConfig
    scan_options: Optional[dict] = Field(None, description="Additional scan options")
    auth_config: Optional[dict] = Field(None, description="Authentication configuration")
    notify_on_completion: bool = Field(True, description="Notify when scan completes")
    notify_on_critical: bool = Field(True, description="Notify on critical findings")
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        # Reuse validation from ScanTarget
        target_validator = ScanTarget(target=v)
        return target_validator.target
    
    @field_validator("scan_type")
    @classmethod
    def validate_scan_types(cls, v):
        valid_types = ["full", "quick", "vuln", "port", "ssl", "headers", "recon", "web"]
        for scan_type in v:
            if scan_type not in valid_types:
                raise ValueError(f"Invalid scan type: {scan_type}")
        return v


class ScheduledScanUpdate(BaseModel):
    """Update scheduled scan request"""
    name: Optional[str] = Field(None, max_length=255)
    target: Optional[str] = None
    scan_type: Optional[List[str]] = None
    schedule: Optional[ScheduleConfig] = None
    scan_options: Optional[dict] = None
    auth_config: Optional[dict] = None
    notify_on_completion: Optional[bool] = None
    notify_on_critical: Optional[bool] = None
    is_active: Optional[bool] = None


class ScheduledScanResponse(BaseModel):
    """Scheduled scan response"""
    id: str
    name: str
    target: str
    scan_type: List[str]
    schedule_type: str
    cron_expression: Optional[str]
    timezone: str
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    run_count: int
    failure_count: int
    notify_on_completion: bool
    notify_on_critical: bool
    created_at: datetime
    updated_at: Optional[datetime]


class ScheduledScanList(BaseModel):
    """Paginated list of scheduled scans"""
    items: List[ScheduledScanResponse]
    total: int
    page: int
    page_size: int


# Endpoints
@router.post("", response_model=ScheduledScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan_endpoint(
    scan_data: ScheduledScanCreate,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Create a new scheduled scan
    
    Schedule types:
    - once: Run once at the next scheduled time
    - daily: Run every day at the same time
    - weekly: Run every week on the same day
    - monthly: Run every month on the same day
    - cron: Custom cron expression
    """
    try:
        # Get user's organization
        user_id = current_user["id"]
        
        # Get organization from user profile
        profile = sb.table("user_profiles").select("organization_id").eq("id", user_id).execute()
        org_id = profile.data[0]["organization_id"] if profile.data else None
        
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with an organization"
            )
        
        # Create scheduled scan
        scheduled = await create_scheduled_scan(
            organization_id=org_id,
            user_id=user_id,
            name=scan_data.name,
            target=scan_data.target,
            schedule_type=scan_data.schedule.schedule_type,
            scan_type=scan_data.scan_type,
            scan_options=scan_data.scan_options,
            auth_config=scan_data.auth_config,
            cron_expression=scan_data.schedule.cron_expression,
            timezone_str=scan_data.schedule.timezone,
            notify_on_completion=scan_data.notify_on_completion,
            notify_on_critical=scan_data.notify_on_critical
        )
        
        return ScheduledScanResponse(
            id=scheduled["id"],
            name=scheduled["name"],
            target=scheduled["target"],
            scan_type=scheduled["scan_type"],
            schedule_type=scheduled["schedule_type"],
            cron_expression=scheduled.get("cron_expression"),
            timezone=scheduled.get("timezone", "UTC"),
            is_active=scheduled.get("is_active", True),
            last_run_at=scheduled.get("last_run_at"),
            next_run_at=scheduled.get("next_run_at"),
            run_count=scheduled.get("run_count", 0),
            failure_count=scheduled.get("failure_count", 0),
            notify_on_completion=scheduled.get("notify_on_completion", True),
            notify_on_critical=scheduled.get("notify_on_critical", True),
            created_at=scheduled.get("created_at", datetime.now(timezone.utc)),
            updated_at=scheduled.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create scheduled scan: {str(e)}"
        )


@router.get("", response_model=ScheduledScanList)
async def list_scheduled_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    List all scheduled scans for the user's organization
    """
    try:
        user_id = current_user["id"]
        
        # Get organization
        profile = sb.table("user_profiles").select("organization_id").eq("id", user_id).execute()
        org_id = profile.data[0]["organization_id"] if profile.data else None
        
        if not org_id:
            return ScheduledScanList(items=[], total=0, page=page, page_size=page_size)
        
        # Build query
        query = sb.table("scheduled_scans").select("*", count="exact").eq("organization_id", org_id)
        
        if is_active is not None:
            query = query.eq("is_active", is_active)
        
        # Pagination
        offset = (page - 1) * page_size
        query = query.order("created_at", desc=True).range(offset, offset + page_size - 1)
        
        result = query.execute()
        
        items = [
            ScheduledScanResponse(
                id=item["id"],
                name=item["name"],
                target=item["target"],
                scan_type=item.get("scan_type", []),
                schedule_type=item["schedule_type"],
                cron_expression=item.get("cron_expression"),
                timezone=item.get("timezone", "UTC"),
                is_active=item.get("is_active", True),
                last_run_at=item.get("last_run_at"),
                next_run_at=item.get("next_run_at"),
                run_count=item.get("run_count", 0),
                failure_count=item.get("failure_count", 0),
                notify_on_completion=item.get("notify_on_completion", True),
                notify_on_critical=item.get("notify_on_critical", True),
                created_at=item.get("created_at"),
                updated_at=item.get("updated_at")
            )
            for item in (result.data or [])
        ]
        
        return ScheduledScanList(
            items=items,
            total=result.count or len(items),
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list scheduled scans: {str(e)}"
        )


@router.get("/{scan_id}", response_model=ScheduledScanResponse)
async def get_scheduled_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Get a specific scheduled scan by ID
    """
    try:
        result = sb.table("scheduled_scans").select("*").eq("id", scan_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        item = result.data[0]
        
        return ScheduledScanResponse(
            id=item["id"],
            name=item["name"],
            target=item["target"],
            scan_type=item.get("scan_type", []),
            schedule_type=item["schedule_type"],
            cron_expression=item.get("cron_expression"),
            timezone=item.get("timezone", "UTC"),
            is_active=item.get("is_active", True),
            last_run_at=item.get("last_run_at"),
            next_run_at=item.get("next_run_at"),
            run_count=item.get("run_count", 0),
            failure_count=item.get("failure_count", 0),
            notify_on_completion=item.get("notify_on_completion", True),
            notify_on_critical=item.get("notify_on_critical", True),
            created_at=item.get("created_at"),
            updated_at=item.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scheduled scan: {str(e)}"
        )


@router.put("/{scan_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan_endpoint(
    scan_id: str,
    scan_data: ScheduledScanUpdate,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Update a scheduled scan
    """
    try:
        # Build update dict
        updates = {}
        
        if scan_data.name is not None:
            updates["name"] = scan_data.name
        if scan_data.target is not None:
            updates["target"] = scan_data.target
        if scan_data.scan_type is not None:
            updates["scan_type"] = scan_data.scan_type
        if scan_data.schedule is not None:
            updates["schedule_type"] = scan_data.schedule.schedule_type
            updates["cron_expression"] = scan_data.schedule.cron_expression
            updates["timezone"] = scan_data.schedule.timezone
        if scan_data.scan_options is not None:
            updates["scan_options"] = scan_data.scan_options
        if scan_data.auth_config is not None:
            updates["auth_config"] = scan_data.auth_config
        if scan_data.notify_on_completion is not None:
            updates["notify_on_completion"] = scan_data.notify_on_completion
        if scan_data.notify_on_critical is not None:
            updates["notify_on_critical"] = scan_data.notify_on_critical
        if scan_data.is_active is not None:
            updates["is_active"] = scan_data.is_active
        
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        updated = await update_scheduled_scan(scan_id, updates)
        
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        return ScheduledScanResponse(
            id=updated["id"],
            name=updated["name"],
            target=updated["target"],
            scan_type=updated.get("scan_type", []),
            schedule_type=updated["schedule_type"],
            cron_expression=updated.get("cron_expression"),
            timezone=updated.get("timezone", "UTC"),
            is_active=updated.get("is_active", True),
            last_run_at=updated.get("last_run_at"),
            next_run_at=updated.get("next_run_at"),
            run_count=updated.get("run_count", 0),
            failure_count=updated.get("failure_count", 0),
            notify_on_completion=updated.get("notify_on_completion", True),
            notify_on_critical=updated.get("notify_on_critical", True),
            created_at=updated.get("created_at"),
            updated_at=updated.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update scheduled scan: {str(e)}"
        )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan_endpoint(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Delete a scheduled scan
    """
    try:
        # Verify scan exists and user has access
        result = sb.table("scheduled_scans").select("id").eq("id", scan_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        await delete_scheduled_scan(scan_id)
        return None
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete scheduled scan: {str(e)}"
        )


@router.post("/{scan_id}/toggle", response_model=ScheduledScanResponse)
async def toggle_scheduled_scan_endpoint(
    scan_id: str,
    enable: bool = Query(..., description="Enable or disable the scan"),
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Enable or disable a scheduled scan
    """
    try:
        toggled = await toggle_scheduled_scan(scan_id, enable)
        
        if not toggled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        return ScheduledScanResponse(
            id=toggled["id"],
            name=toggled["name"],
            target=toggled["target"],
            scan_type=toggled.get("scan_type", []),
            schedule_type=toggled["schedule_type"],
            cron_expression=toggled.get("cron_expression"),
            timezone=toggled.get("timezone", "UTC"),
            is_active=toggled.get("is_active", True),
            last_run_at=toggled.get("last_run_at"),
            next_run_at=toggled.get("next_run_at"),
            run_count=toggled.get("run_count", 0),
            failure_count=toggled.get("failure_count", 0),
            notify_on_completion=toggled.get("notify_on_completion", True),
            notify_on_critical=toggled.get("notify_on_critical", True),
            created_at=toggled.get("created_at"),
            updated_at=toggled.get("updated_at")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to toggle scheduled scan: {str(e)}"
        )


@router.post("/{scan_id}/run-now", status_code=status.HTTP_202_ACCEPTED)
async def run_scheduled_scan_now(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Trigger a scheduled scan to run immediately
    """
    try:
        from app.tasks.scan_tasks import run_scan_task
        import uuid
        
        # Get scheduled scan
        result = sb.table("scheduled_scans").select("*").eq("id", scan_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        scheduled = result.data[0]
        
        # Create new scan
        new_scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        new_scan = {
            "id": new_scan_id,
            "organization_id": scheduled.get("organization_id"),
            "asset_id": scheduled.get("asset_id"),
            "target": scheduled["target"],
            "scan_type": scheduled.get("scan_type", ["full"]),
            "status": "pending",
            "scan_options": scheduled.get("scan_options", {}),
            "auth_config": scheduled.get("auth_config"),
            "triggered_by": "manual",
            "scheduled_at": now.isoformat(),
            "created_at": now.isoformat()
        }
        
        sb.table("scans").insert(new_scan).execute()
        
        # Trigger scan
        run_scan_task.delay(
            scan_id=new_scan_id,
            target=scheduled["target"],
            scan_types=scheduled.get("scan_type", ["full"])
        )
        
        return {
            "message": "Scan triggered successfully",
            "scan_id": new_scan_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger scan: {str(e)}"
        )


@router.get("/{scan_id}/history")
async def get_scheduled_scan_history(
    scan_id: str,
    limit: int = Query(10, ge=1, le=100, description="Number of past runs to return"),
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Get the run history for a scheduled scan
    """
    try:
        # Get scheduled scan to verify it exists
        scheduled = sb.table("scheduled_scans").select("id, target").eq("id", scan_id).execute()
        
        if not scheduled.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scheduled scan not found"
            )
        
        # Get recent scans triggered by this schedule
        scans = sb.table("scans").select(
            "id, status, started_at, completed_at, vulnerabilities_count, created_at"
        ).eq(
            "target", scheduled.data[0]["target"]
        ).eq(
            "triggered_by", "scheduled"
        ).order(
            "created_at", desc=True
        ).limit(limit).execute()
        
        return {
            "scheduled_scan_id": scan_id,
            "runs": scans.data or []
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan history: {str(e)}"
        )
