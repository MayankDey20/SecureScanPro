"""
Vulnerability Management API endpoints
Handle false positives, status changes, and vulnerability workflow
"""
from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from enum import Enum
import uuid

from app.core.dependencies import get_current_user, get_supabase_client
from app.core.rbac import Permission, require_permission

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


class VulnerabilityStatus(str, Enum):
    """Vulnerability status states"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"


class VulnerabilityPriority(str, Enum):
    """Vulnerability priority for remediation"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# Request/Response models
class VulnerabilityResponse(BaseModel):
    """Vulnerability response"""
    id: str
    scan_id: str
    name: str
    description: Optional[str]
    severity: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    url: Optional[str]
    evidence: Optional[str]
    remediation: Optional[str]
    status: str
    priority: Optional[str]
    assignee_id: Optional[str]
    is_false_positive: bool
    false_positive_reason: Optional[str]
    resolved_at: Optional[datetime]
    created_at: datetime


class VulnerabilityList(BaseModel):
    """Paginated vulnerability list"""
    items: List[VulnerabilityResponse]
    total: int
    page: int
    page_size: int


class StatusUpdate(BaseModel):
    """Update vulnerability status"""
    status: VulnerabilityStatus
    note: Optional[str] = Field(None, max_length=1000)


class FalsePositiveRequest(BaseModel):
    """Mark as false positive request"""
    reason: str = Field(..., min_length=10, max_length=1000, description="Detailed reason why this is a false positive")
    evidence: Optional[str] = Field(None, max_length=2000, description="Supporting evidence")
    apply_to_similar: bool = Field(False, description="Apply to similar vulnerabilities")


class AssignRequest(BaseModel):
    """Assign vulnerability request"""
    assignee_id: str
    priority: Optional[VulnerabilityPriority] = None
    due_date: Optional[datetime] = None
    note: Optional[str] = None


class BulkStatusUpdate(BaseModel):
    """Bulk status update request"""
    vulnerability_ids: List[str] = Field(..., min_length=1, max_length=100)
    status: VulnerabilityStatus
    note: Optional[str] = None


class BulkFalsePositive(BaseModel):
    """Bulk false positive request"""
    vulnerability_ids: List[str] = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=10, max_length=1000)


class VulnerabilityComment(BaseModel):
    """Vulnerability comment"""
    id: str
    vulnerability_id: str
    user_id: str
    user_name: Optional[str]
    comment: str
    created_at: datetime


class CommentCreate(BaseModel):
    """Create comment request"""
    comment: str = Field(..., min_length=1, max_length=2000)


class VulnerabilityHistory(BaseModel):
    """Vulnerability history entry"""
    id: str
    vulnerability_id: str
    action: str
    old_value: Optional[str]
    new_value: Optional[str]
    user_id: str
    user_name: Optional[str]
    note: Optional[str]
    created_at: datetime


# Endpoints
@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    status: Optional[VulnerabilityStatus] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    is_false_positive: Optional[bool] = Query(None, description="Filter false positives"),
    assignee_id: Optional[str] = Query(None, description="Filter by assignee"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: dict = Depends(require_permission(Permission.VULN_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    List vulnerabilities with filtering
    """
    try:
        query = sb.table("vulnerabilities").select("*", count="exact")
        
        if scan_id:
            query = query.eq("scan_id", scan_id)
        if status:
            query = query.eq("status", status.value)
        if severity:
            query = query.eq("severity", severity)
        if is_false_positive is not None:
            query = query.eq("is_false_positive", is_false_positive)
        if assignee_id:
            query = query.eq("assignee_id", assignee_id)
        
        # Pagination
        offset = (page - 1) * page_size
        query = query.order("severity_score", desc=True).range(offset, offset + page_size - 1)
        
        result = query.execute()
        
        items = [
            VulnerabilityResponse(
                id=v["id"],
                scan_id=v["scan_id"],
                name=v.get("name", "Unknown"),
                description=v.get("description"),
                severity=v.get("severity", "info"),
                cvss_score=v.get("cvss_score"),
                cve_id=v.get("cve_id"),
                url=v.get("url"),
                evidence=v.get("evidence"),
                remediation=v.get("remediation"),
                status=v.get("status", "open"),
                priority=v.get("priority"),
                assignee_id=v.get("assignee_id"),
                is_false_positive=v.get("is_false_positive", False),
                false_positive_reason=v.get("false_positive_reason"),
                resolved_at=v.get("resolved_at"),
                created_at=v.get("created_at", datetime.now(timezone.utc))
            )
            for v in (result.data or [])
        ]
        
        return VulnerabilityList(
            items=items,
            total=result.count or len(items),
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list vulnerabilities: {str(e)}"
        )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    current_user: dict = Depends(require_permission(Permission.VULN_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Get vulnerability details
    """
    try:
        result = sb.table("vulnerabilities").select("*").eq("id", vuln_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        v = result.data[0]
        
        return VulnerabilityResponse(
            id=v["id"],
            scan_id=v["scan_id"],
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "info"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            url=v.get("url"),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            status=v.get("status", "open"),
            priority=v.get("priority"),
            assignee_id=v.get("assignee_id"),
            is_false_positive=v.get("is_false_positive", False),
            false_positive_reason=v.get("false_positive_reason"),
            resolved_at=v.get("resolved_at"),
            created_at=v.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get vulnerability: {str(e)}"
        )


@router.put("/{vuln_id}/status", response_model=VulnerabilityResponse)
async def update_vulnerability_status(
    vuln_id: str,
    update: StatusUpdate,
    current_user: dict = Depends(require_permission(Permission.VULN_EDIT_STATUS)),
    sb = Depends(get_supabase_client)
):
    """
    Update vulnerability status
    """
    try:
        # Get current vulnerability
        current = sb.table("vulnerabilities").select("status").eq("id", vuln_id).execute()
        
        if not current.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        old_status = current.data[0].get("status")
        
        # Prepare update
        updates = {
            "status": update.status.value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Set resolved_at if resolved
        if update.status == VulnerabilityStatus.RESOLVED:
            updates["resolved_at"] = datetime.now(timezone.utc).isoformat()
        
        # Update vulnerability
        result = sb.table("vulnerabilities").update(updates).eq("id", vuln_id).execute()
        
        # Log history
        await _log_vulnerability_history(
            sb,
            vuln_id,
            "status_change",
            old_status,
            update.status.value,
            current_user["id"],
            update.note
        )
        
        v = result.data[0]
        
        return VulnerabilityResponse(
            id=v["id"],
            scan_id=v["scan_id"],
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "info"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            url=v.get("url"),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            status=v.get("status", "open"),
            priority=v.get("priority"),
            assignee_id=v.get("assignee_id"),
            is_false_positive=v.get("is_false_positive", False),
            false_positive_reason=v.get("false_positive_reason"),
            resolved_at=v.get("resolved_at"),
            created_at=v.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update status: {str(e)}"
        )


@router.post("/{vuln_id}/false-positive", response_model=VulnerabilityResponse)
async def mark_false_positive(
    vuln_id: str,
    request: FalsePositiveRequest,
    current_user: dict = Depends(require_permission(Permission.VULN_MARK_FP)),
    sb = Depends(get_supabase_client)
):
    """
    Mark a vulnerability as false positive
    """
    try:
        # Get current vulnerability
        current = sb.table("vulnerabilities").select("*").eq("id", vuln_id).execute()
        
        if not current.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        vuln = current.data[0]
        
        # Update vulnerability
        updates = {
            "is_false_positive": True,
            "false_positive_reason": request.reason,
            "false_positive_evidence": request.evidence,
            "false_positive_by": current_user["id"],
            "false_positive_at": datetime.now(timezone.utc).isoformat(),
            "status": VulnerabilityStatus.FALSE_POSITIVE.value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = sb.table("vulnerabilities").update(updates).eq("id", vuln_id).execute()
        
        # Log history
        await _log_vulnerability_history(
            sb,
            vuln_id,
            "marked_false_positive",
            "open",
            "false_positive",
            current_user["id"],
            request.reason
        )
        
        # Apply to similar if requested
        if request.apply_to_similar:
            await _apply_fp_to_similar(
                sb,
                vuln,
                request.reason,
                current_user["id"]
            )
        
        v = result.data[0]
        
        return VulnerabilityResponse(
            id=v["id"],
            scan_id=v["scan_id"],
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "info"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            url=v.get("url"),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            status=v.get("status", "open"),
            priority=v.get("priority"),
            assignee_id=v.get("assignee_id"),
            is_false_positive=v.get("is_false_positive", False),
            false_positive_reason=v.get("false_positive_reason"),
            resolved_at=v.get("resolved_at"),
            created_at=v.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark false positive: {str(e)}"
        )


@router.post("/{vuln_id}/unmark-false-positive", response_model=VulnerabilityResponse)
async def unmark_false_positive(
    vuln_id: str,
    current_user: dict = Depends(require_permission(Permission.VULN_MARK_FP)),
    sb = Depends(get_supabase_client)
):
    """
    Unmark a vulnerability as false positive (reopen)
    """
    try:
        updates = {
            "is_false_positive": False,
            "false_positive_reason": None,
            "false_positive_evidence": None,
            "false_positive_by": None,
            "false_positive_at": None,
            "status": VulnerabilityStatus.OPEN.value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = sb.table("vulnerabilities").update(updates).eq("id", vuln_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        # Log history
        await _log_vulnerability_history(
            sb,
            vuln_id,
            "unmarked_false_positive",
            "false_positive",
            "open",
            current_user["id"],
            None
        )
        
        v = result.data[0]
        
        return VulnerabilityResponse(
            id=v["id"],
            scan_id=v["scan_id"],
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "info"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            url=v.get("url"),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            status=v.get("status", "open"),
            priority=v.get("priority"),
            assignee_id=v.get("assignee_id"),
            is_false_positive=v.get("is_false_positive", False),
            false_positive_reason=v.get("false_positive_reason"),
            resolved_at=v.get("resolved_at"),
            created_at=v.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unmark false positive: {str(e)}"
        )


@router.post("/{vuln_id}/assign", response_model=VulnerabilityResponse)
async def assign_vulnerability(
    vuln_id: str,
    request: AssignRequest,
    current_user: dict = Depends(require_permission(Permission.VULN_ASSIGN)),
    sb = Depends(get_supabase_client)
):
    """
    Assign a vulnerability to a user
    """
    try:
        updates = {
            "assignee_id": request.assignee_id,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if request.priority:
            updates["priority"] = request.priority.value
        if request.due_date:
            updates["due_date"] = request.due_date.isoformat()
        
        # Update status to in_progress if currently open
        current = sb.table("vulnerabilities").select("status").eq("id", vuln_id).execute()
        if current.data and current.data[0].get("status") == "open":
            updates["status"] = VulnerabilityStatus.IN_PROGRESS.value
        
        result = sb.table("vulnerabilities").update(updates).eq("id", vuln_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found"
            )
        
        # Log history
        await _log_vulnerability_history(
            sb,
            vuln_id,
            "assigned",
            None,
            request.assignee_id,
            current_user["id"],
            request.note
        )
        
        v = result.data[0]
        
        return VulnerabilityResponse(
            id=v["id"],
            scan_id=v["scan_id"],
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            severity=v.get("severity", "info"),
            cvss_score=v.get("cvss_score"),
            cve_id=v.get("cve_id"),
            url=v.get("url"),
            evidence=v.get("evidence"),
            remediation=v.get("remediation"),
            status=v.get("status", "open"),
            priority=v.get("priority"),
            assignee_id=v.get("assignee_id"),
            is_false_positive=v.get("is_false_positive", False),
            false_positive_reason=v.get("false_positive_reason"),
            resolved_at=v.get("resolved_at"),
            created_at=v.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assign vulnerability: {str(e)}"
        )


@router.post("/bulk/status")
async def bulk_update_status(
    request: BulkStatusUpdate,
    current_user: dict = Depends(require_permission(Permission.VULN_EDIT_STATUS)),
    sb = Depends(get_supabase_client)
):
    """
    Bulk update vulnerability status
    """
    try:
        updates = {
            "status": request.status.value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if request.status == VulnerabilityStatus.RESOLVED:
            updates["resolved_at"] = datetime.now(timezone.utc).isoformat()
        
        sb.table("vulnerabilities").update(updates).in_(
            "id", request.vulnerability_ids
        ).execute()
        
        # Log history for each
        for vuln_id in request.vulnerability_ids:
            await _log_vulnerability_history(
                sb,
                vuln_id,
                "bulk_status_change",
                None,
                request.status.value,
                current_user["id"],
                request.note
            )
        
        return {
            "message": f"Updated {len(request.vulnerability_ids)} vulnerabilities",
            "status": request.status.value
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to bulk update: {str(e)}"
        )


@router.post("/bulk/false-positive")
async def bulk_mark_false_positive(
    request: BulkFalsePositive,
    current_user: dict = Depends(require_permission(Permission.VULN_MARK_FP)),
    sb = Depends(get_supabase_client)
):
    """
    Bulk mark vulnerabilities as false positive
    """
    try:
        updates = {
            "is_false_positive": True,
            "false_positive_reason": request.reason,
            "false_positive_by": current_user["id"],
            "false_positive_at": datetime.now(timezone.utc).isoformat(),
            "status": VulnerabilityStatus.FALSE_POSITIVE.value,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        sb.table("vulnerabilities").update(updates).in_(
            "id", request.vulnerability_ids
        ).execute()
        
        return {
            "message": f"Marked {len(request.vulnerability_ids)} vulnerabilities as false positive"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to bulk mark false positive: {str(e)}"
        )


@router.get("/{vuln_id}/comments", response_model=List[VulnerabilityComment])
async def get_vulnerability_comments(
    vuln_id: str,
    current_user: dict = Depends(require_permission(Permission.VULN_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Get comments for a vulnerability
    """
    try:
        result = sb.table("vulnerability_comments").select(
            "*, user_profiles(full_name)"
        ).eq("vulnerability_id", vuln_id).order("created_at", desc=True).execute()
        
        return [
            VulnerabilityComment(
                id=c["id"],
                vulnerability_id=c["vulnerability_id"],
                user_id=c["user_id"],
                user_name=c.get("user_profiles", {}).get("full_name") if c.get("user_profiles") else None,
                comment=c["comment"],
                created_at=c["created_at"]
            )
            for c in (result.data or [])
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get comments: {str(e)}"
        )


@router.post("/{vuln_id}/comments", response_model=VulnerabilityComment, status_code=status.HTTP_201_CREATED)
async def add_vulnerability_comment(
    vuln_id: str,
    comment: CommentCreate,
    current_user: dict = Depends(require_permission(Permission.VULN_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Add a comment to a vulnerability
    """
    try:
        new_comment = {
            "id": str(uuid.uuid4()),
            "vulnerability_id": vuln_id,
            "user_id": current_user["id"],
            "comment": comment.comment,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        sb.table("vulnerability_comments").insert(new_comment).execute()
        
        # Get user name
        user = sb.table("user_profiles").select("full_name").eq("id", current_user["id"]).execute()
        user_name = user.data[0].get("full_name") if user.data else None
        
        return VulnerabilityComment(
            id=new_comment["id"],
            vulnerability_id=vuln_id,
            user_id=current_user["id"],
            user_name=user_name,
            comment=comment.comment,
            created_at=new_comment["created_at"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add comment: {str(e)}"
        )


@router.get("/{vuln_id}/history", response_model=List[VulnerabilityHistory])
async def get_vulnerability_history(
    vuln_id: str,
    current_user: dict = Depends(require_permission(Permission.VULN_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Get history for a vulnerability
    """
    try:
        result = sb.table("vulnerability_history").select(
            "*, user_profiles(full_name)"
        ).eq("vulnerability_id", vuln_id).order("created_at", desc=True).execute()
        
        return [
            VulnerabilityHistory(
                id=h["id"],
                vulnerability_id=h["vulnerability_id"],
                action=h["action"],
                old_value=h.get("old_value"),
                new_value=h.get("new_value"),
                user_id=h["user_id"],
                user_name=h.get("user_profiles", {}).get("full_name") if h.get("user_profiles") else None,
                note=h.get("note"),
                created_at=h["created_at"]
            )
            for h in (result.data or [])
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get history: {str(e)}"
        )


# Helper functions
async def _log_vulnerability_history(
    sb,
    vulnerability_id: str,
    action: str,
    old_value: Optional[str],
    new_value: Optional[str],
    user_id: str,
    note: Optional[str]
):
    """Log a vulnerability history entry"""
    try:
        sb.table("vulnerability_history").insert({
            "id": str(uuid.uuid4()),
            "vulnerability_id": vulnerability_id,
            "action": action,
            "old_value": old_value,
            "new_value": new_value,
            "user_id": user_id,
            "note": note,
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        # Don't fail if history logging fails
        import logging
        logging.error(f"Failed to log vulnerability history: {e}")


async def _apply_fp_to_similar(
    sb,
    vuln: dict,
    reason: str,
    user_id: str
):
    """Apply false positive status to similar vulnerabilities"""
    try:
        # Find similar vulnerabilities by name and type
        similar = sb.table("vulnerabilities").select("id").eq(
            "name", vuln.get("name")
        ).eq(
            "is_false_positive", False
        ).neq("id", vuln["id"]).execute()
        
        if similar.data:
            ids = [v["id"] for v in similar.data]
            
            sb.table("vulnerabilities").update({
                "is_false_positive": True,
                "false_positive_reason": f"Similar to {vuln['id']}: {reason}",
                "false_positive_by": user_id,
                "false_positive_at": datetime.now(timezone.utc).isoformat(),
                "status": VulnerabilityStatus.FALSE_POSITIVE.value,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }).in_("id", ids).execute()
            
    except Exception as e:
        import logging
        logging.error(f"Failed to apply FP to similar: {e}")
