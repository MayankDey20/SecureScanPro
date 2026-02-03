"""
Notifications API endpoints
Manage user notifications and preferences
"""
from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from app.core.dependencies import get_current_user, get_supabase_client
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["notifications"])


# Request/Response models
class NotificationResponse(BaseModel):
    """Notification response"""
    id: str
    type: str
    title: str
    message: str
    priority: str
    data: Optional[dict]
    is_read: bool
    read_at: Optional[datetime]
    created_at: datetime


class NotificationList(BaseModel):
    """Paginated notification list"""
    items: List[NotificationResponse]
    total: int
    unread_count: int


class MarkReadRequest(BaseModel):
    """Request to mark notifications as read"""
    notification_ids: List[str] = Field(..., min_length=1)


class NotificationPreferences(BaseModel):
    """User notification preferences"""
    email_notifications: bool = True
    slack_notifications: bool = False
    in_app_notifications: bool = True
    scan_completed: bool = True
    critical_findings: bool = True
    high_findings: bool = True
    weekly_reports: bool = True


class IntegrationCreate(BaseModel):
    """Create integration request"""
    type: str = Field(..., description="Integration type: slack, webhook, teams, email")
    name: str = Field(..., max_length=100)
    config: dict = Field(..., description="Integration configuration")


class IntegrationResponse(BaseModel):
    """Integration response"""
    id: str
    type: str
    name: str
    is_active: bool
    created_at: datetime


# Endpoints
@router.get("", response_model=NotificationList)
async def list_notifications(
    unread_only: bool = Query(False, description="Only show unread notifications"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    List user notifications
    """
    try:
        service = NotificationService()
        
        notifications = await service.get_user_notifications(
            user_id=current_user["id"],
            unread_only=unread_only,
            limit=limit,
            offset=offset
        )
        
        unread_count = await service.get_unread_count(current_user["id"])
        
        # Get total count
        query = sb.table("notifications").select("id", count="exact").eq(
            "user_id", current_user["id"]
        )
        if unread_only:
            query = query.eq("is_read", False)
        total_result = query.execute()
        
        return NotificationList(
            items=[
                NotificationResponse(
                    id=n["id"],
                    type=n.get("type", "info"),
                    title=n.get("title", ""),
                    message=n.get("message", ""),
                    priority=n.get("priority", "medium"),
                    data=n.get("data"),
                    is_read=n.get("is_read", False),
                    read_at=n.get("read_at"),
                    created_at=n.get("created_at", datetime.utcnow())
                )
                for n in notifications
            ],
            total=total_result.count or len(notifications),
            unread_count=unread_count
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list notifications: {str(e)}"
        )


@router.get("/unread-count")
async def get_unread_count(
    current_user: dict = Depends(get_current_user)
):
    """
    Get count of unread notifications
    """
    try:
        service = NotificationService()
        count = await service.get_unread_count(current_user["id"])
        return {"unread_count": count}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get unread count: {str(e)}"
        )


@router.post("/mark-read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notifications_read(
    request: MarkReadRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Mark specific notifications as read
    """
    try:
        service = NotificationService()
        await service.mark_as_read(request.notification_ids, current_user["id"])
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark notifications as read: {str(e)}"
        )


@router.post("/mark-all-read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user)
):
    """
    Mark all notifications as read
    """
    try:
        service = NotificationService()
        await service.mark_all_as_read(current_user["id"])
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark all as read: {str(e)}"
        )


@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a notification
    """
    try:
        service = NotificationService()
        await service.delete_notification(notification_id, current_user["id"])
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete notification: {str(e)}"
        )


@router.get("/preferences", response_model=NotificationPreferences)
async def get_notification_preferences(
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Get user notification preferences
    """
    try:
        result = sb.table("user_profiles").select(
            "notification_preferences"
        ).eq("id", current_user["id"]).execute()
        
        if not result.data:
            return NotificationPreferences()
        
        prefs = result.data[0].get("notification_preferences", {}) or {}
        
        return NotificationPreferences(
            email_notifications=prefs.get("email_notifications", True),
            slack_notifications=prefs.get("slack_notifications", False),
            in_app_notifications=prefs.get("in_app_notifications", True),
            scan_completed=prefs.get("scan_completed", True),
            critical_findings=prefs.get("critical_findings", True),
            high_findings=prefs.get("high_findings", True),
            weekly_reports=prefs.get("weekly_reports", True)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get preferences: {str(e)}"
        )


@router.put("/preferences", response_model=NotificationPreferences)
async def update_notification_preferences(
    preferences: NotificationPreferences,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Update user notification preferences
    """
    try:
        prefs_dict = preferences.model_dump()
        
        sb.table("user_profiles").update({
            "notification_preferences": prefs_dict
        }).eq("id", current_user["id"]).execute()
        
        return preferences
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update preferences: {str(e)}"
        )


# Integration endpoints
@router.get("/integrations", response_model=List[IntegrationResponse])
async def list_integrations(
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    List notification integrations for the organization
    """
    try:
        # Get organization
        profile = sb.table("user_profiles").select(
            "organization_id"
        ).eq("id", current_user["id"]).execute()
        
        if not profile.data or not profile.data[0].get("organization_id"):
            return []
        
        org_id = profile.data[0]["organization_id"]
        
        result = sb.table("integrations").select(
            "id, type, name, is_active, created_at"
        ).eq("organization_id", org_id).execute()
        
        return [
            IntegrationResponse(
                id=i["id"],
                type=i["type"],
                name=i["name"],
                is_active=i.get("is_active", True),
                created_at=i.get("created_at", datetime.utcnow())
            )
            for i in (result.data or [])
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list integrations: {str(e)}"
        )


@router.post("/integrations", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    integration: IntegrationCreate,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Create a notification integration (Slack, webhook, etc.)
    """
    try:
        import uuid
        from datetime import timezone
        
        # Validate type
        valid_types = ["slack", "webhook", "teams", "email"]
        if integration.type not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid integration type. Must be one of: {valid_types}"
            )
        
        # Get organization
        profile = sb.table("user_profiles").select(
            "organization_id"
        ).eq("id", current_user["id"]).execute()
        
        if not profile.data or not profile.data[0].get("organization_id"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with an organization"
            )
        
        org_id = profile.data[0]["organization_id"]
        
        # Create integration
        new_integration = {
            "id": str(uuid.uuid4()),
            "organization_id": org_id,
            "type": integration.type,
            "name": integration.name,
            "config": integration.config,
            "is_active": True,
            "created_by": current_user["id"],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = sb.table("integrations").insert(new_integration).execute()
        
        return IntegrationResponse(
            id=new_integration["id"],
            type=integration.type,
            name=integration.name,
            is_active=True,
            created_at=new_integration["created_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create integration: {str(e)}"
        )


@router.delete("/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: str,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Delete a notification integration
    """
    try:
        sb.table("integrations").delete().eq("id", integration_id).execute()
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete integration: {str(e)}"
        )


@router.post("/integrations/{integration_id}/test")
async def test_integration(
    integration_id: str,
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Test a notification integration
    """
    try:
        from app.services.notification_service import (
            NotificationService, NotificationType, NotificationPriority
        )
        
        # Get integration
        result = sb.table("integrations").select("*").eq("id", integration_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        integration = result.data[0]
        config = integration.get("config", {})
        int_type = integration.get("type")
        
        service = NotificationService()
        success = False
        
        if int_type == "slack":
            success = await service._send_slack(
                "Test Notification",
                "This is a test notification from SecureScan Pro.",
                NotificationPriority.LOW,
                config
            )
        elif int_type == "teams":
            success = await service._send_teams(
                "Test Notification",
                "This is a test notification from SecureScan Pro.",
                NotificationPriority.LOW,
                config
            )
        elif int_type == "webhook":
            from app.services.notification_service import NotificationEvent
            success = await service._send_webhook(
                NotificationEvent.SCAN_COMPLETED,
                "Test Notification",
                "This is a test notification from SecureScan Pro.",
                {"test": True},
                config
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Testing not supported for {int_type} integrations"
            )
        
        if success:
            return {"status": "success", "message": "Test notification sent successfully"}
        else:
            return {"status": "failed", "message": "Failed to send test notification"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test integration: {str(e)}"
        )
