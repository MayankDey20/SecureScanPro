"""
Notification Service for SecureScan Pro
Handles email, Slack, webhook, and in-app notifications
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from enum import Enum
import logging
import httpx
import json
import uuid

from app.core.supabase_client import get_supabase
from app.core.config import settings

logger = logging.getLogger(__name__)


class NotificationType(str, Enum):
    """Types of notifications"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    IN_APP = "in_app"
    SMS = "sms"
    TEAMS = "teams"


class NotificationEvent(str, Enum):
    """Events that trigger notifications"""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    CRITICAL_FOUND = "critical_found"
    HIGH_FOUND = "high_found"
    WEEKLY_REPORT = "weekly_report"
    USER_INVITED = "user_invited"
    ASSET_ADDED = "asset_added"
    SCHEDULED_SCAN_FAILED = "scheduled_scan_failed"


class NotificationPriority(str, Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Notification templates
NOTIFICATION_TEMPLATES = {
    NotificationEvent.SCAN_STARTED: {
        "title": "Scan Started",
        "message": "Security scan for {target} has started.",
        "priority": NotificationPriority.LOW
    },
    NotificationEvent.SCAN_COMPLETED: {
        "title": "Scan Completed",
        "message": "Security scan for {target} has completed. Found {total_vulns} vulnerabilities ({critical} critical, {high} high).",
        "priority": NotificationPriority.MEDIUM
    },
    NotificationEvent.SCAN_FAILED: {
        "title": "Scan Failed",
        "message": "Security scan for {target} has failed: {error}",
        "priority": NotificationPriority.HIGH
    },
    NotificationEvent.CRITICAL_FOUND: {
        "title": "Critical Vulnerability Found",
        "message": "Critical vulnerability '{vuln_name}' found on {target}. Immediate action recommended.",
        "priority": NotificationPriority.CRITICAL
    },
    NotificationEvent.HIGH_FOUND: {
        "title": "High Severity Vulnerability Found",
        "message": "High severity vulnerability '{vuln_name}' found on {target}.",
        "priority": NotificationPriority.HIGH
    },
    NotificationEvent.WEEKLY_REPORT: {
        "title": "Weekly Security Report",
        "message": "Your weekly security report is ready. {scans_count} scans, {new_vulns} new vulnerabilities.",
        "priority": NotificationPriority.LOW
    },
    NotificationEvent.USER_INVITED: {
        "title": "Team Invitation",
        "message": "You've been invited to join {org_name} on SecureScan Pro.",
        "priority": NotificationPriority.MEDIUM
    },
    NotificationEvent.ASSET_ADDED: {
        "title": "New Asset Added",
        "message": "New asset '{asset_name}' has been added to monitoring.",
        "priority": NotificationPriority.LOW
    },
    NotificationEvent.SCHEDULED_SCAN_FAILED: {
        "title": "Scheduled Scan Failed",
        "message": "Scheduled scan '{schedule_name}' for {target} has failed multiple times.",
        "priority": NotificationPriority.HIGH
    }
}


class NotificationService:
    """Service for managing and sending notifications"""
    
    def __init__(self):
        self.sb = get_supabase()
    
    async def send_notification(
        self,
        event: NotificationEvent,
        organization_id: str,
        user_ids: Optional[List[str]] = None,
        data: Dict[str, Any] = None,
        channels: Optional[List[NotificationType]] = None
    ) -> Dict[str, Any]:
        """
        Send notifications through configured channels
        
        Args:
            event: The notification event type
            organization_id: Organization ID
            user_ids: Specific users to notify (None = org preferences)
            data: Data to fill in template placeholders
            channels: Specific channels to use (None = all configured)
        
        Returns:
            Status of notification delivery
        """
        template = NOTIFICATION_TEMPLATES.get(event, {})
        data = data or {}
        
        # Format message
        title = template.get("title", "Notification")
        message = template.get("message", "").format(**data)
        priority = template.get("priority", NotificationPriority.MEDIUM)
        
        results = {
            "event": event.value,
            "channels": {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Get organization notification settings
        integrations = await self._get_integrations(organization_id)
        
        # Determine which channels to use
        if channels is None:
            channels = [NotificationType.IN_APP]  # Default to in-app
            
            # Add configured channels
            for integration in integrations:
                int_type = integration.get("type")
                if int_type in [t.value for t in NotificationType]:
                    channels.append(NotificationType(int_type))
        
        # Send through each channel
        for channel in set(channels):
            try:
                if channel == NotificationType.IN_APP:
                    success = await self._send_in_app(
                        organization_id, user_ids, title, message, event, priority, data
                    )
                    results["channels"]["in_app"] = {"success": success}
                
                elif channel == NotificationType.EMAIL:
                    email_config = self._get_integration_config(integrations, "email")
                    success = await self._send_email(
                        organization_id, user_ids, title, message, email_config
                    )
                    results["channels"]["email"] = {"success": success}
                
                elif channel == NotificationType.SLACK:
                    slack_config = self._get_integration_config(integrations, "slack")
                    if slack_config:
                        success = await self._send_slack(
                            title, message, priority, slack_config
                        )
                        results["channels"]["slack"] = {"success": success}
                
                elif channel == NotificationType.WEBHOOK:
                    webhook_configs = self._get_all_integration_configs(integrations, "webhook")
                    for i, webhook_config in enumerate(webhook_configs):
                        success = await self._send_webhook(
                            event, title, message, data, webhook_config
                        )
                        results["channels"][f"webhook_{i}"] = {"success": success}
                
                elif channel == NotificationType.TEAMS:
                    teams_config = self._get_integration_config(integrations, "teams")
                    if teams_config:
                        success = await self._send_teams(
                            title, message, priority, teams_config
                        )
                        results["channels"]["teams"] = {"success": success}
                        
            except Exception as e:
                logger.error(f"Failed to send {channel.value} notification: {e}")
                results["channels"][channel.value] = {"success": False, "error": str(e)}
        
        return results
    
    async def _send_in_app(
        self,
        organization_id: str,
        user_ids: Optional[List[str]],
        title: str,
        message: str,
        event: NotificationEvent,
        priority: NotificationPriority,
        data: Dict
    ) -> bool:
        """Send in-app notification"""
        try:
            # Get users to notify
            if not user_ids:
                # Get all org users based on notification preferences
                users = self.sb.table("user_profiles").select("id").eq(
                    "organization_id", organization_id
                ).execute()
                user_ids = [u["id"] for u in (users.data or [])]
            
            # Create notifications
            notifications = []
            for user_id in user_ids:
                notifications.append({
                    "id": str(uuid.uuid4()),
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "type": event.value,
                    "title": title,
                    "message": message,
                    "priority": priority.value,
                    "data": data,
                    "is_read": False,
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
            
            if notifications:
                self.sb.table("notifications").insert(notifications).execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send in-app notification: {e}")
            return False
    
    async def _send_email(
        self,
        organization_id: str,
        user_ids: Optional[List[str]],
        title: str,
        message: str,
        config: Optional[Dict]
    ) -> bool:
        """Send email notification"""
        try:
            # Get email addresses
            if not user_ids:
                users = self.sb.table("user_profiles").select("email").eq(
                    "organization_id", organization_id
                ).eq("email_notifications", True).execute()
                emails = [u["email"] for u in (users.data or []) if u.get("email")]
            else:
                users = self.sb.table("user_profiles").select("email").in_(
                    "id", user_ids
                ).eq("email_notifications", True).execute()
                emails = [u["email"] for u in (users.data or []) if u.get("email")]
            
            if not emails:
                return True  # No emails to send
            
            # Use configured email service or default
            # This is a placeholder - integrate with actual email service
            # Options: SendGrid, SES, Mailgun, SMTP
            
            email_service = config.get("service", "smtp") if config else "smtp"
            
            if email_service == "sendgrid":
                return await self._send_sendgrid_email(emails, title, message, config)
            elif email_service == "ses":
                return await self._send_ses_email(emails, title, message, config)
            else:
                # Log for now - implement SMTP later
                logger.info(f"Would send email to {emails}: {title}")
                return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def _send_sendgrid_email(
        self,
        emails: List[str],
        title: str,
        message: str,
        config: Dict
    ) -> bool:
        """Send email via SendGrid"""
        api_key = config.get("api_key")
        from_email = config.get("from_email", "noreply@securescan.pro")
        
        if not api_key:
            logger.error("SendGrid API key not configured")
            return False
        
        async with httpx.AsyncClient() as client:
            for email in emails:
                try:
                    response = await client.post(
                        "https://api.sendgrid.com/v3/mail/send",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "personalizations": [{"to": [{"email": email}]}],
                            "from": {"email": from_email, "name": "SecureScan Pro"},
                            "subject": f"[SecureScan] {title}",
                            "content": [
                                {"type": "text/plain", "value": message},
                                {"type": "text/html", "value": self._format_email_html(title, message)}
                            ]
                        }
                    )
                    
                    if response.status_code not in [200, 202]:
                        logger.error(f"SendGrid error: {response.text}")
                        
                except Exception as e:
                    logger.error(f"Failed to send to {email}: {e}")
        
        return True
    
    async def _send_ses_email(
        self,
        emails: List[str],
        title: str,
        message: str,
        config: Dict
    ) -> bool:
        """Send email via AWS SES"""
        # Placeholder for SES integration
        logger.info(f"Would send SES email to {emails}: {title}")
        return True
    
    async def _send_slack(
        self,
        title: str,
        message: str,
        priority: NotificationPriority,
        config: Dict
    ) -> bool:
        """Send Slack notification"""
        webhook_url = config.get("webhook_url")
        channel = config.get("channel")
        
        if not webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        # Color based on priority
        colors = {
            NotificationPriority.CRITICAL: "#dc3545",
            NotificationPriority.HIGH: "#fd7e14",
            NotificationPriority.MEDIUM: "#ffc107",
            NotificationPriority.LOW: "#28a745"
        }
        
        payload = {
            "attachments": [
                {
                    "color": colors.get(priority, "#6c757d"),
                    "title": title,
                    "text": message,
                    "footer": "SecureScan Pro",
                    "ts": int(datetime.now(timezone.utc).timestamp())
                }
            ]
        }
        
        if channel:
            payload["channel"] = channel
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload)
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    async def _send_teams(
        self,
        title: str,
        message: str,
        priority: NotificationPriority,
        config: Dict
    ) -> bool:
        """Send Microsoft Teams notification"""
        webhook_url = config.get("webhook_url")
        
        if not webhook_url:
            logger.error("Teams webhook URL not configured")
            return False
        
        # Color based on priority
        colors = {
            NotificationPriority.CRITICAL: "dc3545",
            NotificationPriority.HIGH: "fd7e14",
            NotificationPriority.MEDIUM: "ffc107",
            NotificationPriority.LOW: "28a745"
        }
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": colors.get(priority, "6c757d"),
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "text": message,
                "facts": [
                    {
                        "name": "Priority",
                        "value": priority.value.upper()
                    },
                    {
                        "name": "Time",
                        "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    }
                ]
            }]
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload)
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False
    
    async def _send_webhook(
        self,
        event: NotificationEvent,
        title: str,
        message: str,
        data: Dict,
        config: Dict
    ) -> bool:
        """Send webhook notification"""
        url = config.get("url")
        secret = config.get("secret")
        headers = config.get("headers", {})
        
        if not url:
            logger.error("Webhook URL not configured")
            return False
        
        payload = {
            "event": event.value,
            "title": title,
            "message": message,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "securescan-pro"
        }
        
        # Add signature if secret configured
        if secret:
            import hmac
            import hashlib
            signature = hmac.new(
                secret.encode(),
                json.dumps(payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecureScan-Signature"] = f"sha256={signature}"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10.0
                )
                return response.status_code in [200, 201, 202, 204]
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False
    
    async def _get_integrations(self, organization_id: str) -> List[Dict]:
        """Get organization integrations"""
        try:
            result = self.sb.table("integrations").select("*").eq(
                "organization_id", organization_id
            ).eq("is_active", True).execute()
            return result.data or []
        except Exception:
            return []
    
    def _get_integration_config(
        self,
        integrations: List[Dict],
        int_type: str
    ) -> Optional[Dict]:
        """Get config for a specific integration type"""
        for integration in integrations:
            if integration.get("type") == int_type:
                return integration.get("config", {})
        return None
    
    def _get_all_integration_configs(
        self,
        integrations: List[Dict],
        int_type: str
    ) -> List[Dict]:
        """Get all configs for a specific integration type"""
        configs = []
        for integration in integrations:
            if integration.get("type") == int_type:
                configs.append(integration.get("config", {}))
        return configs
    
    def _format_email_html(self, title: str, message: str) -> str:
        """Format email as HTML"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1a365d; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f7fafc; }}
                .footer {{ padding: 10px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SecureScan Pro</h1>
                </div>
                <div class="content">
                    <h2>{title}</h2>
                    <p>{message}</p>
                </div>
                <div class="footer">
                    <p>This is an automated message from SecureScan Pro.</p>
                    <p>Configure your notification preferences in settings.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    # Methods for managing notifications
    async def get_user_notifications(
        self,
        user_id: str,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """Get notifications for a user"""
        query = self.sb.table("notifications").select("*").eq("user_id", user_id)
        
        if unread_only:
            query = query.eq("is_read", False)
        
        result = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()
        return result.data or []
    
    async def mark_as_read(
        self,
        notification_ids: List[str],
        user_id: str
    ) -> bool:
        """Mark notifications as read"""
        try:
            self.sb.table("notifications").update({
                "is_read": True,
                "read_at": datetime.now(timezone.utc).isoformat()
            }).in_("id", notification_ids).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to mark notifications as read: {e}")
            return False
    
    async def mark_all_as_read(self, user_id: str) -> bool:
        """Mark all notifications as read for a user"""
        try:
            self.sb.table("notifications").update({
                "is_read": True,
                "read_at": datetime.now(timezone.utc).isoformat()
            }).eq("user_id", user_id).eq("is_read", False).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to mark all notifications as read: {e}")
            return False
    
    async def delete_notification(
        self,
        notification_id: str,
        user_id: str
    ) -> bool:
        """Delete a notification"""
        try:
            self.sb.table("notifications").delete().eq(
                "id", notification_id
            ).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to delete notification: {e}")
            return False
    
    async def get_unread_count(self, user_id: str) -> int:
        """Get count of unread notifications"""
        try:
            result = self.sb.table("notifications").select(
                "id", count="exact"
            ).eq("user_id", user_id).eq("is_read", False).execute()
            return result.count or 0
        except Exception:
            return 0


# Helper function for quick notifications
async def notify(
    event: NotificationEvent,
    organization_id: str,
    data: Dict = None,
    user_ids: List[str] = None,
    channels: List[NotificationType] = None
):
    """
    Quick helper to send notifications
    
    Usage:
        await notify(
            NotificationEvent.SCAN_COMPLETED,
            org_id,
            {"target": "example.com", "total_vulns": 5, "critical": 1, "high": 2}
        )
    """
    service = NotificationService()
    return await service.send_notification(
        event=event,
        organization_id=organization_id,
        user_ids=user_ids,
        data=data,
        channels=channels
    )
