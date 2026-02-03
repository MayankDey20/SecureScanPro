"""
Scheduled Scan Tasks for SecureScan Pro
Handles recurring security scans using Celery Beat
"""
from celery import shared_task
from celery.schedules import crontab
from datetime import datetime, timezone, timedelta
import logging
from typing import Dict, Any, List, Optional
import uuid

from app.celery_worker import celery_app
from app.core.supabase_client import get_supabase
from app.tasks.scan_tasks import run_scan_task

logger = logging.getLogger(__name__)


# Celery Beat schedule configuration
celery_app.conf.beat_schedule = {
    # Check for scheduled scans every minute
    'check-scheduled-scans': {
        'task': 'app.tasks.scheduled_tasks.check_and_run_scheduled_scans',
        'schedule': 60.0,  # Every 60 seconds
    },
    # Sync threat intelligence daily at 2 AM
    'sync-threat-intel': {
        'task': 'app.tasks.scheduled_tasks.sync_threat_intelligence',
        'schedule': crontab(hour=2, minute=0),
    },
    # Clean up old scan data weekly
    'cleanup-old-scans': {
        'task': 'app.tasks.scheduled_tasks.cleanup_old_data',
        'schedule': crontab(day_of_week=0, hour=3, minute=0),
    },
    # Generate weekly reports every Monday at 8 AM
    'generate-weekly-reports': {
        'task': 'app.tasks.scheduled_tasks.generate_weekly_reports',
        'schedule': crontab(day_of_week=1, hour=8, minute=0),
    },
}


@celery_app.task(bind=True)
def check_and_run_scheduled_scans(self):
    """
    Check for scheduled scans that need to run and trigger them
    """
    logger.info("Checking for scheduled scans...")
    
    try:
        sb = get_supabase()
        now = datetime.now(timezone.utc)
        
        # Get all active scheduled scans where next_run_at <= now
        result = sb.table("scheduled_scans").select("*").eq(
            "is_active", True
        ).lte(
            "next_run_at", now.isoformat()
        ).execute()
        
        scheduled_scans = result.data if result.data else []
        
        logger.info(f"Found {len(scheduled_scans)} scheduled scans to run")
        
        for scheduled in scheduled_scans:
            try:
                # Create a new scan
                scan_id = str(uuid.uuid4())
                
                new_scan = {
                    "id": scan_id,
                    "organization_id": scheduled.get("organization_id"),
                    "asset_id": scheduled.get("asset_id"),
                    "target": scheduled["target"],
                    "scan_type": scheduled.get("scan_type", ["full"]),
                    "status": "pending",
                    "scan_options": scheduled.get("scan_options", {}),
                    "auth_config": scheduled.get("auth_config"),
                    "triggered_by": "scheduled",
                    "scheduled_at": scheduled.get("next_run_at"),
                    "created_at": now.isoformat()
                }
                
                # Insert scan
                sb.table("scans").insert(new_scan).execute()
                
                # Trigger the scan task
                run_scan_task.delay(
                    scan_id=scan_id,
                    target=scheduled["target"],
                    scan_types=scheduled.get("scan_type", ["full"])
                )
                
                # Calculate next run time
                next_run = calculate_next_run(
                    scheduled["schedule_type"],
                    scheduled.get("cron_expression"),
                    scheduled.get("timezone", "UTC")
                )
                
                # Update scheduled scan
                sb.table("scheduled_scans").update({
                    "last_run_at": now.isoformat(),
                    "last_scan_id": scan_id,
                    "next_run_at": next_run.isoformat() if next_run else None,
                    "run_count": scheduled.get("run_count", 0) + 1
                }).eq("id", scheduled["id"]).execute()
                
                # Deactivate if one-time scan
                if scheduled["schedule_type"] == "once":
                    sb.table("scheduled_scans").update({
                        "is_active": False
                    }).eq("id", scheduled["id"]).execute()
                
                logger.info(f"Triggered scheduled scan {scan_id} for {scheduled['target']}")
                
            except Exception as e:
                logger.error(f"Failed to run scheduled scan {scheduled['id']}: {e}")
                
                # Increment failure count
                sb.table("scheduled_scans").update({
                    "failure_count": scheduled.get("failure_count", 0) + 1
                }).eq("id", scheduled["id"]).execute()
        
        return {"scheduled_scans_triggered": len(scheduled_scans)}
        
    except Exception as e:
        logger.error(f"Error checking scheduled scans: {e}")
        return {"error": str(e)}


@celery_app.task(bind=True)
def sync_threat_intelligence(self):
    """
    Sync threat intelligence from external sources
    """
    logger.info("Starting threat intelligence sync...")
    
    try:
        import asyncio
        from app.services.threat_service import ThreatService
        
        threat_service = ThreatService()
        
        # Run the async sync
        stats = asyncio.run(threat_service.sync_threats())
        
        logger.info(f"Threat sync completed: {stats}")
        return stats
        
    except Exception as e:
        logger.error(f"Threat sync failed: {e}")
        return {"error": str(e)}


@celery_app.task(bind=True)
def cleanup_old_data(self):
    """
    Clean up old scan data and temporary files
    """
    logger.info("Starting data cleanup...")
    
    try:
        sb = get_supabase()
        now = datetime.now(timezone.utc)
        
        # Delete scan progress older than 7 days
        seven_days_ago = (now - timedelta(days=7)).isoformat()
        sb.table("scan_progress").delete().lt("started_at", seven_days_ago).execute()
        
        # Delete notifications older than 30 days
        thirty_days_ago = (now - timedelta(days=30)).isoformat()
        sb.table("notifications").delete().lt("created_at", thirty_days_ago).eq("is_read", True).execute()
        
        # Delete expired reports
        sb.table("reports").delete().lt("expires_at", now.isoformat()).execute()
        
        logger.info("Data cleanup completed")
        return {"status": "completed"}
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return {"error": str(e)}


@celery_app.task(bind=True)
def generate_weekly_reports(self):
    """
    Generate weekly summary reports for all organizations
    """
    logger.info("Generating weekly reports...")
    
    try:
        sb = get_supabase()
        
        # Get all organizations
        orgs = sb.table("organizations").select("id, name").execute()
        
        for org in orgs.data or []:
            try:
                generate_org_weekly_report.delay(org["id"])
            except Exception as e:
                logger.error(f"Failed to trigger report for org {org['id']}: {e}")
        
        return {"organizations_processed": len(orgs.data or [])}
        
    except Exception as e:
        logger.error(f"Weekly report generation failed: {e}")
        return {"error": str(e)}


@celery_app.task(bind=True)
def generate_org_weekly_report(self, organization_id: str):
    """
    Generate weekly report for a specific organization
    """
    try:
        import asyncio
        from app.services.report_service import ReportService
        
        report_service = ReportService()
        
        # Get scans from the past week
        sb = get_supabase()
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        
        scans = sb.table("scans").select("id").eq(
            "organization_id", organization_id
        ).gte("created_at", week_ago).execute()
        
        if not scans.data:
            logger.info(f"No scans in past week for org {organization_id}")
            return {"status": "no_scans"}
        
        # Generate report for each scan
        for scan in scans.data:
            try:
                asyncio.run(report_service.generate_json_report(scan["id"]))
            except Exception as e:
                logger.error(f"Failed to generate report for scan {scan['id']}: {e}")
        
        return {"scans_processed": len(scans.data)}
        
    except Exception as e:
        logger.error(f"Org weekly report failed: {e}")
        return {"error": str(e)}


def calculate_next_run(
    schedule_type: str,
    cron_expression: Optional[str] = None,
    timezone_str: str = "UTC"
) -> Optional[datetime]:
    """
    Calculate the next run time based on schedule configuration
    """
    from zoneinfo import ZoneInfo
    
    try:
        tz = ZoneInfo(timezone_str)
    except Exception:
        tz = ZoneInfo("UTC")
    
    now = datetime.now(tz)
    
    if schedule_type == "once":
        return None  # One-time scans don't have a next run
    
    elif schedule_type == "daily":
        # Same time tomorrow
        return now + timedelta(days=1)
    
    elif schedule_type == "weekly":
        # Same time next week
        return now + timedelta(weeks=1)
    
    elif schedule_type == "monthly":
        # Same day next month (approximate)
        next_month = now.month + 1
        next_year = now.year
        if next_month > 12:
            next_month = 1
            next_year += 1
        
        # Handle month-end edge cases
        day = min(now.day, 28)  # Safe for all months
        return now.replace(year=next_year, month=next_month, day=day)
    
    elif schedule_type == "cron" and cron_expression:
        # Parse cron expression
        try:
            from croniter import croniter  # type: ignore
            cron = croniter(cron_expression, now)
            return cron.get_next(datetime)
        except ImportError:
            logger.warning("croniter not installed, falling back to daily")
            return now + timedelta(days=1)
        except Exception as e:
            logger.error(f"Invalid cron expression: {e}")
            return now + timedelta(days=1)
    
    else:
        # Default to daily
        return now + timedelta(days=1)


# API functions for managing scheduled scans
async def create_scheduled_scan(
    organization_id: str,
    user_id: str,
    name: str,
    target: str,
    schedule_type: str,
    scan_type: List[str] = None,
    scan_options: Dict = None,
    auth_config: Dict = None,
    cron_expression: str = None,
    timezone_str: str = "UTC",
    notify_on_completion: bool = True,
    notify_on_critical: bool = True
) -> Dict[str, Any]:
    """
    Create a new scheduled scan
    """
    sb = get_supabase()
    
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    # Calculate first run time
    next_run = calculate_next_run(schedule_type, cron_expression, timezone_str)
    
    # For "once", set next_run to the scheduled time if provided
    if schedule_type == "once":
        next_run = now + timedelta(minutes=1)  # Run soon for one-time
    
    scheduled_scan = {
        "id": scan_id,
        "organization_id": organization_id,
        "name": name,
        "target": target,
        "scan_type": scan_type or ["full"],
        "scan_options": scan_options or {},
        "auth_config": auth_config,
        "schedule_type": schedule_type,
        "cron_expression": cron_expression,
        "timezone": timezone_str,
        "next_run_at": next_run.isoformat() if next_run else None,
        "is_active": True,
        "notify_on_completion": notify_on_completion,
        "notify_on_critical": notify_on_critical,
        "created_by": user_id,
        "created_at": now.isoformat()
    }
    
    result = sb.table("scheduled_scans").insert(scheduled_scan).execute()
    
    return result.data[0] if result.data else scheduled_scan


async def update_scheduled_scan(
    scan_id: str,
    updates: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Update a scheduled scan
    """
    sb = get_supabase()
    
    # Recalculate next_run if schedule changed
    if "schedule_type" in updates or "cron_expression" in updates:
        schedule_type = updates.get("schedule_type")
        cron_expression = updates.get("cron_expression")
        timezone_str = updates.get("timezone", "UTC")
        
        if schedule_type:
            next_run = calculate_next_run(schedule_type, cron_expression, timezone_str)
            updates["next_run_at"] = next_run.isoformat() if next_run else None
    
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    result = sb.table("scheduled_scans").update(updates).eq("id", scan_id).execute()
    
    return result.data[0] if result.data else {}


async def delete_scheduled_scan(scan_id: str) -> bool:
    """
    Delete a scheduled scan
    """
    sb = get_supabase()
    sb.table("scheduled_scans").delete().eq("id", scan_id).execute()
    return True


async def toggle_scheduled_scan(scan_id: str, is_active: bool) -> Dict[str, Any]:
    """
    Enable or disable a scheduled scan
    """
    sb = get_supabase()
    
    updates = {
        "is_active": is_active,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Recalculate next_run if re-enabling
    if is_active:
        scheduled = sb.table("scheduled_scans").select("*").eq("id", scan_id).execute()
        if scheduled.data:
            sched = scheduled.data[0]
            next_run = calculate_next_run(
                sched["schedule_type"],
                sched.get("cron_expression"),
                sched.get("timezone", "UTC")
            )
            updates["next_run_at"] = next_run.isoformat() if next_run else None
    
    result = sb.table("scheduled_scans").update(updates).eq("id", scan_id).execute()
    
    return result.data[0] if result.data else {}
