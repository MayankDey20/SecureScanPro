import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from app.core.supabase_client import get_supabase
from app.core.config import settings
from app.core.websocket_manager import SyncProgressPublisher

# Import Scanners
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.network_scanner import NetworkScanner
from app.scanners.recon_scanner import ReconScanner
from app.scanners.vuln_scanner import VulnScanner
from app.scanners.combined_scanners import ApiScanner, AuthScanner, ContentScanner, ServiceScanner
from app.scanners.nuclei_scanner import AdvancedVulnScanner
from app.scanners.crawler import WebCrawler, CrawlConfig

# Import External Providers
from app.services.threat_service import ThreatService
from app.services.notification_service import NotificationService, NotificationEvent

logger = logging.getLogger(__name__)

class ScanService:
    """Service to orchestrate security scans across multiple providers"""
    
    def __init__(self):
        self.supabase = get_supabase()
        self.threat_service = ThreatService()
        self.notification_service = NotificationService()
        try:
            self._pub = SyncProgressPublisher(
                redis_url=getattr(settings, 'REDIS_URL', 'redis://redis:6379/0')
            )
        except Exception:
            self._pub = None
        
        # Initialize Scanners
        self.scanners = {
            "ssl":     SSLScanner(),
            "headers": HeaderScanner(),
            "network": NetworkScanner(),
            "recon":   ReconScanner(),
            "vuln":    VulnScanner(),
            "api":     ApiScanner(),
            "auth":    AuthScanner(),
            "content": ContentScanner(),
            "service": ServiceScanner(),   # network CVE + unauthenticated service checks
            "advanced": AdvancedVulnScanner(),  # Nuclei + OWASP checks
        }

    async def run_scan(
        self,
        scan_id: str,
        target: str,
        scan_types: List[str],
        auth_config: Optional[Dict] = None,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        scan_options: Optional[Dict] = None,
    ):
        """Execute a full scan on the target"""
        logger.info(f"Starting scan {scan_id} for target {target} with types: {scan_types}")

        # ── Normalise incoming scan_type aliases → internal scanner keys ──
        # Must happen BEFORE any scan_types checks (crawl gate, scanner loop, etc.)
        SCAN_TYPE_ALIASES = {
            "vulnerabilities": "vuln",
            "vulnerability":   "vuln",
            "ports":           "network",
            "headers":         "headers",
            "ssl":             "ssl",
            "recon":           "recon",
            "api":             "api",
            "auth":            "auth",
            "content":         "content",
            "advanced":        "advanced",
            "full":            "full",
            "quick":           "full",
        }
        scan_types = [SCAN_TYPE_ALIASES.get(st, st) for st in scan_types]
        logger.info(f"Normalised scan types: {scan_types}")
        
        # Update status to running — also notify via pub/sub
        try:
            self.supabase.table("scans").update({
                "status": "running",
                "progress": 5,
                "current_phase": "Initializing",
                "started_at": datetime.now(timezone.utc).isoformat()
            }).eq("id", scan_id).execute()
        except Exception:
            pass
        if self._pub:
            try:
                self._pub.update_progress(
                    scan_id=scan_id, status="running",
                    progress=5, current_phase="Initializing"
                )
            except Exception:
                pass

        # Fire scan_started notification
        try:
            if organization_id:
                await self.notification_service.send_notification(
                    event=NotificationEvent.SCAN_STARTED,
                    organization_id=organization_id,
                    user_ids=[user_id] if user_id else None,
                    data={"target": target},
                )
        except Exception as e:
            logger.warning(f"Notification send_started failed (non-fatal): {e}")

        # ── Phase 0: Web Crawl (discovers attack surface) ──────────────────────
        crawl_summary = {}
        crawl_result  = {}  # kept in scope for VulnScanner
        if "full" in scan_types or "vuln" in scan_types or "crawl" in scan_types:
            try:
                self._publish_progress(scan_id, "running", 8, "Crawling")

                crawl_cfg = CrawlConfig(
                    max_depth=2,
                    max_pages=50,
                    max_time_seconds=60,
                    auth=auth_config,
                )
                crawler = WebCrawler(crawl_cfg)
                crawl_result = await crawler.crawl(target)
                crawl_summary = crawl_result.get("summary", {})
                logger.info(
                    f"Crawl complete: {crawl_summary.get('urls_crawled', 0)} pages, "
                    f"{crawl_summary.get('forms_found', 0)} forms, "
                    f"techs: {crawl_summary.get('technologies', [])}"
                )
            except Exception as e:
                logger.warning(f"Crawler failed (non-fatal): {e}")
        
        results = {
            "scan_id": scan_id,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "status": "processing",
            "modules": {}
        }
        
        # Map scanner names to UI phase labels
        phase_map = {
            "recon":        "Reconnaissance",
            "ssl":          "SSL Analysis",
            "headers":      "Header Inspection",
            "network":      "Port Scanning",
            "vuln":         "Vulnerability Detection",
            "api":          "API Discovery",
            "auth":         "Auth Checks",
            "content":      "Content Inspection",
            "service":      "Service Exploitation Checks",
            "threat_intel": "Threat Intelligence",
            "advanced":     "Deep Vulnerability Scan",
        }

        tasks = []
        task_names = []

        # 1. External Threat Intelligence
        if "threat_intel" in scan_types or "full" in scan_types:
            tasks.append(self.threat_service.aggregate_intel(target))
            task_names.append("threat_intel")

        # 2. Local Scanners
        # Run network scanner first (synchronously before the task list) so its
        # results are available for ServiceScanner CVE correlation.
        nmap_result = None
        if "network" in scan_types or "full" in scan_types:
            network_scanner = self.scanners["network"]
            try:
                nmap_result = await network_scanner.scan(target)
            except Exception as e:
                logger.warning(f"Network scan pre-run failed: {e}")
                nmap_result = {"status": "failed", "error": str(e)}
            results["modules"]["network"] = nmap_result

        for name, scanner in self.scanners.items():
            if name not in (scan_types if "full" not in scan_types else list(self.scanners.keys()) + ["threat_intel"]):
                continue
            if name == "network":
                continue  # already ran above
            if name == "vuln":
                tasks.append(scanner.scan(
                    target,
                    crawl_data=crawl_result,
                    auth_config=auth_config,
                ))
            elif name == "service":
                tasks.append(scanner.scan(
                    target,
                    nmap_results=nmap_result.get("data") if nmap_result else None,
                ))
            elif name == "api":
                auth_hdrs = {}
                if auth_config:
                    if auth_config.get("type") == "bearer":
                        auth_hdrs["Authorization"] = f"Bearer {auth_config['token']}"
                    elif auth_config.get("type") == "basic":
                        import base64
                        creds = base64.b64encode(
                            f"{auth_config['username']}:{auth_config['password']}".encode()
                        ).decode()
                        auth_hdrs["Authorization"] = f"Basic {creds}"
                tasks.append(scanner.scan(target, auth_headers=auth_hdrs if auth_hdrs else None))
            else:
                tasks.append(scanner.scan(target))
            task_names.append(name)

        total_tasks = len(tasks)

        # Execute scanners one-by-one so we can report real progress
        scan_results = []
        for i, (task, name) in enumerate(zip(tasks, task_names)):
            phase = phase_map.get(name, name.replace("_", " ").title())
            progress_pct = 10 + int((i / max(total_tasks, 1)) * 80)
            self._publish_progress(scan_id, "running", progress_pct, phase)
            result = await task
            scan_results.append(result)

        # Process results
        for name, result in zip(task_names, scan_results):
            if isinstance(result, Exception):
                logger.error(f"Scanner {name} failed: {str(result)}")
                results["modules"][name] = {"status": "failed", "error": str(result)}
            else:
                results["modules"][name] = result
                
                # Save vulnerabilities found by this module
                if "vulnerabilities" in result and result["vulnerabilities"]:
                    try:
                        vulns_to_insert = []
                        for v in result["vulnerabilities"]:
                            vulns_to_insert.append({
                                "scan_id": scan_id,
                                "vuln_type": v.get("type", "unknown"),
                                "severity": v.get("severity", "info").lower(),
                                "title": v.get("title", "Unknown Vulnerability"),
                                "description": v.get("description", ""),
                                "location": v.get("location", target),
                                "cve_id": v.get("cve_id")
                            })
                        
                        if vulns_to_insert:
                            self.supabase.table("vulnerabilities").insert(vulns_to_insert).execute()
                    except Exception as e:
                        logger.error(f"Failed to save vulnerabilities for module {name}: {e}")

        # Tally vulnerabilities by severity
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total = 0
        for module in results["modules"].values():
            for v in module.get("vulnerabilities", []):
                sev = v.get("severity", "info").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["info"] += 1
                total += 1

        score = self.calculate_final_score(sev_counts)

        # Update scan completion — include crawl summary in results
        update_payload = {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "security_score": score,
            "findings_count": total,
            "vulnerabilities_count": sev_counts,
            "progress": 100,
        }
        # Note: crawl_summary is not a DB column — stored in memory only
        self.supabase.table("scans").update(update_payload).eq("id", scan_id).execute()

        # Fire scan_completed notification
        try:
            if organization_id:
                await self.notification_service.send_notification(
                    event=NotificationEvent.SCAN_COMPLETED,
                    organization_id=organization_id,
                    user_ids=[user_id] if user_id else None,
                    data={
                        "target": target,
                        "total_vulns": total,
                        "critical": sev_counts.get("critical", 0),
                        "high": sev_counts.get("high", 0),
                    },
                )
            # Fire extra critical notification if any critical vulns found
            if sev_counts.get("critical", 0) > 0 and organization_id:
                first_critical = next(
                    (v for m in results["modules"].values()
                     for v in m.get("vulnerabilities", [])
                     if v.get("severity", "").lower() == "critical"),
                    None
                )
                if first_critical:
                    await self.notification_service.send_notification(
                        event=NotificationEvent.CRITICAL_FOUND,
                        organization_id=organization_id,
                        user_ids=[user_id] if user_id else None,
                        data={"target": target, "vuln_name": first_critical.get("title", "Unknown")},
                    )
        except Exception as e:
            logger.warning(f"Notification send_completed failed (non-fatal): {e}")

        logger.info(f"Scan {scan_id} completed. Score={score}, Findings={total}")
        return results

    def _publish_progress(
        self, scan_id: str, status: str, progress: int,
        current_phase: str, findings_count: int = 0
    ):
        """Push progress to Redis pub/sub (picked up by WebSocket manager) AND update Supabase."""
        try:
            self.supabase.table("scans").update({
                "progress": progress,
                "current_phase": current_phase,
                "status": status,
            }).eq("id", scan_id).execute()
        except Exception:
            pass
        if self._pub:
            try:
                self._pub.update_progress(
                    scan_id=scan_id,
                    status=status,
                    progress=progress,
                    current_phase=current_phase,
                    findings_count=findings_count,
                )
            except Exception:
                pass

    def calculate_final_score(self, sev_counts: dict) -> int:
        """Calculate security score: start at 100, deduct per severity"""
        deductions = {
            "critical": 20,
            "high": 10,
            "medium": 5,
            "low": 2,
            "info": 0,
        }
        score = 100
        for sev, count in sev_counts.items():
            score -= deductions.get(sev, 0) * count
        return max(0, score)

    def count_vulnerabilities(self, results) -> int:
        """Count total vulnerabilities from scan results"""
        return sum(len(module.get("vulnerabilities", [])) for module in results["modules"].values())

