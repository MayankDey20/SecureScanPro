import httpx
import logging
import asyncio
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.services.providers.base import ThreatProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

# With an API key NVD allows 50 requests per 30 seconds.
# Without a key the limit is 5 per 30 seconds.
# We stay well inside the limit by sleeping between calls.
_NVD_SLEEP_KEYED    = 0.6   # ~50 req/30s  → 1 every 0.6s
_NVD_SLEEP_UNKEYED  = 6.5   # ~4 req/30s   → safe margin


class NVDProvider(ThreatProvider):
    """
    Dual-source threat provider:
      1. CISA KEV  — always fresh, no key needed, returns actively exploited CVEs
      2. NIST NVD  — Critical/High CVEs from the last 30 days
    """

    NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def get_provider_name(self) -> str:
        return "NVD+CISA"

    async def fetch_latest_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch from CISA KEV first (fast, no rate limit), then NVD for
        additional Critical/High CVEs. De-duplicates by cve_id.
        """
        seen:    set         = set()
        threats: List[Dict] = []

        cisa_threats = await self._fetch_cisa_kev(limit)
        for t in cisa_threats:
            if t["cve_id"] not in seen:
                seen.add(t["cve_id"])
                threats.append(t)

        nvd_threats = await self._fetch_nvd_recent(limit)
        for t in nvd_threats:
            if t["cve_id"] not in seen:
                seen.add(t["cve_id"])
                threats.append(t)

        logger.info(f"Total threats collected: {len(threats)} "
                    f"(CISA: {len(cisa_threats)}, NVD new: {len(threats) - len(cisa_threats)})")
        return threats[:limit * 2]

    # ── CISA KEV ────────────────────────────────────────────────
    async def _fetch_cisa_kev(self, limit: int) -> List[Dict]:
        threats = []
        cutoff  = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(self.CISA_URL)
                if r.status_code != 200:
                    logger.error(f"CISA KEV error: {r.status_code}")
                    return []

                vulns = r.json().get("vulnerabilities", [])
                vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

                for v in vulns:
                    date_added = v.get("dateAdded", "")
                    if date_added < cutoff and len(threats) >= limit:
                        break
                    cve_id = v.get("cveID", "")
                    if not cve_id:
                        continue
                    name     = v.get("vulnerabilityName", f"{cve_id} Vulnerability")
                    desc     = v.get("shortDescription", "No description available.")
                    vendor   = v.get("vendorProject", "Unknown")
                    product  = v.get("product", "")
                    severity = self._severity_from_name(name + " " + desc)
                    threats.append({
                        "cve_id":            cve_id,
                        "title":             name,
                        "description":       desc,
                        "severity":          severity,
                        "cvss_score":        self._cvss_from_severity(severity),
                        "published_date":    f"{date_added}T00:00:00",
                        "category":          self._categorize_threat(desc),
                        "references":        [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        "affected_products": [f"{vendor} {product}".strip()],
                        "trending":          True,
                        "exploit_available": True,
                    })

            logger.info(f"CISA KEV: fetched {len(threats)} threats")
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")
        return threats

    # ── NVD ─────────────────────────────────────────────────────
    async def _fetch_nvd_recent(self, limit: int) -> List[Dict]:
        threats  = []
        end_dt   = datetime.utcnow()
        start_dt = end_dt - timedelta(days=30)
        pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        has_key = bool(
            settings.NVD_API_KEY and
            settings.NVD_API_KEY not in ("your-nvd-api-key", "")
        )
        headers = {"apiKey": settings.NVD_API_KEY} if has_key else {}
        sleep_s = _NVD_SLEEP_KEYED if has_key else _NVD_SLEEP_UNKEYED

        logger.info(
            f"NVD: using {'API key (50 req/30s)' if has_key else 'anonymous (5 req/30s)'}"
        )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for severity in ("CRITICAL", "HIGH"):
                    params = {
                        "pubStartDate":   pub_start,
                        "pubEndDate":     pub_end,
                        "resultsPerPage": min(limit, 50),
                        "cvssV3Severity": severity,
                    }
                    logger.info(f"Fetching NVD {severity} CVEs …")

                    # Retry once on 403 (rate limit hit)
                    for attempt in range(2):
                        r = await client.get(self.NVD_URL, params=params, headers=headers)
                        if r.status_code == 200:
                            for item in r.json().get("vulnerabilities", []):
                                t = self._normalize_cve(item.get("cve", {}))
                                if t:
                                    threats.append(t)
                            break
                        elif r.status_code == 403:
                            wait = 35 if attempt == 0 else 0
                            logger.warning(
                                f"NVD rate-limited (403) on {severity} — "
                                f"{'waiting 35s then retrying' if wait else 'giving up'}"
                            )
                            if wait:
                                await asyncio.sleep(wait)
                        else:
                            logger.error(f"NVD {severity}: {r.status_code} — {r.text[:200]}")
                            break

                    # Respect NVD rate limit between severity calls
                    await asyncio.sleep(sleep_s)

        except Exception as e:
            logger.error(f"NVD fetch failed: {e}")

        logger.info(f"NVD: fetched {len(threats)} threats")
        return threats

    # ── Helpers ─────────────────────────────────────────────────
    def _normalize_cve(self, cve: Dict) -> Dict | None:
        try:
            cve_id = cve.get("id", "")
            if not cve_id:
                return None
            descriptions = cve.get("descriptions", [])
            description  = next((d["value"] for d in descriptions if d["lang"] == "en"),
                                 "No description available")
            metrics   = cve.get("metrics", {})
            cvss_data = {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                if key in metrics:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    break
            if not cvss_data:
                return None
            score    = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "unknown").lower()
            return {
                "cve_id":            cve_id,
                "title":             f"{cve_id}: {description[:77]}{'…' if len(description) > 77 else ''}",
                "description":       description,
                "severity":          severity,
                "cvss_score":        score,
                "published_date":    cve.get("published", datetime.utcnow().isoformat()),
                "category":          self._categorize_threat(description),
                "references":        self._extract_references(cve.get("references", [])),
                "affected_products": [],
                "trending":          score >= 9.0,
                "exploit_available": False,
            }
        except Exception as e:
            logger.warning(f"Normalize error {cve.get('id','?')}: {e}")
            return None

    def _categorize_threat(self, description: str) -> str:
        d = description.lower()
        if any(k in d for k in ("sql", "injection")):                       return "Injection"
        if any(k in d for k in ("xss", "cross-site script")):               return "XSS"
        if any(k in d for k in ("buffer", "overflow", "heap", "use-after")): return "Memory Corruption"
        if any(k in d for k in ("privilege", "escalation", "elevation")):   return "Privilege Escalation"
        if any(k in d for k in ("denial", " dos ", "exhaustion")):          return "DoS"
        if any(k in d for k in ("remote code", "arbitrary code", "rce")):   return "RCE"
        if any(k in d for k in ("path traversal", "directory traversal")):  return "Path Traversal"
        if any(k in d for k in ("auth bypass", "unauthenticated")):         return "Auth Bypass"
        if any(k in d for k in ("command inject", "os command")):           return "Command Injection"
        return "Vulnerability"

    def _severity_from_name(self, text: str) -> str:
        t = text.lower()
        if any(k in t for k in ("remote code", "rce", "os command", "ransomware")): return "critical"
        if any(k in t for k in ("privilege", "auth bypass")):                        return "high"
        if any(k in t for k in ("cross-site", "xss")):                               return "medium"
        return "high"

    def _cvss_from_severity(self, severity: str) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5}.get(severity, 7.0)

    def _extract_references(self, refs: List[Dict]) -> List[str]:
        return [r.get("url") for r in refs[:3] if r.get("url")]
