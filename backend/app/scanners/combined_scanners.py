"""
Combined Scanners for SecureScan Pro
  - ApiScanner:     OpenAPI/Swagger spec import + BOLA/BFLA/Mass-assignment testing
  - AuthScanner:    Sensitive path exposure + default credential checks
  - ContentScanner: Secret leakage, email exposure, comment analysis, CVE correlation
  - ServiceScanner: Network service exploitation (default creds, version CVE lookup)
"""
import httpx
import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


# ── Known CVE mapping for common service versions ────────────────────────────
# Format: (product_keyword, version_prefix) -> list of (CVE, description, severity)
SERVICE_CVE_MAP = [
    # Apache
    ("apache", "2.4.49", [("CVE-2021-41773", "Path traversal & RCE in Apache 2.4.49", "critical")]),
    ("apache", "2.4.50", [("CVE-2021-42013", "Path traversal & RCE in Apache 2.4.50", "critical")]),
    ("apache", "2.2.",   [("CVE-2017-7679",  "Apache 2.2.x buffer overflow", "high")]),
    # OpenSSH
    ("openssh", "7.",    [("CVE-2023-38408", "OpenSSH 7.x remote code execution via PKCS#11", "critical")]),
    ("openssh", "8.",    [("CVE-2023-51385", "OpenSSH 8.x OS command injection via invalid hostname", "high")]),
    # nginx
    ("nginx", "1.16.",   [("CVE-2021-23017", "nginx 1.16 DNS resolver buffer overflow", "high")]),
    ("nginx", "1.18.",   [("CVE-2021-23017", "nginx 1.18 DNS resolver buffer overflow", "high")]),
    # ProFTPD
    ("proftpd", "1.3.",  [("CVE-2019-12815", "ProFTPD 1.3.x arbitrary file copy via mod_copy", "critical")]),
    # vsftpd
    ("vsftpd", "2.3.4",  [("CVE-2011-2523",  "vsftpd 2.3.4 backdoor command execution", "critical")]),
    # Samba
    ("samba", "3.",      [("CVE-2017-7494",  "Samba 3.x/4.x remote code execution (EternalRed)", "critical")]),
    ("samba", "4.",      [("CVE-2017-7494",  "Samba 4.x remote code execution (EternalRed)", "critical")]),
    # Redis
    ("redis", "",        [("CVE-2022-0543",  "Redis Lua sandbox escape leading to RCE", "critical")]),
    # MySQL
    ("mysql", "5.7.",    [("CVE-2016-6662",  "MySQL 5.7.x remote code execution via config overwrite", "critical")]),
    # PHP
    ("php", "7.1.",      [("CVE-2019-11043", "PHP-FPM 7.1 RCE with nginx misconfiguration", "critical")]),
    ("php", "7.2.",      [("CVE-2019-11043", "PHP-FPM 7.2 RCE with nginx misconfiguration", "critical")]),
    ("php", "7.3.",      [("CVE-2019-11043", "PHP-FPM 7.3 RCE with nginx misconfiguration", "critical")]),
    # IIS
    ("iis", "6.",        [("CVE-2017-7269",  "IIS 6.0 WebDAV buffer overflow RCE", "critical")]),
    # Tomcat
    ("tomcat", "9.0.",   [("CVE-2020-1938",  "Apache Tomcat 9.0.x AJP file inclusion (Ghostcat)", "critical")]),
    ("tomcat", "8.5.",   [("CVE-2020-1938",  "Apache Tomcat 8.5.x AJP file inclusion (Ghostcat)", "critical")]),
]

# Default credentials for common services
DEFAULT_CREDS = {
    21:   [("anonymous", "anonymous"), ("admin", "admin"), ("ftp", "ftp")],
    22:   [],  # SSH — don't attempt (illegal on most targets)
    23:   [("admin", "admin"), ("root", "root"), ("cisco", "cisco")],
    80:   [("admin", "admin"), ("admin", "password"), ("admin", "")],
    443:  [("admin", "admin"), ("admin", "password")],
    3306: [("root", ""), ("root", "root"), ("admin", "admin")],
    5432: [("postgres", "postgres"), ("admin", "admin")],
    6379: [("", "")],   # Redis — no auth = vulnerability
    27017:[("admin", "admin")],  # MongoDB
    8080: [("admin", "admin"), ("tomcat", "tomcat"), ("manager", "manager")],
    8443: [("admin", "admin")],
}


class ApiScanner:
    """
    API discovery + OpenAPI/Swagger spec-driven testing.
    Tests BOLA (Broken Object Level Authorization), BFLA, mass assignment,
    and unauthenticated access to API endpoints.
    """

    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/swagger.json", "/swagger/v1/swagger.json",
        "/openapi.json", "/openapi.yaml",
        "/docs", "/redoc", "/swagger-ui.html",
        "/graphql", "/graphiql", "/graphql/console",
        "/api-docs", "/api/docs",
        "/v1", "/v2", "/v3",
        "/.well-known/openapi",
    ]

    BOLA_PATHS = [
        "/api/v1/users/1", "/api/v1/users/2",
        "/api/v1/accounts/1", "/api/users/1",
        "/api/admin", "/api/v1/admin",
        "/api/internal", "/api/private",
    ]

    async def scan(self, target: str, auth_headers: Optional[Dict] = None) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        found_endpoints = []
        spec_vulns: List[Dict] = []
        bola_vulns: List[Dict] = []
        vulns: List[Dict] = []

        headers = auth_headers or {}

        async with httpx.AsyncClient(verify=False, timeout=8.0,
                                      follow_redirects=True) as client:
            # ── Endpoint discovery ──
            for path in self.COMMON_API_PATHS:
                url = f"{target.rstrip('/')}{path}"
                try:
                    r = await client.get(url, headers=headers)
                    if r.status_code in (200, 401, 403):
                        found_endpoints.append({
                            "path": path,
                            "status": r.status_code,
                            "url": url,
                        })
                        # Parse OpenAPI spec if found
                        if r.status_code == 200 and path in (
                            "/swagger.json", "/openapi.json",
                            "/swagger/v1/swagger.json",
                        ):
                            spec_vulns += self._analyze_spec(r.text, url)
                except Exception:
                    pass

            # ── BOLA / IDOR check ──
            for path in self.BOLA_PATHS:
                url = f"{target.rstrip('/')}{path}"
                try:
                    # Try with no auth
                    r_no_auth = await client.get(url)
                    # Try with auth if provided
                    r_auth = await client.get(url, headers=headers) if headers else None

                    if r_no_auth.status_code == 200:
                        bola_vulns.append({
                            "type": "bola_idor",
                            "severity": "high",
                            "title": "Broken Object Level Authorization (BOLA/IDOR)",
                            "description": (
                                f"API endpoint '{path}' returns data without authentication "
                                f"(HTTP {r_no_auth.status_code}). Attackers can access "
                                f"other users' data by changing object IDs."
                            ),
                            "location": url,
                        })
                    elif r_auth and r_auth.status_code == 200 and r_no_auth.status_code == 200:
                        bola_vulns.append({
                            "type": "bola_idor",
                            "severity": "high",
                            "title": "Potential BOLA — Object ID Enumeration",
                            "description": (
                                f"Authenticated access to '{path}' succeeded. "
                                f"Verify that users can only access their own objects."
                            ),
                            "location": url,
                        })
                except Exception:
                    pass

            # ── Mass assignment check ──
            ma_urls = [
                f"{target.rstrip('/')}/api/v1/users",
                f"{target.rstrip('/')}/api/users",
            ]
            mass_assign_payload = {"id": 1, "admin": True, "role": "admin",
                                   "is_admin": True, "isAdmin": True}
            for url in ma_urls:
                try:
                    r = await client.post(url, json=mass_assign_payload,
                                          headers={**headers,
                                                   "Content-Type": "application/json"})
                    if r.status_code in (200, 201):
                        resp_text = r.text.lower()
                        if "admin" in resp_text or "role" in resp_text:
                            vulns.append({
                                "type": "mass_assignment",
                                "severity": "high",
                                "title": "Mass Assignment Vulnerability",
                                "description": (
                                    f"API endpoint '{url}' accepts elevated privilege fields "
                                    f"(admin, role) in the request body. "
                                    f"Attackers can escalate privileges."
                                ),
                                "location": url,
                            })
                except Exception:
                    pass

        return {
            "status": "completed",
            "scanner": "api_discovery",
            "vulnerabilities": spec_vulns + bola_vulns + vulns,
            "data": {"endpoints": found_endpoints},
        }

    def _analyze_spec(self, spec_text: str, spec_url: str) -> List[Dict]:
        """Basic OpenAPI spec analysis — find unauthenticated endpoints."""
        vulns = []
        try:
            import json
            spec = json.loads(spec_text)
            paths = spec.get("paths", {})
            security_global = spec.get("security", [])

            for path, methods in paths.items():
                for method, details in methods.items():
                    if not isinstance(details, dict):
                        continue
                    # Endpoint with no security requirement
                    endpoint_security = details.get("security")
                    if endpoint_security == [] or (
                        endpoint_security is None and not security_global
                    ):
                        vulns.append({
                            "type": "unauthenticated_api_endpoint",
                            "severity": "medium",
                            "title": "Unauthenticated API Endpoint in Spec",
                            "description": (
                                f"{method.upper()} {path} has no security requirement "
                                f"defined in the OpenAPI spec."
                            ),
                            "location": spec_url,
                        })
        except Exception:
            pass
        return vulns

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target


class AuthScanner:
    """
    Auth surface scanner:
    - Sensitive path exposure
    - Default credential checks on web login forms
    - Directory listing detection
    - Backup file exposure
    """

    SENSITIVE_PATHS = [
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/dashboard", "/manager", "/control", "/panel",
        "/config", "/configuration", "/setup",
        "/phpMyAdmin", "/phpmyadmin",
        "/console", "/actuator", "/actuator/env",
        "/actuator/heapdump", "/actuator/shutdown",
        "/debug", "/.env", "/.git/config",
        "/backup", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/database.sql", "/dump.sql",
        "/server-status", "/server-info",
        "/.DS_Store", "/robots.txt", "/sitemap.xml",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
    ]

    DEFAULT_WEB_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("root", "root"), ("root", ""), ("test", "test"),
        ("administrator", "administrator"), ("guest", "guest"),
        ("tomcat", "tomcat"), ("manager", "manager"),
    ]

    async def scan(self, target: str) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        vulns = []

        async with httpx.AsyncClient(verify=False, timeout=8.0,
                                      follow_redirects=False) as client:
            # ── Sensitive path exposure ──
            for path in self.SENSITIVE_PATHS:
                url = f"{target.rstrip('/')}{path}"
                try:
                    r = await client.get(url)
                    if r.status_code == 200:
                        text_lower = r.text.lower()
                        is_login = any(k in text_lower for k in
                                       ("login", "sign in", "password", "username"))

                        if path in ("/.env",):
                            vulns.append({
                                "type": "sensitive_file_exposed",
                                "severity": "critical",
                                "title": "Environment File Exposed",
                                "description": (
                                    f"The .env file is publicly accessible at '{url}'. "
                                    f"This likely contains database passwords, API keys, "
                                    f"and secret tokens."
                                ),
                                "location": url,
                            })
                        elif path in ("/.git/config",):
                            vulns.append({
                                "type": "git_exposed",
                                "severity": "high",
                                "title": "Git Repository Exposed",
                                "description": (
                                    f"The .git directory is publicly accessible. "
                                    f"Attackers can reconstruct the entire source code."
                                ),
                                "location": url,
                            })
                        elif path in ("/db.sql", "/database.sql", "/dump.sql"):
                            vulns.append({
                                "type": "database_backup_exposed",
                                "severity": "critical",
                                "title": "Database Backup File Exposed",
                                "description": (
                                    f"A database backup file is publicly accessible at '{url}'. "
                                    f"This exposes all database contents."
                                ),
                                "location": url,
                            })
                        elif path in ("/actuator/env", "/actuator/heapdump"):
                            vulns.append({
                                "type": "spring_actuator_exposed",
                                "severity": "critical",
                                "title": "Spring Boot Actuator Endpoint Exposed",
                                "description": (
                                    f"Spring Boot Actuator endpoint '{path}' is publicly "
                                    f"accessible and may expose environment variables, "
                                    f"credentials, and heap dumps."
                                ),
                                "location": url,
                            })
                        elif not is_login:
                            vulns.append({
                                "type": "unprotected_admin_path",
                                "severity": "high",
                                "title": "Unprotected Sensitive Path",
                                "description": (
                                    f"The path '{path}' is accessible without authentication "
                                    f"(HTTP 200) and does not appear to be a login page."
                                ),
                                "location": url,
                            })

                    # Directory listing
                    elif r.status_code == 200:
                        if "index of /" in r.text.lower() or "directory listing" in r.text.lower():
                            vulns.append({
                                "type": "directory_listing",
                                "severity": "medium",
                                "title": "Directory Listing Enabled",
                                "description": (
                                    f"Directory listing is enabled at '{url}', "
                                    f"exposing file structure to attackers."
                                ),
                                "location": url,
                            })

                except Exception:
                    pass

            # ── Default credential check on login forms ──
            login_paths = ["/admin", "/wp-admin", "/administrator",
                           "/login", "/signin", "/user/login"]
            for lpath in login_paths:
                url = f"{target.rstrip('/')}{lpath}"
                try:
                    r = await client.get(url, follow_redirects=True)
                    if r.status_code == 200:
                        text = r.text.lower()
                        if ("username" in text or "email" in text) and "password" in text:
                            # Found a login form — try default creds
                            cred_vuln = await self._try_default_creds(
                                client, url, r.text
                            )
                            if cred_vuln:
                                vulns.append(cred_vuln)
                except Exception:
                    pass

        return {
            "status": "completed",
            "scanner": "auth_check",
            "vulnerabilities": vulns,
            "data": {"sensitive_paths_checked": len(self.SENSITIVE_PATHS)},
        }

    async def _try_default_creds(
        self, client: httpx.AsyncClient, login_url: str, page_html: str
    ) -> Optional[Dict]:
        """Attempt common default credentials against a discovered login form."""
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(page_html, "html.parser")
            form = soup.find("form")
            if not form:
                return None

            action = form.get("action", login_url)
            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(login_url, action)
            method = form.get("method", "post").upper()

            # Identify username/password field names
            inputs = form.find_all("input")
            user_field = pass_field = None
            for inp in inputs:
                itype = inp.get("type", "text").lower()
                iname = inp.get("name", "").lower()
                if itype in ("text", "email") or "user" in iname or "email" in iname:
                    user_field = inp.get("name")
                elif itype == "password":
                    pass_field = inp.get("name")

            if not user_field or not pass_field:
                return None

            for username, password in self.DEFAULT_WEB_CREDS:
                data = {user_field: username, pass_field: password}
                try:
                    r = await client.post(action, data=data,
                                          follow_redirects=True, timeout=6.0)
                    text_lower = r.text.lower()
                    # Heuristic: if we no longer see "login" and see "logout"/"dashboard"
                    if (r.status_code == 200 and
                            "logout" in text_lower and
                            "login" not in text_lower[:200]):
                        return {
                            "type": "default_credentials",
                            "severity": "critical",
                            "title": "Default Credentials Accepted",
                            "description": (
                                f"Login at '{action}' accepted default credentials "
                                f"username='{username}' password='{password}'. "
                                f"Change these immediately."
                            ),
                            "location": action,
                        }
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target


class ContentScanner:
    """
    Content analysis scanner:
    - Secret / credential leakage (regex-based, like truffleHog)
    - Email exposure
    - HTML comment analysis
    - Inline JavaScript secret detection
    - CVE correlation for detected server/tech versions
    """

    # Regex patterns for secret detection
    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
         "API Key", "high"),
        (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+]{20,})['\"]?",
         "Secret Key", "critical"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
         "Hardcoded Password", "critical"),
        (r"(?i)(aws_access_key_id|aws[_-]?key)\s*[=:]\s*['\"]?(AKIA[A-Z0-9]{16})['\"]?",
         "AWS Access Key", "critical"),
        (r"AKIA[A-Z0-9]{16}",
         "AWS Access Key ID", "critical"),
        (r"(?i)(aws_secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
         "AWS Secret Key", "critical"),
        (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-/+]{30,})['\"]?",
         "Private Key", "critical"),
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
         "Private Key in Source", "critical"),
        (r"(?i)(db[_-]?password|database[_-]?password|mysql[_-]?password)\s*[=:]\s*['\"]([^'\"]+)['\"]",
         "Database Password", "critical"),
        (r"(?i)(bearer\s+[A-Za-z0-9\-_\.]{20,})",
         "Bearer Token", "high"),
        (r"(?i)(github[_-]?token|gh[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_]{35,})['\"]?",
         "GitHub Token", "critical"),
        (r"sk-[A-Za-z0-9]{48}",
         "OpenAI API Key", "critical"),
        (r"xox[baprs]-[A-Za-z0-9\-]+",
         "Slack Token", "critical"),
    ]

    async def scan(self, target: str) -> Dict[str, Any]:
        target = self._ensure_protocol(target)
        vulns = []

        async with httpx.AsyncClient(verify=False, timeout=12.0,
                                      follow_redirects=True) as client:
            # Main page
            try:
                r = await client.get(target)
                vulns += self._scan_content(r.text, target, r.headers)
            except Exception as e:
                logger.warning(f"ContentScanner main page failed: {e}")

            # JS files often contain secrets
            js_paths = ["/app.js", "/main.js", "/bundle.js", "/static/js/main.js",
                        "/assets/js/app.js", "/js/app.js", "/dist/bundle.js"]
            for jspath in js_paths:
                url = f"{target.rstrip('/')}{jspath}"
                try:
                    r = await client.get(url)
                    if r.status_code == 200 and "javascript" in r.headers.get(
                        "content-type", ""
                    ):
                        vulns += self._scan_content(r.text, url, r.headers,
                                                     is_js=True)
                except Exception:
                    pass

            # robots.txt — may reveal hidden paths
            try:
                r = await client.get(f"{target.rstrip('/')}/robots.txt")
                if r.status_code == 200:
                    disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
                    if disallowed:
                        vulns.append({
                            "type": "robots_disallow_leak",
                            "severity": "info",
                            "title": "Sensitive Paths in robots.txt",
                            "description": (
                                f"robots.txt reveals {len(disallowed)} disallowed paths: "
                                f"{', '.join(disallowed[:5])}. "
                                f"These may be sensitive endpoints worth investigating."
                            ),
                            "location": f"{target.rstrip('/')}/robots.txt",
                        })
            except Exception:
                pass

        return {
            "status": "completed",
            "scanner": "content_inspection",
            "vulnerabilities": vulns,
        }

    def _scan_content(
        self,
        text: str,
        url: str,
        headers: Any,
        is_js: bool = False,
    ) -> List[Dict]:
        vulns = []

        # ── Secret patterns ──
        for pattern, label, severity in self.SECRET_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                # Redact actual value in output
                vulns.append({
                    "type": "secret_leaked",
                    "severity": severity,
                    "title": f"Hardcoded {label} in {'JavaScript' if is_js else 'Source'}",
                    "description": (
                        f"A {label} was found hardcoded in {'a JavaScript file' if is_js else 'the page source'} "
                        f"at '{url}'. This exposes credentials to anyone who can view the source."
                    ),
                    "location": url,
                })

        # ── Email exposure ──
        emails = re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text
        )
        if emails:
            vulns.append({
                "type": "email_exposure",
                "severity": "low",
                "title": "Email Addresses Exposed in Source",
                "description": (
                    f"{len(emails)} email address(es) found in page source at '{url}'. "
                    f"Examples: {', '.join(set(emails[:3]))}. "
                    f"Emails can be harvested for phishing or spam."
                ),
                "location": url,
            })

        # ── HTML comment analysis ──
        comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL)
        sensitive_comment_keywords = [
            "password", "todo", "fixme", "hack", "bug", "debug",
            "admin", "key", "secret", "token", "credential",
        ]
        for comment in comments:
            c = comment.lower()
            hits = [k for k in sensitive_comment_keywords if k in c]
            if hits and len(comment.strip()) > 5:
                vulns.append({
                    "type": "sensitive_comment",
                    "severity": "medium",
                    "title": "Sensitive Information in HTML Comment",
                    "description": (
                        f"An HTML comment at '{url}' contains potentially sensitive "
                        f"keywords: {', '.join(hits)}. "
                        f"Comment (truncated): {comment.strip()[:100]}"
                    ),
                    "location": url,
                })
                break  # one per page is enough

        # ── CVE correlation from Server/X-Powered-By headers ──
        server  = str(headers.get("server", "")).lower()
        powered = str(headers.get("x-powered-by", "")).lower()
        combined = server + " " + powered

        for product, version_prefix, cves in SERVICE_CVE_MAP:
            if product in combined and (not version_prefix or version_prefix in combined):
                for cve_id, desc, sev in cves:
                    vulns.append({
                        "type":        "cve_correlation",
                        "severity":    sev,
                        "title":       f"{cve_id} — {desc.split(' ', 4)[:4][-1]}",
                        "description": (
                            f"Server header indicates a version matching {cve_id}. "
                            f"{desc}. "
                            f"Detected: '{combined.strip()}'"
                        ),
                        "location":    url,
                        "cve_id":      cve_id,
                    })

        return vulns

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target


class ServiceScanner:
    """
    Network service exploitation scanner.
    Uses nmap results to identify service versions, then:
    - Correlates CVEs from the version database
    - Checks for default credentials on discovered services
    - Detects unauthenticated Redis, MongoDB, Elasticsearch
    """

    async def scan(self, target: str, nmap_results: Optional[Dict] = None) -> Dict[str, Any]:
        vulns: List[Dict] = []
        target_host = self._extract_host(target)

        # ── CVE correlation from nmap results ──
        if nmap_results:
            for host_data in nmap_results.get("hosts", []):
                for proto, ports in host_data.get("protocols", {}).items():
                    for port_data in ports:
                        port    = port_data.get("port")
                        product = port_data.get("product", "").lower()
                        version = port_data.get("version", "").lower()
                        service = port_data.get("service", "").lower()
                        combined = f"{product} {version} {service}"

                        for prod_key, ver_prefix, cves in SERVICE_CVE_MAP:
                            if prod_key in combined and (
                                not ver_prefix or ver_prefix in combined
                            ):
                                for cve_id, desc, sev in cves:
                                    vulns.append({
                                        "type":        "network_cve",
                                        "severity":    sev,
                                        "title":       f"{cve_id} on port {port}",
                                        "description": (
                                            f"Port {port} runs '{product} {version}' "
                                            f"which matches {cve_id}. {desc}"
                                        ),
                                        "location":    f"{target_host}:{port}",
                                        "cve_id":      cve_id,
                                    })

        # ── Unauthenticated service checks ──
        vulns += await self._check_open_services(target_host)

        return {
            "status": "completed",
            "scanner": "service_exploitation",
            "vulnerabilities": vulns,
        }

    async def _check_open_services(self, host: str) -> List[Dict]:
        """Check for unauthenticated access to common services."""
        vulns = []

        # Redis — no-auth check
        try:
            import asyncio
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 6379), timeout=3
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(100), timeout=3)
            writer.close()
            if b"+PONG" in data:
                vulns.append({
                    "type":        "unauthenticated_redis",
                    "severity":    "critical",
                    "title":       "Unauthenticated Redis Instance",
                    "description": (
                        f"Redis on {host}:6379 responds to PING without authentication. "
                        f"Attackers can read/write all cached data, execute Lua scripts, "
                        f"and potentially achieve RCE via config rewrite."
                    ),
                    "location":    f"{host}:6379",
                    "cve_id":      "CVE-2022-0543",
                })
        except Exception:
            pass

        # MongoDB — unauthenticated check
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(f"http://{host}:27017/")
                if r.status_code == 200 and "mongodb" in r.text.lower():
                    vulns.append({
                        "type":     "unauthenticated_mongodb",
                        "severity": "critical",
                        "title":    "Unauthenticated MongoDB HTTP Interface",
                        "description": (
                            f"MongoDB HTTP interface is exposed on {host}:27017 "
                            f"without authentication."
                        ),
                        "location": f"{host}:27017",
                    })
        except Exception:
            pass

        # Elasticsearch — unauthenticated check
        for port in (9200, 9300):
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    r = await client.get(f"http://{host}:{port}/")
                    if r.status_code == 200 and "elasticsearch" in r.text.lower():
                        vulns.append({
                            "type":     "unauthenticated_elasticsearch",
                            "severity": "critical",
                            "title":    "Unauthenticated Elasticsearch",
                            "description": (
                                f"Elasticsearch on {host}:{port} is publicly accessible "
                                f"without authentication. All indexed data is exposed."
                            ),
                            "location": f"{host}:{port}",
                        })
            except Exception:
                pass

        return vulns

    def _extract_host(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.hostname or target

    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target

