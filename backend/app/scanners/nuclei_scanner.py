"""
Nuclei Scanner Integration for SecureScan Pro
Provides comprehensive vulnerability scanning using ProjectDiscovery's Nuclei
"""
import asyncio
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)


@dataclass
class NucleiConfig:
    """Configuration for Nuclei scanner"""
    # Template categories to run
    templates: List[str] = field(default_factory=lambda: [
        "cves", "vulnerabilities", "exposures", "misconfiguration", 
        "technologies", "default-logins"
    ])
    # Severity filter
    severity: List[str] = field(default_factory=lambda: [
        "critical", "high", "medium", "low"
    ])
    # Rate limiting
    rate_limit: int = 150
    bulk_size: int = 25
    concurrency: int = 25
    # Timeout
    timeout: int = 10
    # Additional options
    follow_redirects: bool = True
    max_host_errors: int = 30
    # Custom templates directory
    custom_templates_dir: Optional[str] = None
    # Headers
    headers: Dict[str, str] = field(default_factory=dict)


class NucleiScanner:
    """
    Nuclei-based vulnerability scanner
    Requires Nuclei to be installed: https://github.com/projectdiscovery/nuclei
    """
    
    NUCLEI_PATH = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    
    def __init__(self, config: Optional[NucleiConfig] = None):
        self.config = config or NucleiConfig()
        self._verify_installation()
    
    def _verify_installation(self):
        """Verify Nuclei is installed"""
        if not os.path.exists(self.NUCLEI_PATH):
            logger.warning("Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    
    async def scan(self, target: str, progress_callback=None) -> Dict[str, Any]:
        """
        Run Nuclei scan on target
        """
        results = {
            "status": "completed",
            "scanner": "nuclei",
            "target": target,
            "findings": [],
            "summary": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "templates_used": 0,
            "errors": []
        }
        
        if not os.path.exists(self.NUCLEI_PATH):
            results["status"] = "error"
            results["errors"].append("Nuclei not installed")
            return results
        
        target = self._ensure_protocol(target)
        
        try:
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Build command
            cmd = self._build_command(target, output_file)
            
            logger.info(f"Running Nuclei scan: {' '.join(cmd)}")
            
            if progress_callback:
                await progress_callback({
                    "phase": "nuclei_scan",
                    "message": "Starting Nuclei vulnerability scan",
                    "progress": 0
                })
            
            # Run Nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Stream output for progress updates
            findings_count = 0
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode().strip()
                if line_str:
                    # Nuclei outputs JSON lines when using -json flag
                    try:
                        finding = json.loads(line_str)
                        parsed = self._parse_finding(finding)
                        if parsed:
                            results["findings"].append(parsed)
                            findings_count += 1
                            results["summary"][parsed["severity"]] += 1
                            results["summary"]["total"] += 1
                            
                            if progress_callback:
                                await progress_callback({
                                    "phase": "nuclei_scan",
                                    "message": f"Found: {parsed['title']}",
                                    "findings_count": findings_count,
                                    "severity": parsed["severity"]
                                })
                    except json.JSONDecodeError:
                        # Not JSON, might be status message
                        logger.debug(f"Nuclei: {line_str}")
            
            await process.wait()
            
            # Also read from output file in case streaming missed anything
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            parsed = self._parse_finding(finding)
                            if parsed and not any(
                                f["fingerprint"] == parsed["fingerprint"] 
                                for f in results["findings"]
                            ):
                                results["findings"].append(parsed)
                                results["summary"][parsed["severity"]] += 1
                                results["summary"]["total"] += 1
                        except json.JSONDecodeError:
                            continue
                
                os.unlink(output_file)
            
            if progress_callback:
                await progress_callback({
                    "phase": "nuclei_scan",
                    "message": "Nuclei scan completed",
                    "progress": 100,
                    "total_findings": results["summary"]["total"]
                })
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            results["status"] = "error"
            results["errors"].append(str(e))
        
        return results
    
    def _build_command(self, target: str, output_file: str) -> List[str]:
        """Build Nuclei command with options"""
        cmd = [
            self.NUCLEI_PATH,
            "-u", target,
            "-json",
            "-o", output_file,
            "-rate-limit", str(self.config.rate_limit),
            "-bulk-size", str(self.config.bulk_size),
            "-c", str(self.config.concurrency),
            "-timeout", str(self.config.timeout),
            "-max-host-error", str(self.config.max_host_errors),
            "-silent",
            "-no-color"
        ]
        
        # Add severity filter
        if self.config.severity:
            cmd.extend(["-severity", ",".join(self.config.severity)])
        
        # Add template categories
        if self.config.templates:
            for template in self.config.templates:
                cmd.extend(["-tags", template])
        
        # Custom templates
        if self.config.custom_templates_dir:
            cmd.extend(["-t", self.config.custom_templates_dir])
        
        # Headers
        for key, value in self.config.headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
        
        # Follow redirects
        if self.config.follow_redirects:
            cmd.append("-follow-redirects")
        
        return cmd
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse Nuclei JSON output into our vulnerability format"""
        try:
            info = finding.get("info", {})
            severity = info.get("severity", "info").lower()
            
            # Map Nuclei severity to our format
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
                "unknown": "info"
            }
            severity = severity_map.get(severity, "info")
            
            # Extract CVE/CWE if available
            cve_id = None
            cwe_id = None
            classification = info.get("classification", {})
            
            if "cve-id" in classification:
                cve_ids = classification["cve-id"]
                cve_id = cve_ids[0] if cve_ids else None
            
            if "cwe-id" in classification:
                cwe_ids = classification["cwe-id"]
                cwe_id = cwe_ids[0] if cwe_ids else None
            
            # Build fingerprint for deduplication
            import hashlib
            fingerprint_data = f"{finding.get('template-id', '')}:{finding.get('matched-at', '')}:{finding.get('matcher-name', '')}"
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
            
            return {
                "title": info.get("name", "Unknown Vulnerability"),
                "description": info.get("description", ""),
                "severity": severity,
                "cvss_score": classification.get("cvss-score"),
                "cvss_vector": classification.get("cvss-metrics"),
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "vuln_type": info.get("tags", ["unknown"])[0] if info.get("tags") else "unknown",
                "location": finding.get("matched-at", finding.get("host", "")),
                "evidence": finding.get("extracted-results", []),
                "matcher": finding.get("matcher-name", ""),
                "template_id": finding.get("template-id", ""),
                "template_path": finding.get("template-path", ""),
                "reference": info.get("reference", []),
                "remediation": info.get("remediation", ""),
                "fingerprint": fingerprint,
                "raw": finding  # Keep raw output for debugging
            }
            
        except Exception as e:
            logger.error(f"Failed to parse Nuclei finding: {e}")
            return None
    
    def _ensure_protocol(self, target: str) -> str:
        """Ensure target has protocol"""
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            process = await asyncio.create_subprocess_exec(
                self.NUCLEI_PATH, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Failed to update Nuclei templates: {e}")
            return False


class AdvancedVulnScanner:
    """
    Advanced vulnerability scanner combining multiple engines
    """
    
    def __init__(self):
        self.nuclei = NucleiScanner()
        self.custom_checks = CustomSecurityChecks()
    
    async def scan(self, target: str, scan_types: List[str] = None, progress_callback=None) -> Dict[str, Any]:
        """
        Run comprehensive vulnerability scan
        """
        results = {
            "status": "completed",
            "target": target,
            "findings": [],
            "summary": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "scanners_used": []
        }
        
        scan_types = scan_types or ["nuclei", "owasp", "custom"]
        
        # Run Nuclei scanner
        if "nuclei" in scan_types or "full" in scan_types:
            if progress_callback:
                await progress_callback({"phase": "nuclei", "message": "Running Nuclei scanner"})
            
            nuclei_results = await self.nuclei.scan(target, progress_callback)
            results["findings"].extend(nuclei_results.get("findings", []))
            results["scanners_used"].append("nuclei")
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                results["summary"][severity] += nuclei_results["summary"].get(severity, 0)
        
        # Run custom OWASP checks
        if "owasp" in scan_types or "full" in scan_types:
            if progress_callback:
                await progress_callback({"phase": "owasp", "message": "Running OWASP security checks"})
            
            owasp_results = await self.custom_checks.run_owasp_checks(target)
            results["findings"].extend(owasp_results)
            results["scanners_used"].append("owasp_custom")
        
        # Update summary
        results["summary"]["total"] = len(results["findings"])
        
        return results


class CustomSecurityChecks:
    """
    Custom security checks for OWASP Top 10 and common vulnerabilities
    """
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'SecureScan-Pro/1.0 (Security Scanner)'
        }
    
    async def run_owasp_checks(self, target: str) -> List[Dict]:
        """Run OWASP Top 10 security checks"""
        findings = []
        
        target = self._ensure_protocol(target)
        
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            # A01: Broken Access Control
            findings.extend(await self._check_access_control(client, target))
            
            # A02: Cryptographic Failures
            findings.extend(await self._check_crypto(client, target))
            
            # A03: Injection (basic checks)
            findings.extend(await self._check_injection(client, target))
            
            # A05: Security Misconfiguration
            findings.extend(await self._check_misconfig(client, target))
            
            # A06: Vulnerable Components (via headers/fingerprinting)
            findings.extend(await self._check_vulnerable_components(client, target))
            
            # A07: Auth Failures
            findings.extend(await self._check_auth(client, target))
            
            # A09: Security Logging (CORS, etc.)
            findings.extend(await self._check_cors(client, target))
        
        return findings
    
    async def _check_access_control(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for access control issues"""
        findings = []
        
        sensitive_paths = [
            "/.git/config", "/.env", "/.htaccess", "/wp-config.php",
            "/config.php", "/settings.py", "/web.config", "/.svn/entries",
            "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
            "/admin", "/administrator", "/phpmyadmin", "/cpanel",
            "/.aws/credentials", "/.docker/config.json", "/id_rsa",
            "/server-status", "/server-info", "/.well-known/security.txt"
        ]
        
        for path in sensitive_paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                resp = await client.get(url, headers=self.headers, follow_redirects=False)
                
                if resp.status_code == 200:
                    # Check if it's actually sensitive content
                    content = resp.text.lower()
                    is_sensitive = any([
                        "password" in content,
                        "secret" in content,
                        "api_key" in content,
                        "database" in content and "host" in content,
                        "[core]" in content,  # .git/config
                        "AWS_" in resp.text,
                        "BEGIN RSA" in resp.text,
                        "root:" in content,  # /etc/passwd style
                    ])
                    
                    severity = "critical" if is_sensitive else "medium"
                    
                    findings.append({
                        "title": f"Sensitive Path Exposed: {path}",
                        "description": f"The path {path} is accessible and may expose sensitive information",
                        "severity": severity,
                        "vuln_type": "exposure",
                        "owasp_category": "A01:2021-Broken Access Control",
                        "location": url,
                        "evidence": f"HTTP {resp.status_code}",
                        "remediation": "Restrict access to sensitive files and directories using proper access controls"
                    })
                    
            except Exception:
                continue
        
        return findings
    
    async def _check_crypto(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for cryptographic issues"""
        findings = []
        
        try:
            resp = await client.get(target, headers=self.headers)
            
            # Check for HTTP (non-HTTPS)
            if target.startswith("http://"):
                findings.append({
                    "title": "Site Not Using HTTPS",
                    "description": "The website is accessible over unencrypted HTTP",
                    "severity": "high",
                    "vuln_type": "crypto",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "location": target,
                    "remediation": "Implement HTTPS with a valid TLS certificate and redirect all HTTP traffic to HTTPS"
                })
            
            # Check for Strict-Transport-Security header
            if "strict-transport-security" not in resp.headers:
                findings.append({
                    "title": "Missing HSTS Header",
                    "description": "HTTP Strict Transport Security header is not set",
                    "severity": "medium",
                    "vuln_type": "header",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "location": target,
                    "remediation": "Add Strict-Transport-Security header with appropriate max-age"
                })
            
        except Exception as e:
            logger.error(f"Crypto check failed: {e}")
        
        return findings
    
    async def _check_injection(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for injection vulnerabilities"""
        findings = []
        
        # SQL Injection error-based detection
        sqli_payloads = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--"]
        sql_errors = [
            "sql syntax", "mysql_fetch", "sqlite3", "postgresql",
            "ora-01756", "sqlstate", "jdbc", "odbc", "sql server"
        ]
        
        for payload in sqli_payloads:
            try:
                url = f"{target}?id={payload}"
                resp = await client.get(url, headers=self.headers)
                
                content_lower = resp.text.lower()
                for error in sql_errors:
                    if error in content_lower:
                        findings.append({
                            "title": "Potential SQL Injection",
                            "description": f"SQL error message detected with payload: {payload}",
                            "severity": "critical",
                            "vuln_type": "sqli",
                            "owasp_category": "A03:2021-Injection",
                            "location": url,
                            "evidence": f"SQL error pattern: {error}",
                            "remediation": "Use parameterized queries or prepared statements"
                        })
                        break
            except Exception:
                continue
        
        # XSS reflection check
        xss_payload = "<script>alert(1)</script>"
        try:
            url = f"{target}?q={xss_payload}"
            resp = await client.get(url, headers=self.headers)
            
            if xss_payload in resp.text:
                findings.append({
                    "title": "Reflected Cross-Site Scripting (XSS)",
                    "description": "User input is reflected in the response without proper encoding",
                    "severity": "high",
                    "vuln_type": "xss",
                    "owasp_category": "A03:2021-Injection",
                    "location": url,
                    "evidence": "XSS payload reflected in response",
                    "remediation": "Encode all user input before rendering in HTML context"
                })
        except Exception:
            pass
        
        return findings
    
    async def _check_misconfig(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for security misconfigurations"""
        findings = []
        
        try:
            resp = await client.get(target, headers=self.headers)
            headers = resp.headers
            
            # Security headers check
            security_headers = {
                "x-content-type-options": ("Missing X-Content-Type-Options", "Add X-Content-Type-Options: nosniff"),
                "x-frame-options": ("Missing X-Frame-Options", "Add X-Frame-Options: DENY or SAMEORIGIN"),
                "x-xss-protection": ("Missing X-XSS-Protection", "Add X-XSS-Protection: 1; mode=block"),
                "content-security-policy": ("Missing Content-Security-Policy", "Implement a strict Content-Security-Policy"),
                "referrer-policy": ("Missing Referrer-Policy", "Add Referrer-Policy: strict-origin-when-cross-origin"),
                "permissions-policy": ("Missing Permissions-Policy", "Add Permissions-Policy to control browser features")
            }
            
            for header, (title, remediation) in security_headers.items():
                if header not in headers:
                    findings.append({
                        "title": title,
                        "description": f"The {header} security header is not set",
                        "severity": "low",
                        "vuln_type": "misconfiguration",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "location": target,
                        "remediation": remediation
                    })
            
            # Check for server version disclosure
            if "server" in headers:
                server_value = headers["server"]
                if any(v in server_value.lower() for v in ["apache/", "nginx/", "iis/", "litespeed/"]):
                    findings.append({
                        "title": "Server Version Disclosure",
                        "description": f"Server header reveals version information: {server_value}",
                        "severity": "info",
                        "vuln_type": "information_disclosure",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "location": target,
                        "evidence": f"Server: {server_value}",
                        "remediation": "Remove or obfuscate server version information"
                    })
            
            # Check for X-Powered-By
            if "x-powered-by" in headers:
                findings.append({
                    "title": "Technology Disclosure via X-Powered-By",
                    "description": f"X-Powered-By header reveals: {headers['x-powered-by']}",
                    "severity": "info",
                    "vuln_type": "information_disclosure",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "location": target,
                    "evidence": f"X-Powered-By: {headers['x-powered-by']}",
                    "remediation": "Remove X-Powered-By header"
                })
            
            # Check for directory listing
            common_dirs = ["/images/", "/uploads/", "/static/", "/assets/", "/files/"]
            for dir_path in common_dirs:
                try:
                    dir_url = f"{target.rstrip('/')}{dir_path}"
                    dir_resp = await client.get(dir_url, headers=self.headers)
                    
                    if dir_resp.status_code == 200 and "index of" in dir_resp.text.lower():
                        findings.append({
                            "title": "Directory Listing Enabled",
                            "description": f"Directory listing is enabled for {dir_path}",
                            "severity": "low",
                            "vuln_type": "misconfiguration",
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "location": dir_url,
                            "remediation": "Disable directory listing in web server configuration"
                        })
                        break
                except Exception:
                    continue
            
        except Exception as e:
            logger.error(f"Misconfig check failed: {e}")
        
        return findings
    
    async def _check_vulnerable_components(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for known vulnerable components"""
        findings = []
        
        # Known vulnerable versions (simplified - in production, use a CVE database)
        vulnerable_versions = {
            "jquery": [("1.", "jQuery 1.x"), ("2.", "jQuery 2.x")],
            "angular": [("1.", "AngularJS 1.x")],
            "bootstrap": [("3.", "Bootstrap 3.x")],
        }
        
        try:
            resp = await client.get(target, headers=self.headers)
            content = resp.text.lower()
            
            # Check for outdated libraries in HTML/JS
            for lib, versions in vulnerable_versions.items():
                if lib in content:
                    for version_prefix, desc in versions:
                        if f"{lib}/{version_prefix}" in content or f"{lib}@{version_prefix}" in content:
                            findings.append({
                                "title": f"Potentially Outdated Library: {desc}",
                                "description": f"An older version of {lib} was detected which may have known vulnerabilities",
                                "severity": "medium",
                                "vuln_type": "vulnerable_component",
                                "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                                "location": target,
                                "remediation": f"Update {lib} to the latest stable version"
                            })
            
        except Exception as e:
            logger.error(f"Component check failed: {e}")
        
        return findings
    
    async def _check_auth(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for authentication issues"""
        findings = []
        
        try:
            resp = await client.get(target, headers=self.headers)
            
            # Check for forms without CSRF tokens
            if "<form" in resp.text.lower():
                if "csrf" not in resp.text.lower() and "_token" not in resp.text.lower():
                    findings.append({
                        "title": "Potential Missing CSRF Protection",
                        "description": "Forms were found without apparent CSRF token fields",
                        "severity": "medium",
                        "vuln_type": "csrf",
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "location": target,
                        "remediation": "Implement CSRF tokens for all state-changing forms"
                    })
            
            # Check for password fields without autocomplete=off
            if 'type="password"' in resp.text and 'autocomplete="off"' not in resp.text:
                if 'autocomplete="new-password"' not in resp.text and 'autocomplete="current-password"' not in resp.text:
                    findings.append({
                        "title": "Password Field Autocomplete Enabled",
                        "description": "Password fields may allow browser autocomplete",
                        "severity": "info",
                        "vuln_type": "auth",
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "location": target,
                        "remediation": "Consider adding autocomplete attribute to password fields"
                    })
            
        except Exception as e:
            logger.error(f"Auth check failed: {e}")
        
        return findings
    
    async def _check_cors(self, client: httpx.AsyncClient, target: str) -> List[Dict]:
        """Check for CORS misconfigurations"""
        findings = []
        
        try:
            # Send request with Origin header
            evil_origin = "https://evil.com"
            headers = {**self.headers, "Origin": evil_origin}
            resp = await client.get(target, headers=headers)
            
            acao = resp.headers.get("access-control-allow-origin", "")
            
            if acao == "*":
                findings.append({
                    "title": "Permissive CORS Policy (Wildcard)",
                    "description": "CORS allows requests from any origin",
                    "severity": "medium",
                    "vuln_type": "cors",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "location": target,
                    "evidence": "Access-Control-Allow-Origin: *",
                    "remediation": "Restrict CORS to specific trusted origins"
                })
            elif acao == evil_origin:
                acac = resp.headers.get("access-control-allow-credentials", "")
                severity = "high" if acac.lower() == "true" else "medium"
                findings.append({
                    "title": "CORS Reflects Arbitrary Origin",
                    "description": "CORS policy reflects the attacker-controlled Origin header",
                    "severity": severity,
                    "vuln_type": "cors",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "location": target,
                    "evidence": f"Reflected origin: {evil_origin}",
                    "remediation": "Implement a whitelist of allowed origins"
                })
            
        except Exception as e:
            logger.error(f"CORS check failed: {e}")
        
        return findings
    
    def _ensure_protocol(self, target: str) -> str:
        if not target.startswith(('http://', 'https://')):
            return f'https://{target}'
        return target


# Import httpx at module level
import httpx
