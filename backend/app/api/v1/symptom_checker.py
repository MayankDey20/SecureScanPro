"""
Symptom Checker API — "Security Medical Checkup"
User describes symptoms (e.g. "slow responses, strange redirects, admin logged in unexpectedly")
and receives a differential diagnosis: matching known attack patterns, historical breaches,
vulnerability classes, and actionable remediation advice.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import logging
import asyncio

from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/symptom-checker", tags=["symptom-checker"])
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
#  Rich knowledge base: real-world attack patterns with symptoms
# ─────────────────────────────────────────────────────────────────
ATTACK_PATTERNS = [
    {
        "id": "sql-injection",
        "name": "SQL Injection",
        "owasp": "A03:2021 – Injection",
        "severity": "critical",
        "keywords": ["sql", "database", "error", "query", "syntax", "mysql", "postgres", "ora-", "500 error",
                     "unexpected output", "login bypass", "union", "drop table", "db crash"],
        "symptom_phrases": ["database errors in response", "unexpected data in output", "login works with any password",
                            "error messages exposing table names", "slow database queries"],
        "historical_attacks": [
            {"name": "Heartland Payment Systems (2008)", "detail": "SQL injection led to theft of 130M+ card numbers — largest breach at the time."},
            {"name": "Sony Pictures (2011)", "detail": "Simple SQLi exposed 1M+ user accounts, passwords, and personal data."},
            {"name": "TalkTalk (2015)", "detail": "Basic SQL injection by a 17-year-old exposed 157,000 customer records."},
        ],
        "cve_examples": ["CVE-2012-1823", "CVE-2019-0604"],
        "remediation": [
            "Use parameterized queries / prepared statements — never concatenate user input into SQL.",
            "Apply input validation: allowlist expected data types and lengths.",
            "Use an ORM (SQLAlchemy, Hibernate) that handles escaping automatically.",
            "Implement least-privilege database accounts — app user should not have DROP/ALTER rights.",
            "Enable WAF rules for common SQLi patterns.",
        ],
        "compliance": ["OWASP Top 10 A03", "PCI-DSS 6.5.1", "CWE-89"],
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 – Injection",
        "severity": "high",
        "keywords": ["script", "popup", "alert", "cookie", "session hijack", "redirect", "strange javascript",
                     "unexpected popup", "browser warning", "malicious ad", "defacement"],
        "symptom_phrases": ["users seeing unexpected popups", "browser redirecting to unknown sites",
                            "session cookies being stolen", "page content looks altered"],
        "historical_attacks": [
            {"name": "British Airways (2018)", "detail": "Stored XSS via Magecart skimmer injected into payment page, stealing 500K card details."},
            {"name": "eBay (2014)", "detail": "Stored XSS allowed attackers to redirect users to phishing pages from legitimate eBay listings."},
            {"name": "Samy Worm — MySpace (2005)", "detail": "Self-propagating XSS worm infected 1M+ profiles in under 20 hours."},
        ],
        "cve_examples": ["CVE-2021-26084", "CVE-2020-17496"],
        "remediation": [
            "Implement Content Security Policy (CSP) headers to restrict script sources.",
            "Apply context-aware output encoding for all user-controlled data rendered in HTML/JS/CSS.",
            "Use modern frameworks (React, Vue) which auto-escape by default — avoid dangerouslySetInnerHTML.",
            "Set HttpOnly and Secure flags on session cookies.",
            "Validate and sanitize all user input server-side.",
        ],
        "compliance": ["OWASP Top 10 A03", "PCI-DSS 6.5.7", "CWE-79"],
    },
    {
        "id": "brute-force",
        "name": "Brute Force / Credential Stuffing",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "severity": "high",
        "keywords": ["login", "failed attempts", "locked out", "unusual login", "multiple ips", "bot", "slow login",
                     "account takeover", "password spray", "credential", "unauthorized access", "login spike"],
        "symptom_phrases": ["many failed login attempts in logs", "accounts locked out unexpectedly",
                            "logins from unusual geographic locations", "spike in authentication requests"],
        "historical_attacks": [
            {"name": "Credential Stuffing — Zoom (2020)", "detail": "500K+ Zoom credentials sold on dark web after credential stuffing from previously breached databases."},
            {"name": "GitHub (2013)", "detail": "Brute force attack against GitHub accounts; led to introduction of 2FA enforcement."},
            {"name": "Dunkin' Donuts (2019)", "detail": "Credential stuffing compromised DD Perks accounts; attackers redeemed rewards points."},
        ],
        "cve_examples": ["CWE-307", "CWE-521"],
        "remediation": [
            "Implement account lockout or progressive delays after N failed attempts.",
            "Enforce Multi-Factor Authentication (MFA/2FA) on all accounts.",
            "Use CAPTCHAs on login forms to block automated attempts.",
            "Monitor and alert on login anomalies (geo-velocity, IP reputation).",
            "Check credentials against HaveIBeenPwned API at registration/login.",
        ],
        "compliance": ["OWASP Top 10 A07", "NIST 800-63B", "CWE-307"],
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021 – SSRF",
        "severity": "critical",
        "keywords": ["internal", "metadata", "aws", "169.254", "localhost", "internal ip", "cloud metadata",
                     "unusual outbound", "url fetch", "webhook abuse", "internal service"],
        "symptom_phrases": ["server fetching internal URLs", "AWS metadata endpoint accessed",
                            "requests to internal services from app", "unexpected outbound connections"],
        "historical_attacks": [
            {"name": "Capital One Breach (2019)", "detail": "SSRF against AWS EC2 metadata service exposed IAM credentials, leading to exfiltration of 100M+ records."},
            {"name": "GitLab SSRF (2021)", "detail": "CVE-2021-22214 allowed unauthenticated SSRF to read internal services."},
        ],
        "cve_examples": ["CVE-2021-22214", "CVE-2019-11043"],
        "remediation": [
            "Validate and allowlist permitted outbound request destinations.",
            "Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, 172.16.x.x, 192.168.x.x).",
            "Use IMDSv2 (token-based) on AWS EC2 to prevent SSRF metadata access.",
            "Disable unnecessary URL fetch functionality in application logic.",
            "Implement egress firewall rules to restrict outbound traffic.",
        ],
        "compliance": ["OWASP Top 10 A10", "CWE-918"],
    },
    {
        "id": "rce",
        "name": "Remote Code Execution (RCE)",
        "owasp": "A03:2021 – Injection",
        "severity": "critical",
        "keywords": ["command", "shell", "exec", "process", "system call", "eval", "deserialization",
                     "unexpected process", "server cpu spike", "cryptominer", "reverse shell", "unusual process"],
        "symptom_phrases": ["unexpected processes running on server", "high CPU usage from unknown processes",
                            "server executing arbitrary commands", "cryptominer detected",
                            "unusual network connections from server"],
        "historical_attacks": [
            {"name": "Log4Shell (2021)", "detail": "CVE-2021-44228 — JNDI injection via Log4j allowed unauthenticated RCE across millions of services worldwide."},
            {"name": "EternalBlue / WannaCry (2017)", "detail": "SMB vulnerability allowed RCE propagating ransomware to 200K+ systems in 150 countries."},
            {"name": "Spring4Shell (2022)", "detail": "CVE-2022-22965 — Java Spring Framework RCE via data binding, affecting widespread Java applications."},
        ],
        "cve_examples": ["CVE-2021-44228", "CVE-2017-0144", "CVE-2022-22965"],
        "remediation": [
            "Never pass user-controlled data to eval(), exec(), system(), or similar functions.",
            "Keep all dependencies and frameworks updated — subscribe to CVE advisories.",
            "Use application sandboxing (containers, AppArmor, SELinux) to limit blast radius.",
            "Implement runtime application self-protection (RASP) for critical apps.",
            "Monitor for unusual process spawning and outbound connections.",
        ],
        "compliance": ["OWASP Top 10 A03", "CWE-78", "CWE-502"],
    },
    {
        "id": "path-traversal",
        "name": "Path Traversal / Directory Traversal",
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "high",
        "keywords": ["../", "file", "directory", "etc/passwd", "config", "read file", "download",
                     "sensitive file", "traversal", "windows/system32", "local file inclusion", "lfi"],
        "symptom_phrases": ["application serving system files", "config files accessible via URL",
                            "filenames in URLs with ../ sequences", "user accessing files outside web root"],
        "historical_attacks": [
            {"name": "Microsoft Exchange ProxyLogon (2021)", "detail": "Path traversal component of chain exploit allowed unauthenticated attackers to write files."},
            {"name": "Pulse Secure VPN (2019)", "detail": "CVE-2019-11510 — unauthenticated path traversal to read arbitrary files including credentials."},
        ],
        "cve_examples": ["CVE-2019-11510", "CVE-2021-26855"],
        "remediation": [
            "Canonicalize file paths using realpath() and verify they remain within the expected base directory.",
            "Never use user-supplied input directly in file system operations.",
            "Implement allowlists for permitted file names/extensions.",
            "Run the web application with a user that has minimal file system permissions.",
        ],
        "compliance": ["OWASP Top 10 A01", "CWE-22"],
    },
    {
        "id": "idor",
        "name": "Insecure Direct Object Reference (IDOR)",
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "high",
        "keywords": ["id", "user id", "account", "object", "sequential", "can access other user", "unauthorized",
                     "object reference", "increment", "guid", "access control", "privilege"],
        "symptom_phrases": ["changing ID in URL accesses other users' data", "sequential IDs in API responses",
                            "no authorization check on resource access", "users accessing others' records"],
        "historical_attacks": [
            {"name": "Instagram IDOR (2019)", "detail": "IDOR allowed any user to view private posts and stories of other users by manipulating media IDs."},
            {"name": "Venmo IDOR (2018)", "detail": "Public transaction feed exposed private financial data — 207M transactions scraped."},
            {"name": "Parler (2021)", "detail": "Sequential post IDs with no auth allowed bulk scraping of all deleted posts before shutdown."},
        ],
        "cve_examples": ["CWE-639", "CWE-284"],
        "remediation": [
            "Implement server-side authorization checks on every resource access — never trust client-supplied IDs alone.",
            "Use non-sequential, unpredictable UUIDs for resource identifiers.",
            "Enforce ownership checks: verify the requesting user owns the resource.",
            "Conduct regular authorization testing (IDOR-specific pentest checklist).",
        ],
        "compliance": ["OWASP Top 10 A01", "CWE-639"],
    },
    {
        "id": "mitm",
        "name": "Man-in-the-Middle (MITM) / SSL Strip",
        "owasp": "A02:2021 – Cryptographic Failures",
        "severity": "high",
        "keywords": ["ssl", "tls", "certificate", "http", "mixed content", "expired cert", "invalid cert",
                     "traffic intercept", "downgrade", "weak cipher", "hsts", "cleartext"],
        "symptom_phrases": ["SSL certificate warnings in browser", "HTTP traffic visible on network",
                            "mixed content warnings", "weak TLS version (TLS 1.0/1.1)", "missing HSTS header"],
        "historical_attacks": [
            {"name": "DigiNotar CA Compromise (2011)", "detail": "Fraudulent Google SSL certs issued after CA breach enabled MITM against 300K+ Iranian users."},
            {"name": "Lenovo Superfish (2015)", "detail": "Pre-installed adware intercepted HTTPS traffic by installing a rogue root CA on Lenovo laptops."},
            {"name": "BEAST Attack (2011)", "detail": "TLS 1.0 CBC vulnerability allowed MITM to decrypt HTTPS cookies, leading to mass TLS upgrades."},
        ],
        "cve_examples": ["CVE-2014-0224", "CVE-2009-3555"],
        "remediation": [
            "Enforce TLS 1.2+ and disable TLS 1.0/1.1 and SSLv3.",
            "Implement HTTP Strict Transport Security (HSTS) with long max-age and includeSubDomains.",
            "Use strong cipher suites — disable RC4, 3DES, export-grade ciphers.",
            "Enable OCSP stapling and certificate pinning for mobile apps.",
            "Redirect all HTTP traffic to HTTPS at the load balancer level.",
        ],
        "compliance": ["OWASP Top 10 A02", "PCI-DSS 4.1", "CWE-295"],
    },
    {
        "id": "xxe",
        "name": "XML External Entity (XXE) Injection",
        "owasp": "A03:2021 – Injection",
        "severity": "high",
        "keywords": ["xml", "soap", "doctype", "entity", "external", "xxe", "xml parser", "xml upload",
                     "file read via xml", "ssrf via xml"],
        "symptom_phrases": ["XML parsing errors in logs", "application accepting XML input",
                            "server reading local files via XML", "SOAP endpoint present"],
        "historical_attacks": [
            {"name": "PayPal XXE (2013)", "detail": "XXE in payment processing endpoint allowed reading of internal server files."},
            {"name": "Facebook XXE (2014)", "detail": "XXE via Word document upload allowed SSRF and internal file disclosure, earning $30K bug bounty."},
        ],
        "cve_examples": ["CVE-2014-3660", "CVE-2018-1000840"],
        "remediation": [
            "Disable external entity processing in XML parsers (set FEATURE_EXTERNAL_GENERAL_ENTITIES to false).",
            "Use JSON instead of XML where possible.",
            "Validate and sanitize all XML input before parsing.",
            "Use modern XML libraries with secure defaults (lxml with resolve_entities=False).",
        ],
        "compliance": ["OWASP Top 10 A03", "CWE-611"],
    },
    {
        "id": "supply-chain",
        "name": "Supply Chain / Dependency Attack",
        "owasp": "A06:2021 – Vulnerable and Outdated Components",
        "severity": "critical",
        "keywords": ["dependency", "npm", "package", "library", "outdated", "third party", "open source",
                     "npm audit", "typosquat", "malicious package", "build pipeline", "ci/cd"],
        "symptom_phrases": ["outdated packages with known CVEs", "unexpected package behaviour",
                            "typosquatting package installed", "build pipeline producing unexpected artifacts"],
        "historical_attacks": [
            {"name": "SolarWinds (2020)", "detail": "Malicious code inserted into SolarWinds Orion build pipeline, affecting 18,000+ organizations including US government agencies."},
            {"name": "event-stream npm (2018)", "detail": "Malicious code injected into popular npm package (2M downloads/week) to steal Bitcoin wallet credentials."},
            {"name": "ua-parser-js (2021)", "detail": "Hijacked npm package with 9M weekly downloads deployed cryptominer and password stealer."},
        ],
        "cve_examples": ["CVE-2021-44228", "CVE-2020-10148"],
        "remediation": [
            "Run dependency audits regularly (npm audit, pip-audit, Snyk, Dependabot).",
            "Pin dependency versions and verify checksums/hashes in lockfiles.",
            "Use private package registries with allowlisted packages.",
            "Implement software composition analysis (SCA) in your CI/CD pipeline.",
            "Subscribe to security advisories for all major dependencies.",
        ],
        "compliance": ["OWASP Top 10 A06", "CWE-937", "SLSA Framework"],
    },
    {
        "id": "data-exposure",
        "name": "Sensitive Data Exposure / Data Leak",
        "owasp": "A02:2021 – Cryptographic Failures",
        "severity": "high",
        "keywords": ["password", "api key", "token", "secret", "plaintext", "log", "debug", "stack trace",
                     "git", "s3", "bucket", "exposed", "leak", "dump", "backup", "env file"],
        "symptom_phrases": ["API keys in public git repositories", "passwords stored in plaintext",
                            "stack traces visible to users", ".env file publicly accessible",
                            "database backups in public storage", "credentials in logs"],
        "historical_attacks": [
            {"name": "Uber (2016)", "detail": "AWS credentials in GitHub repo led to 57M user/driver records being accessed. Uber paid $100K ransom and concealed breach for a year."},
            {"name": "Facebook (2019)", "detail": "Hundreds of millions of user passwords stored in plaintext in internal logs, discoverable by 2,000+ engineers."},
            {"name": "Toyota (2023)", "detail": "Git repo with access key exposed 2.15M customer records for a decade."},
        ],
        "cve_examples": ["CWE-312", "CWE-359"],
        "remediation": [
            "Use secrets management tools (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets).",
            "Never commit secrets to version control — use pre-commit hooks (git-secrets, truffleHog).",
            "Encrypt sensitive data at rest (AES-256) and in transit (TLS 1.2+).",
            "Hash passwords with bcrypt/argon2 — never SHA1/MD5 for passwords.",
            "Audit public-facing S3 buckets and git repos for accidental exposure.",
        ],
        "compliance": ["OWASP Top 10 A02", "GDPR Article 32", "CWE-312"],
    },
    {
        "id": "ddos",
        "name": "DDoS / Resource Exhaustion",
        "owasp": "A05:2021 – Security Misconfiguration",
        "severity": "high",
        "keywords": ["slow", "down", "unavailable", "timeout", "traffic spike", "bandwidth", "cpu 100",
                     "memory full", "server unresponsive", "latency", "rate limit", "flood", "bot traffic"],
        "symptom_phrases": ["server unresponsive under load", "massive spike in traffic from unusual IPs",
                            "CPU/memory maxing out with no code change", "requests timing out consistently",
                            "no rate limiting on endpoints"],
        "historical_attacks": [
            {"name": "GitHub DDoS (2018)", "detail": "1.35 Tbps memcached amplification attack — largest DDoS ever recorded at that time. Mitigated in 10 minutes."},
            {"name": "Dyn DNS (2016)", "detail": "Mirai botnet DDoS (1.2 Tbps) took down Twitter, Netflix, Reddit, Amazon for hours via DNS provider."},
            {"name": "Cloudflare (2023)", "detail": "HTTP/2 Rapid Reset attack — 201M rps, largest DDoS ever, exploiting HTTP/2 protocol vulnerability."},
        ],
        "cve_examples": ["CVE-2023-44487", "CWE-400"],
        "remediation": [
            "Implement rate limiting at the API gateway / load balancer level.",
            "Use a CDN/DDoS mitigation service (Cloudflare, AWS Shield, Akamai).",
            "Apply connection throttling and request queue limits.",
            "Configure auto-scaling to handle legitimate traffic spikes.",
            "Block known bot/scanner IP ranges via firewall rules.",
        ],
        "compliance": ["OWASP Top 10 A05", "CWE-400"],
    },
    {
        "id": "open-redirect",
        "name": "Open Redirect / Phishing Vector",
        "owasp": "A01:2021 – Broken Access Control",
        "severity": "medium",
        "keywords": ["redirect", "url", "next", "return", "goto", "phishing", "link", "forwarding",
                     "referrer", "suspicious url", "external redirect"],
        "symptom_phrases": ["application redirects to external URLs", "redirect parameter in URL not validated",
                            "users being sent to phishing sites via your domain", "OAuth redirect_uri abuse"],
        "historical_attacks": [
            {"name": "Google Open Redirect (2012)", "detail": "Google's redirect parameter allowed phishing attacks using a trusted google.com URL prefix."},
            {"name": "PayPal Phishing via Open Redirect", "detail": "PayPal's open redirect used in phishing campaigns — victims saw legitimate paypal.com in URL before being redirected."},
        ],
        "cve_examples": ["CWE-601"],
        "remediation": [
            "Allowlist permitted redirect destinations — never allow arbitrary external URLs.",
            "Validate that redirect targets are relative paths or trusted domains only.",
            "Show a confirmation page before redirecting to any external URL.",
            "Audit OAuth redirect_uri registration to only allow exact URLs.",
        ],
        "compliance": ["OWASP Top 10 A01", "CWE-601"],
    },
]


# ─────────────────────────────────────────────────────────────────
#  Symptom matching logic
# ─────────────────────────────────────────────────────────────────
def _score_pattern(symptoms_lower: str, pattern: dict) -> float:
    """Score how well a symptom description matches an attack pattern."""
    score = 0.0

    for kw in pattern["keywords"]:
        if kw in symptoms_lower:
            score += 2.0

    for phrase in pattern.get("symptom_phrases", []):
        # partial match on phrase words
        phrase_words = phrase.lower().split()
        hits = sum(1 for w in phrase_words if w in symptoms_lower)
        if hits >= 2:
            score += hits * 1.5

    return score


def _heuristic_diagnose(symptoms: str) -> List[Dict[str, Any]]:
    """Score all patterns and return top matches with confidence."""
    s = symptoms.lower()
    scored = []
    for pattern in ATTACK_PATTERNS:
        score = _score_pattern(s, pattern)
        if score > 0:
            # Normalise to 0-1
            max_possible = len(pattern["keywords"]) * 2 + len(pattern.get("symptom_phrases", [])) * 6
            confidence = min(score / max(max_possible * 0.25, 1), 1.0)
            scored.append((confidence, pattern))

    scored.sort(key=lambda x: x[0], reverse=True)

    results = []
    for conf, pattern in scored[:5]:
        results.append({
            "attack_id":    pattern["id"],
            "name":         pattern["name"],
            "owasp":        pattern["owasp"],
            "severity":     pattern["severity"],
            "confidence":   round(conf, 2),
            "match_reason": f"Symptoms match {len([k for k in pattern['keywords'] if k in s])} indicator(s) for {pattern['name']}.",
            "historical_attacks":  pattern["historical_attacks"],
            "cve_examples":        pattern["cve_examples"],
            "remediation":         pattern["remediation"],
            "compliance":          pattern["compliance"],
        })

    return results


# ─────────────────────────────────────────────────────────────────
#  Gemini-powered diagnosis prompt
# ─────────────────────────────────────────────────────────────────
_SYMPTOM_PROMPT = """You are a world-class cybersecurity expert acting as a "security doctor".
A user has described symptoms their system is exhibiting. Your job is to diagnose possible security vulnerabilities and attacks.

Symptoms described by user:
{symptoms}

Known attack patterns to consider (pick the best matches):
{patterns_summary}

Respond ONLY with a valid JSON array of up to 5 objects. No markdown, no explanation outside the JSON.

Each object must follow this exact schema:
{{
  "attack_id": "<id from the pattern list>",
  "name": "<attack name>",
  "owasp": "<OWASP category>",
  "severity": "<critical|high|medium|low>",
  "confidence": <0.0-1.0 float>,
  "match_reason": "<2-sentence explanation of why these symptoms suggest this attack>",
  "historical_attacks": [
    {{"name": "<real breach name + year>", "detail": "<1-2 sentence description of how it happened and impact>"}}
  ],
  "cve_examples": ["<CVE or CWE ID>"],
  "remediation": ["<specific actionable step 1>", "<step 2>", "<step 3>"],
  "compliance": ["<OWASP/CWE/PCI-DSS reference>"]
}}"""


async def _gemini_diagnose(symptoms: str) -> List[Dict[str, Any]]:
    """Use Gemini to diagnose symptoms."""
    api_key = settings.GEMINI_API_KEY
    if not api_key or api_key == "your-gemini-api-key":
        return []

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={"temperature": 0.3, "response_mime_type": "application/json"},
        )

        # Build compact patterns summary for the prompt
        patterns_summary = "\n".join(
            f"- id={p['id']}, name={p['name']}, keywords={', '.join(p['keywords'][:8])}"
            for p in ATTACK_PATTERNS
        )

        prompt = _SYMPTOM_PROMPT.format(
            symptoms=symptoms,
            patterns_summary=patterns_summary,
        )

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: model.generate_content(prompt))

        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        results = json.loads(text)
        # Merge in historical attacks from our knowledge base if Gemini returned fewer
        id_to_pattern = {p["id"]: p for p in ATTACK_PATTERNS}
        for r in results:
            if not r.get("historical_attacks") and r.get("attack_id") in id_to_pattern:
                r["historical_attacks"] = id_to_pattern[r["attack_id"]]["historical_attacks"]
        return results

    except Exception as e:
        logger.warning(f"Gemini symptom diagnosis failed: {e} — falling back to heuristics")
        return []


# ─────────────────────────────────────────────────────────────────
#  Request / Response models
# ─────────────────────────────────────────────────────────────────
class SymptomRequest(BaseModel):
    symptoms: str       # free-text description of observed symptoms
    context: str = ""   # optional: tech stack, environment info


class SymptomResponse(BaseModel):
    diagnoses: List[Dict[str, Any]]
    ai_powered: bool
    symptom_summary: str
    total_matches: int


# ─────────────────────────────────────────────────────────────────
#  Endpoint
# ─────────────────────────────────────────────────────────────────
@router.post("/diagnose", response_model=SymptomResponse)
async def diagnose_symptoms(
    req: SymptomRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Security Medical Checkup — diagnose possible vulnerabilities from symptom description.
    Returns ranked list of matching attack patterns with historical breaches and remediation.
    """
    if not req.symptoms or len(req.symptoms.strip()) < 5:
        raise HTTPException(status_code=422, detail="Please describe your symptoms in more detail.")

    combined = req.symptoms + " " + req.context

    # Try Gemini first, fall back to heuristics
    diagnoses = await _gemini_diagnose(combined)
    ai_powered = bool(diagnoses)

    if not diagnoses:
        diagnoses = _heuristic_diagnose(combined)

    # If still nothing matched, return a generic advice
    if not diagnoses:
        diagnoses = [{
            "attack_id":   "general",
            "name":        "General Security Review Recommended",
            "owasp":       "General",
            "severity":    "medium",
            "confidence":  0.3,
            "match_reason": "The described symptoms do not clearly match known attack patterns. A general security audit is recommended.",
            "historical_attacks": [],
            "cve_examples": [],
            "remediation": [
                "Run a full automated security scan to detect surface-level issues.",
                "Review application logs for anomalies in the past 30 days.",
                "Conduct a dependency audit (npm audit / pip-audit).",
                "Review access control policies and recent privilege changes.",
            ],
            "compliance": ["OWASP Top 10", "CWE Top 25"],
        }]

    return SymptomResponse(
        diagnoses=diagnoses,
        ai_powered=ai_powered,
        symptom_summary=req.symptoms[:200],
        total_matches=len(diagnoses),
    )
