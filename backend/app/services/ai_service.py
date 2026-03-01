
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Gemini prompt template
_PROMPT = """You are a senior application security engineer. Analyze the following vulnerability and respond ONLY with a valid JSON object — no markdown, no explanation outside the JSON.

Vulnerability:
  Title: {title}
  Description: {description}
  Severity: {severity}

Required JSON schema:
{{
  "classification": {{
    "detected_type": "<specific vulnerability class, e.g. SQL Injection, XSS, SSRF>",
    "confidence_score": <0.0-1.0>,
    "owasp_category": "<e.g. A03:2021 – Injection>"
  }},
  "risk_assessment": {{
    "calculated_risk_score": <0-100 integer>,
    "predicted_impact": "<1-2 sentence business impact>",
    "vector": "<Network|Adjacent|Local|Physical>",
    "exploitability": "<Easy|Medium|Hard>"
  }},
  "remediation": {{
    "suggested_action": "<specific, actionable fix — 2-3 sentences>",
    "priority_level": "<Immediate|High|Scheduled|Low>",
    "references": ["<relevant OWASP/CVE/CWE link>"]
  }},
  "explanation": "<2-3 sentence plain-English explanation of the vulnerability and why it matters>"
}}"""


class AIService:
    """
    AI Service powered by Google Gemini (gemini-1.5-flash).
    Falls back to rule-based heuristics if GEMINI_API_KEY is not configured.
    """

    def __init__(self):
        self._model = None
        self._init_gemini()

    def _init_gemini(self):
        """Initialize Gemini client if API key is available."""
        try:
            from app.core.config import settings
            api_key = settings.GEMINI_API_KEY
            if not api_key or api_key == "your-gemini-api-key":
                logger.info("GEMINI_API_KEY not configured — using heuristic fallback")
                return

            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                generation_config={
                    "temperature": 0.2,       # Low temperature for consistent analysis
                    "response_mime_type": "application/json",
                },
            )
            logger.info("Gemini AI initialized (gemini-1.5-flash)")
        except Exception as e:
            logger.warning(f"Failed to initialize Gemini: {e} — using heuristic fallback")

    async def analyze_vulnerability(self, title: str, description: str, severity: str) -> Dict[str, Any]:
        """
        Analyze a vulnerability.
        Uses Gemini if configured, falls back to heuristics otherwise.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        if self._model:
            try:
                result = await self._gemini_analyze(title, description, severity)
                result["ai_model"] = "gemini-1.5-flash"
                result["analysis_timestamp"] = timestamp
                return result
            except Exception as e:
                logger.error(f"Gemini analysis failed: {e} — falling back to heuristics")

        # Heuristic fallback
        result = self._heuristic_analyze(title, description, severity)
        result["analysis_timestamp"] = timestamp
        return result

    async def _gemini_analyze(self, title: str, description: str, severity: str) -> Dict[str, Any]:
        """Call Gemini API and parse the JSON response."""
        import asyncio
        prompt = _PROMPT.format(title=title, description=description, severity=severity)

        # Gemini SDK is sync — run in thread pool to keep FastAPI non-blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._model.generate_content(prompt)
        )

        text = response.text.strip()
        # Strip markdown code fences if model adds them despite mime type
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)

    def _heuristic_analyze(self, title: str, description: str, severity: str) -> Dict[str, Any]:
        """Rule-based fallback — deterministic, no random()."""
        title_lower = title.lower()

        # Classification
        type_map = [
            (["sql", "injection"],                    "SQL Injection (SQLi)",            0.97, "A03:2021 – Injection"),
            (["xss", "cross-site scripting"],         "Cross-Site Scripting (XSS)",      0.95, "A03:2021 – Injection"),
            (["csrf", "request forgery"],             "CSRF",                            0.92, "A01:2021 – Broken Access Control"),
            (["ssrf", "server-side request"],         "SSRF",                            0.91, "A10:2021 – SSRF"),
            (["buffer", "overflow"],                  "Buffer Overflow",                 0.90, "A06:2021 – Vulnerable Components"),
            (["path traversal", "directory traversal"], "Path Traversal",               0.90, "A01:2021 – Broken Access Control"),
            (["auth", "login", "session"],            "Broken Authentication",           0.88, "A07:2021 – Auth Failures"),
            (["xxe", "xml external"],                 "XXE Injection",                   0.93, "A03:2021 – Injection"),
            (["open redirect"],                       "Open Redirect",                   0.87, "A01:2021 – Broken Access Control"),
            (["sensitive", "exposure", "leak"],       "Sensitive Data Exposure",         0.85, "A02:2021 – Cryptographic Failures"),
        ]

        vuln_type, confidence, owasp = "Security Misconfiguration", 0.75, "A05:2021 – Security Misconfiguration"
        for keywords, vtype, conf, owasp_cat in type_map:
            if any(kw in title_lower for kw in keywords):
                vuln_type, confidence, owasp = vtype, conf, owasp_cat
                break

        # Deterministic risk score by severity
        score_map = {"critical": 95, "high": 78, "medium": 52, "low": 22, "info": 8}
        impact_map = {
            "critical": "Immediate system compromise likely. Full data exfiltration or RCE possible.",
            "high":     "Significant service disruption or unauthorized access to sensitive data.",
            "medium":   "Feature abuse or limited data exposure possible under specific conditions.",
            "low":      "Minimal direct impact, but expands the attack surface.",
            "info":     "Informational finding — no direct exploitability.",
        }
        exploit_map = {"critical": "Easy", "high": "Medium", "medium": "Medium", "low": "Hard", "info": "Hard"}

        sev = severity.lower()
        risk_score = score_map.get(sev, 40)
        impact = impact_map.get(sev, impact_map["medium"])
        exploitability = exploit_map.get(sev, "Medium")

        # Mitigation
        mitigations = {
            "SQL Injection":          "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Apply input validation and least-privilege DB accounts.",
            "Cross-Site Scripting":   "Implement Content Security Policy (CSP) and context-aware output encoding for all user-controlled data rendered in HTML/JS.",
            "CSRF":                   "Use synchronizer token pattern (CSRF tokens) or SameSite=Strict cookies on all state-changing endpoints.",
            "SSRF":                   "Validate and allowlist permitted outbound request destinations. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, etc.).",
            "Broken Authentication":  "Enforce MFA, use secure session management, rotate tokens on privilege change, implement account lockout.",
            "Path Traversal":         "Canonicalize file paths and validate they remain within the expected base directory before any file operation.",
        }
        mitigation = next(
            (v for k, v in mitigations.items() if k.lower() in vuln_type.lower()),
            "Apply vendor security patches, review configuration against CIS benchmarks, and conduct a targeted code review."
        )

        return {
            "ai_model": "SecureScan-Heuristic-v2 (no API key configured)",
            "classification": {
                "detected_type": vuln_type,
                "confidence_score": confidence,
                "owasp_category": owasp,
            },
            "risk_assessment": {
                "calculated_risk_score": risk_score,
                "predicted_impact": impact,
                "vector": "Network",
                "exploitability": exploitability,
            },
            "remediation": {
                "suggested_action": mitigation,
                "priority_level": "Immediate" if risk_score >= 80 else ("High" if risk_score >= 60 else "Scheduled"),
                "references": [f"https://owasp.org/Top10/#{owasp.split()[0].lower()}"],
            },
            "explanation": f"This finding is classified as {vuln_type} ({owasp}). The {sev}-severity rating indicates {impact.lower()}",
        }
