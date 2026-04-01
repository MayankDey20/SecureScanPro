import httpx
import uuid
import json
from datetime import datetime, timezone

URL = "https://gdcooiiderywiekarpvt.supabase.co"
KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdkY29vaWlkZXJ5d2lla2FycHZ0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDAyNDE4OCwiZXhwIjoyMDg1NjAwMTg4fQ.g_JESMYaDfjQ3tfS415cSJBtbqaTY2CxhHMt_0TQkJc"

headers = {
    "apikey": KEY,
    "Authorization": f"Bearer {KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

try:
    # Fetch first user to attribute the scan
    r = httpx.get(f"{URL}/rest/v1/profiles?select=id&limit=1", headers=headers)
    profiles = r.json()
    user_id = profiles[0]["id"] if profiles else None

    # Create dummy scan
    scan_id = str(uuid.uuid4())
    scan_data = {
        "id": scan_id,
        "target": "http://testphp.vulnweb.com",
        "url": "http://testphp.vulnweb.com",
        "status": "completed",
        "scan_type": "full",
        "score": 50,
        "findings_count": 5,
        "findings_summary": {"critical": 0, "high": 2, "medium": 2, "low": 1, "info": 0},
        "created_by": user_id,
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    r2 = httpx.post(f"{URL}/rest/v1/scans", headers=headers, json=scan_data)
    print("Created Scan:", r2.status_code)

    # Insert Dummy Vulns
    vulns = [
        {
            "id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "title": "SQL Injection (Blind)",
            "severity": "high",
            "vulnerability_type": "sql_injection",
            "description": "The application is vulnerable to time-based blind SQL injection via the 'id' parameter.",
            "location": "http://testphp.vulnweb.com/artists.php?artist=1",
            "evidence": "Delay of 5 seconds observed when passing SLEEP(5).",
            "remediation": "Use parameterized queries or prepared statements.",
            "status": "open"
        },
        {
            "id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "title": "Cross-Site Scripting (Reflected)",
            "severity": "high",
            "vulnerability_type": "xss",
            "description": "Reflected XSS found in search field.",
            "location": "http://testphp.vulnweb.com/search.php?test=query",
            "evidence": "<script>alert(1)</script> reflected in response.",
            "remediation": "HTML encode all user input before reflecting it.",
            "status": "open"
        },
        {
            "id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "title": "Directory Traversal",
            "severity": "medium",
            "vulnerability_type": "path_traversal",
            "description": "Possible to read local files via the file parameter.",
            "location": "http://testphp.vulnweb.com/showimage.php?file=../../../etc/passwd",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
            "remediation": "Validate and whitelist file names.",
            "status": "open"
        },
        {
            "id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "title": "Missing CSRF Token",
            "severity": "medium",
            "vulnerability_type": "csrf",
            "description": "No Cross-Site Request Forgery protection found on form submission.",
            "location": "http://testphp.vulnweb.com/login.php",
            "evidence": "No anti-CSRF token in HTTP request.",
            "remediation": "Implement synchronizer token pattern.",
            "status": "open"
        },
        {
            "id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "title": "Server Information Leak",
            "severity": "low",
            "vulnerability_type": "info_disclosure",
            "description": "Server version disclosed in HTTP headers.",
            "location": "http://testphp.vulnweb.com",
            "evidence": "Server: nginx/1.19.0",
            "remediation": "Configure web server to not disclose version.",
            "status": "open"
        }
    ]
    
    r3 = httpx.post(f"{URL}/rest/v1/vulnerabilities", headers=headers, json=vulns)
    print("Created Vulnerabilities:", r3.status_code)

except Exception as e:
    print("Error:", e)
