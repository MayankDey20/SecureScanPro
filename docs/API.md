# SecureScan Pro - API Documentation

## Overview

SecureScan Pro provides a comprehensive RESTful API for website security scanning, vulnerability detection, and compliance checking. All API endpoints are versioned and return JSON responses.

**Base URL:** `https://api.securescan.pro/api/v1`

**API Version:** 1.0.0

## Authentication

All API requests require authentication using JWT tokens or API keys.

### JWT Authentication

```http
Authorization: Bearer <jwt_token>
```

### API Key Authentication

```http
X-API-Key: <your_api_key>
```

## Rate Limiting

- **Standard Plan:** 60 requests/minute, 1000 requests/hour
- **Pro Plan:** 120 requests/minute, 5000 requests/hour
- **Enterprise:** Custom limits

Rate limit headers:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1699564800
```

## Response Format

### Success Response
```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2024-11-08T12:00:00Z"
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": { ... }
  },
  "timestamp": "2024-11-08T12:00:00Z"
}
```

## Endpoints

### Scan Operations

#### Start New Scan

```http
POST /scan/start
```

**Request Body:**
```json
{
  "targetUrl": "https://example.com",
  "scanType": "full",
  "scanDepth": "medium",
  "options": {
    "portRange": "80,443,8080-8090",
    "userAgent": "SecureScan-Pro/1.0",
    "authentication": {
      "type": "basic",
      "username": "user",
      "password": "pass"
    },
    "proxy": {
      "url": "http://proxy:8080"
    },
    "customHeaders": {
      "X-Custom-Header": "value"
    },
    "modules": [
      "ssl_analysis",
      "security_headers",
      "vulnerability_detection",
      "reconnaissance"
    ]
  },
  "schedule": {
    "frequency": "daily",
    "startTime": "2024-11-09T02:00:00Z"
  },
  "notifications": {
    "webhook": "https://your-webhook.com/endpoint",
    "email": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "scan_1a2b3c4d",
    "status": "queued",
    "estimatedTime": "15 minutes",
    "queuePosition": 3
  }
}
```

#### Get Scan Status

```http
GET /scan/{scanId}/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "scan_1a2b3c4d",
    "status": "running",
    "progress": 45,
    "currentPhase": "Vulnerability Detection",
    "startedAt": "2024-11-08T12:00:00Z",
    "estimatedCompletion": "2024-11-08T12:15:00Z"
  }
}
```

#### Get Scan Results

```http
GET /scan/{scanId}/results
```

**Query Parameters:**
- `include` (optional): Comma-separated list of sections to include
  - Options: `summary`, `vulnerabilities`, `network`, `compliance`, `recommendations`
  - Default: All sections

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "scan_1a2b3c4d",
    "targetUrl": "https://example.com",
    "status": "completed",
    "completedAt": "2024-11-08T12:15:23Z",
    "duration": 923,
    "securityScore": 74,
    "summary": {
      "totalVulnerabilities": 27,
      "critical": 2,
      "high": 5,
      "medium": 8,
      "low": 12
    },
    "vulnerabilities": [
      {
        "id": "vuln_xyz123",
        "severity": "high",
        "type": "XSS",
        "title": "Cross-Site Scripting Vulnerability",
        "description": "User input not properly sanitized in search parameter",
        "location": "/api/search?q=<input>",
        "cve": "N/A",
        "cvss": 7.5,
        "attackVector": "Network",
        "proofOfConcept": "GET /api/search?q=<script>alert('XSS')</script>",
        "recommendation": "Implement proper input validation and output encoding",
        "references": [
          "https://owasp.org/www-community/attacks/xss/"
        ]
      }
    ],
    "network": {
      "openPorts": [
        {
          "port": 80,
          "service": "HTTP",
          "version": "nginx/1.21.0",
          "status": "open"
        },
        {
          "port": 443,
          "service": "HTTPS",
          "version": "nginx/1.21.0",
          "status": "open"
        }
      ],
      "ssl": {
        "protocol": "TLS 1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "certificateValid": true,
        "expiryDate": "2025-02-06",
        "issuer": "Let's Encrypt"
      }
    },
    "compliance": {
      "owaspTop10": {
        "score": "7/10",
        "findings": [
          {
            "category": "A03:2021 – Injection",
            "status": "failed",
            "details": "SQL injection vulnerability detected"
          }
        ]
      },
      "pciDss": {
        "compliant": false,
        "failedRequirements": ["6.5.1", "6.5.7"]
      },
      "gdpr": {
        "status": "partial",
        "findings": []
      }
    },
    "recommendations": [
      {
        "priority": "critical",
        "category": "Injection",
        "title": "Fix SQL Injection Vulnerabilities",
        "description": "Use parameterized queries or ORM",
        "impact": "Database compromise, data breach",
        "effort": "medium",
        "codeExample": "// Use parameterized queries\nconst result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);"
      }
    ]
  }
}
```

#### Start Batch Scan

```http
POST /scan/batch
```

**Request Body:**
```json
{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com"
  ],
  "scanDepth": "shallow",
  "concurrent": 3,
  "options": { ... }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "batchId": "batch_abc123",
    "totalScans": 3,
    "scanIds": [
      "scan_1a2b3c4d",
      "scan_2b3c4d5e",
      "scan_3c4d5e6f"
    ],
    "status": "queued"
  }
}
```

#### Compare Scans

```http
POST /scan/compare
```

**Request Body:**
```json
{
  "scan1": "scan_1a2b3c4d",
  "scan2": "scan_2b3c4d5e"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "comparison": {
      "scoreDiff": 12,
      "vulnerabilities": {
        "new": 3,
        "fixed": 8,
        "unchanged": 15
      },
      "details": [
        {
          "type": "fixed",
          "vulnerability": "SQL Injection in /api/login"
        }
      ]
    }
  }
}
```

### Analytics Operations

#### Get Trends

```http
GET /analytics/trends
```

**Query Parameters:**
- `period`: `7d`, `30d`, `90d`, `365d` (default: `30d`)
- `metric`: `security_score`, `vulnerabilities`, `scans` (default: all)

**Response:**
```json
{
  "success": true,
  "data": {
    "period": "30d",
    "securityScores": [65, 68, 72, 70, 75, 78, 74],
    "vulnerabilityCounts": {
      "critical": [3, 2, 2, 1, 2, 2, 2],
      "high": [8, 7, 6, 5, 6, 5, 5],
      "medium": [12, 11, 10, 9, 10, 9, 8],
      "low": [20, 19, 18, 17, 18, 17, 12]
    },
    "scanCounts": [5, 7, 4, 6, 8, 5, 6],
    "dates": ["2024-10-09", "2024-10-16", "..."]
  }
}
```

### Reports Operations

#### Generate Report

```http
POST /reports/generate
```

**Request Body:**
```json
{
  "scanId": "scan_1a2b3c4d",
  "type": "executive",
  "format": "pdf",
  "options": {
    "includeCharts": true,
    "includePOC": false,
    "includeRemediation": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "reportId": "report_xyz789",
    "status": "generating",
    "estimatedTime": "30 seconds"
  }
}
```

#### Get Report

```http
GET /reports/{reportId}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "reportId": "report_xyz789",
    "scanId": "scan_1a2b3c4d",
    "status": "ready",
    "format": "pdf",
    "size": 2048576,
    "downloadUrl": "/reports/report_xyz789/download",
    "generatedAt": "2024-11-08T12:20:00Z"
  }
}
```

#### Download Report

```http
GET /reports/{reportId}/download
```

**Query Parameters:**
- `format`: `pdf`, `json`, `csv`, `xml` (optional if specified during generation)

**Response:** Binary file download

### Webhooks Operations

#### Configure Webhook

```http
POST /webhooks/configure
```

**Request Body:**
```json
{
  "url": "https://your-webhook.com/endpoint",
  "events": ["scan.completed", "scan.failed", "vulnerability.critical"],
  "secret": "your_webhook_secret",
  "active": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "webhookId": "webhook_abc123",
    "url": "https://your-webhook.com/endpoint",
    "status": "active"
  }
}
```

#### Test Webhook

```http
POST /webhooks/{webhookId}/test
```

**Response:**
```json
{
  "success": true,
  "data": {
    "tested": true,
    "responseCode": 200,
    "responseTime": 142
  }
}
```

### Vulnerability Database

#### Query CVE

```http
GET /vulnerabilities/database
```

**Query Parameters:**
- `cve`: CVE identifier (e.g., `CVE-2024-1234`)
- `search`: Search query
- `severity`: `critical`, `high`, `medium`, `low`

**Response:**
```json
{
  "success": true,
  "data": {
    "cve": "CVE-2024-1234",
    "severity": "high",
    "cvss": 7.5,
    "description": "...",
    "published": "2024-01-15",
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    ],
    "affectedProducts": [
      "Product X version 1.0 to 2.5"
    ]
  }
}
```

## WebSocket API

### Live Scan Feed

```javascript
const ws = new WebSocket('wss://api.securescan.pro/api/v1/scan/{scanId}/live');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Scan update:', data);
};
```

**Message Format:**
```json
{
  "scanId": "scan_1a2b3c4d",
  "timestamp": "2024-11-08T12:05:23Z",
  "type": "progress",
  "data": {
    "progress": 45,
    "phase": "Vulnerability Detection",
    "message": "Checking for XSS vulnerabilities..."
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Invalid request parameters |
| `AUTHENTICATION_REQUIRED` | Missing or invalid authentication |
| `RATE_LIMIT_EXCEEDED` | Too many requests |
| `RESOURCE_NOT_FOUND` | Requested resource not found |
| `SCAN_FAILED` | Scan execution failed |
| `INSUFFICIENT_CREDITS` | Not enough API credits |
| `INTERNAL_ERROR` | Internal server error |

## Best Practices

1. **Use webhooks** for long-running scans instead of polling
2. **Implement exponential backoff** for retries
3. **Cache results** when appropriate
4. **Use batch operations** for multiple scans
5. **Set appropriate timeouts** (recommended: 30s)
6. **Handle rate limits** gracefully

## Code Examples

### Python

```python
import requests

API_KEY = "your_api_key"
BASE_URL = "https://api.securescan.pro/api/v1"

headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

# Start scan
response = requests.post(
    f"{BASE_URL}/scan/start",
    json={
        "targetUrl": "https://example.com",
        "scanType": "full"
    },
    headers=headers
)

scan_id = response.json()["data"]["scanId"]
print(f"Scan started: {scan_id}")
```

### JavaScript

```javascript
const API_KEY = 'your_api_key';
const BASE_URL = 'https://api.securescan.pro/api/v1';

async function startScan(url) {
  const response = await fetch(`${BASE_URL}/scan/start`, {
    method: 'POST',
    headers: {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetUrl: url,
      scanType: 'full'
    })
  });
  
  const data = await response.json();
  return data.data.scanId;
}
```

## Support

- **Documentation:** https://docs.securescan.pro
- **API Status:** https://status.securescan.pro
- **Support:** support@securescan.pro
