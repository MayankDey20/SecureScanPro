# SecureScan Pro

A web-based security scanner built to detect vulnerabilities, misconfigurations, and compliance issues in web applications. It runs active scans against a target URL, shows live progress over WebSocket, and generates structured reports.

> **Legal notice:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate local laws.

---

## What it does

- Crawls the target and discovers pages, forms, and input surfaces
- Runs configurable scan modules (SQLi, XSS, SSL/TLS, headers, ports, recon, etc.)
- Streams live progress to the browser via WebSocket with Redis pub/sub backing
- Saves findings to Supabase (PostgreSQL) and scores the target's security posture
- Generates PDF, JSON, and CSV reports
- Supports scheduled recurring scans via Celery Beat
- RBAC with six roles (Owner → Guest) and 40+ granular permissions
- Notifications over Email, Slack, Teams, or webhooks

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Chart.js |
| Backend | FastAPI (Python 3.11) |
| Task queue | Celery + Redis |
| Database | Supabase (PostgreSQL) |
| Auth | Supabase JWT |
| Reverse proxy | Nginx |
| Containerisation | Docker Compose |

---

### 🎨 Advanced Frontend (React + Vite)
- ✅ **Interactive Dashboard**
## Getting started

**Prerequisites:** Docker and Docker Compose

```bash
git clone https://github.com/MayankDey20/SecureScanPro.git
cd SecureScanPro

cp .env.example .env
# Fill in your Supabase URL, anon key, and service role key

docker compose up --build -d
```

The app will be available at `http://localhost:3000`.

To watch logs from all services:

```bash
docker compose logs -f
```

To stop everything:

```bash
docker compose down
```

---

## Project structure

```
.
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Route handlers
│   │   ├── core/            # Config, auth, RBAC, WebSocket manager
│   │   ├── models/          # Pydantic models
│   │   ├── scanners/        # Individual scan modules
│   │   ├── services/        # Business logic, report generation
│   │   └── tasks/           # Celery tasks
│   └── migrations/          # SQL migration files
├── frontend/
│   └── src/
│       ├── components/      # React components by feature
│       ├── contexts/        # Auth context
│       └── services/        # API client
├── docs/                    # Architecture, API, deployment guides
└── docker-compose.yml
```

---

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan/` | Start a new scan |
| `GET` | `/api/v1/scan/{id}/status` | Poll scan status and progress |
| `WS` | `/api/v1/scan/{id}/live` | Live progress stream |
| `GET` | `/api/v1/scan/{id}/results` | Fetch completed scan results |
| `POST` | `/api/v1/reports/generate` | Generate PDF/JSON/CSV report |
| `GET` | `/api/v1/analytics/trends` | Historical scan analytics |
| `GET` | `/api/v1/threats/` | Threat intelligence feed |

Full reference: [docs/API.md](docs/API.md)

---

## Scan modules

| Module | Checks |
|---|---|
| `vuln` | SQLi (error-based, blind), XSS (reflected), CSRF, path traversal, SSTI |
| `ssl` | Certificate validity, cipher suites, protocol versions, OCSP |
| `headers` | CSP, HSTS, X-Frame-Options, CORS, 20+ headers |
| `network` | Port scanning via Nmap, service/version detection |
| `recon` | Tech fingerprinting, CMS detection, DNS, WHOIS |
| `full` | All of the above |

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Security](docs/SECURITY.md)

---

## License

MIT
