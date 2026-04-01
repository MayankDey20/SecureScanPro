# SecureScanPro

<p align="center">
  <strong>A Comprehensive Web Security Scanning & Threat Intelligence Platform</strong>
</p>

> **Legal Notice:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate local laws and terms of service.

---

## 📖 Project Overview

**SecureScanPro** is an advanced, distributed web vulnerability scanner and threat intelligence platform. It provides organizations and security professionals with a unified dashboard to proactively discover, analyze, and remediate security flaws across their web infrastructure. 

By combining active vulnerability scanning with machine learning-powered threat intelligence and real-time reporting, SecureScanPro offers a holistic view of an asset's security posture.

---

## ✨ Key Features

### 🛡️ Comprehensive Vulnerability Scanning
- **Dynamic Application Security Testing (DAST):** Automated crawling and mapping of target surfaces.
- **Multi-Vector Scan Modules:**
  - **Vulnerability Scanner:** Detects SQLi, XSS, SSRF, CSRF, Path Traversal, and more.
  - **SSL/TLS Scanner:** Analyzes certificate validity, cipher strength, and protocol versions.
  - **Network & Port Scanner:** Port discovery and service fingerprinting.
  - **Header & Auth Scanners:** Validates security headers (CSP, HSTS, CORS) and checks authentication mechanisms.
  - **Nuclei Integration:** Runs customizable, template-based vulnerability scans.
  - **Reconnaissance:** Uncovers tech stacks, CMS fingerprints, and directory structures.

### 🧠 AI & Machine Learning Threat Intelligence
- **ML Threat Scoring:** Evaluates scan results against machine learning models to predict exploitability and prioritize remediation.
- **Symptom Checker:** Interactive AI-driven utility to diagnose and contextualize bizarre system behaviors or logs.
- **Threat Feed Integration:** Cross-references findings with the latest CVEs and threat intelligence databases.

### ⚡ Real-Time Monitoring & Execution
- **WebSocket Streaming:** Watch scans progress in real-time on the frontend.
- **Distributed Task Queue:** Built on Celery and Redis to handle concurrent, long-running heavy scans without blocking the API.
- **Scheduled Scans:** Set up recurring security audits automatically.

### 📊 Analytics & Automated Reporting
- **Interactive Dashboard:** Visualizes security posture, historical trends, and high-risk vulnerabilities tracking over time.
- **Automated Report Generation:** Export findings in professional PDF, JSON, or CSV formats customized for both technical and executive audiences.
- **SLA Tracking:** Monitor time-to-remediate against organizational security policies.

### 🔒 Enterprise-Grade Access Control
- **Authentication:** Secure passwordless, OAuth, or email/password logins powered by Supabase Auth.
- **Role-Based Access Control (RBAC):** Granular permissions supporting multiple tenant roles (Owner, Admin, Auditor, Guest).

### 🔔 Smart Notifications
- Automated alerts sent via Email, Slack, Microsoft Teams, or custom Webhooks when new critical vulnerabilities are detected.

---

## 🛠️ Technology Stack

We engineered SecureScanPro using a modern, scalable, and modular stack:

### Frontend
- **Framework:** React 18 & Vite
- **Styling UI:** Custom CSS & Component Modules
- **State & Data:** Supabase JS Client, React Context API
- **Charts:** Chart.js for analytics visualization
- **Hosting:** Netlify / NGINX

### Backend & Core Services
- **Framework:** FastAPI (Python 3.11)
- **Concurrency:** Uvicorn & AsyncIO for high-performance API handling
- **WebSockets:** FastAPI WebSockets for real-time client-server communication
- **Task Brokers:** Celery + Redis for asynchronous, distributed task execution
- **Machine Learning:** Scikit-Learn / Custom Python ML pipelines
- **Hosting:** Railway (API & Celery Workers)

### Data Layer
- **Primary Database:** PostgreSQL (Hosted on Supabase)
- **Storage:** Supabase Storage (for Reports & Uploads)
- **Migrations:** Pure SQL migrations managed by custom setup scripts

### Infrastructure & DevOps
- **Containerization:** Docker & Docker Compose
- **Reverse Proxy:** Nginx
- **CI/CD:** Multi-environment deployment configs (`netlify.toml`, `railway.toml`)

---

## 🏗️ System Architecture

1. **Client (React):** Authenticates securely via Supabase Auth and talks to the FastAPI backend over REST (`/api/v1/`).
2. **API (FastAPI):** Validates requests, enforces RBAC, and writes scan configurations to the PostgreSQL database.
3. **Queue (Redis + Celery):** The backend dispatches heavy scanning tasks to Redis. 
4. **Workers (Python/Celery):** Background workers pick up tasks, execute rigorous network/web scanning modules (e.g., Nuclei, Nmap, custom HTTP spiders), and apply Machine Learning models to calculate threat intelligence scores.
5. **Real-Time Feed (WebSockets + Redis Pub/Sub):** Workers publish progress events back to Redis, which the FastAPI WebSocket manager broadcasts to the React client instantly.

---

## 🚀 Getting Started (Local Development)

**Prerequisites:** 
- Docker & Docker Compose
- A Supabase Project (for DB & Auth)

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/MayankDey20/SecureScanPro.git
   cd SecureScanPro
   ```

2. **Environment Configuration:**
   Copy the example environment file and fill in your Supabase credentials:
   ```bash
   cp .env.example .env
   # Add your SUPABASE_URL, SUPABASE_KEY, REDIS_URL, etc.
   ```

3. **Database Setup:**
   Run the Supabase migrations available in the `/migrations/` folder to set up your tables, row-level security (RLS), and RBAC schema.
   ```bash
   ./setup-supabase.sh
   ```

4. **Launch the Stack:**
   ```bash
   docker compose up --build -d
   ```

5. **Access the Application:**
   - **Frontend:** `http://localhost:3000`
   - **Backend API Docs (Swagger):** `http://localhost:8000/docs`

To view logs for background workers and services:
```bash
docker compose logs -f
```

---

## 📁 Repository Structure

```text
.
├── backend/                  # Python API and Celery Workers
│   ├── app/
│   │   ├── api/v1/           # REST endpoints (auth, scans, reports, ml, etc.)
│   │   ├── core/             # Configuration, RBAC, WebSocket manager
│   │   ├── models/           # DB schemas and Pydantic validators
│   │   ├── scanners/         # Core vulnerability scanning logic (Nuclei, SSL, Network, etc.)
│   │   ├── services/         # Business logic (AI tracking, PDF reports, Threat Intelligence)
│   │   └── tasks/            # Asynchronous Celery & scheduled tasks
│   ├── migrations/           # Supabase SQL schema definitions
│   └── ml_models/            # Serialized ML threat intelligence models
├── frontend/                 # React UI Application
│   ├── src/
│   │   ├── components/       # Pages (Dashboard, Scanner, Threat Intelligence, Analytics)
│   │   ├── contexts/         # React Context (AuthContext)
│   │   └── services/         # API hooks and Supabase configuration
├── docs/                     # Extended documentation (API, Architecture, Security)
└── docker-compose.yml        # Local orchestration
```

---

## 📖 Extended Documentation

- [System Architecture](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Notice](docs/SECURITY.md)
- [API Reference](docs/API.md)

---

## 📄 License & Terms

This project is licensed under the MIT License. 
By utilizing SecureScanPro, you agree to exclusively use the software for educational, research, and authorized security auditing purposes.
