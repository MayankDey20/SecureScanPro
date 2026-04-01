# SecureScan Pro

A Comprehensive Web Security Scanning & Threat Intelligence Platform

Legal Notice: Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate local laws and terms of service.

## Project Overview

SecureScan Pro is an advanced, distributed web vulnerability scanner and threat intelligence platform. It provides organizations and security professionals with a unified dashboard to proactively discover, analyze, and remediate security flaws across their web infrastructure.

By combining active vulnerability scanning with machine learning-powered threat intelligence and real-time reporting, SecureScan Pro offers a holistic view of an asset's security posture.

## Interface & Features

### Interactive Dashboard
Visualizes security posture, historical trends, and high-risk vulnerabilities tracking over time.

(add image of main dashboard)

### Real-Time Scan Execution
Watch scans progress in real-time on the frontend via WebSocket streaming. A distributed task queue built on Celery and Redis handles concurrent, long-running heavy scans without blocking the application.

(add image of active scan progress)

### Comprehensive Vulnerability Scanning
Automated crawling and mapping of target surfaces using Multi-Vector Scan Modules:
- Vulnerability Scanner: Detects SQLi, XSS, SSRF, CSRF, Path Traversal, and more.
- SSL/TLS Scanner: Analyzes certificate validity, cipher strength, and protocol versions.
- Network & Port Scanner: Port discovery and service fingerprinting.
- Header & Auth Scanners: Validates security headers (CSP, HSTS, CORS) and checks authentication mechanisms.
- Nuclei Integration: Runs customizable, template-based vulnerability scans.

(add image of scan results and detailed findings)

### AI & Machine Learning Threat Intelligence
Evaluates scan results against machine learning models to predict exploitability and prioritize remediation. Includes an interactive AI-driven utility to diagnose and contextualize system behaviors or logs.

(add image of threat analysis and AI symptom checker)

### Automated Reporting
Export findings in professional PDF, JSON, or CSV formats customized for both technical and executive audiences.

(add image of generated PDF report)

### Enterprise-Grade Access Control
Secure authentication powered by Supabase Auth with Role-Based Access Control (RBAC) supporting multiple tenant roles (Owner, Admin, Auditor, Guest).

(add image of user profiles and role management)

## Technology Stack

- Frontend: React, Vite, Tailwind CSS
- Backend: FastAPI (Python), WebSockets
- Async Workers: Celery, Redis
- Database & Auth: Supabase (PostgreSQL)
- Security Engines: Custom Python scanners, Nuclei integration

## Local Development Setup

Follow these steps to initialize the application on your local machine for evaluation or usage.

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- Supabase account (for database and authentication configuration)

### 1. Environment Configuration
- In the `backend` directory, copy `.env.example` to `.env` and fill in your Supabase URL, Service Role Key, and Redis credentials.
- In the `frontend` directory, configure your `.env` to point to the local FastAPI instance and provide the Supabase public keys.

### 2. Start Infrastructure
Start the Redis container required for Celery task queuing using Docker Compose:
```bash
docker-compose up -d redis
```

### 3. Initialize Backend Services
Navigate to the `backend` directory, install the Python dependencies, and start the FastAPI server:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

In a separate terminal within the `backend` directory, activate the environment and start the Celery worker to process scans:
```bash
cd backend
source .venv/bin/activate
celery -A app.celery_worker.celery_app worker --loglevel=info
```

### 4. Start Frontend Interface
Navigate to the `frontend` directory, install node modules, and start the Vite development server:
```bash
cd frontend
npm install
npm run dev
```

The application interface will be accessible via the local address provided by the Vite server (typically `http://localhost:5173`).
