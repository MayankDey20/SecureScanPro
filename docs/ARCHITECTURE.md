# System Architecture

## Overview

SecureScan Pro employs a modern, distributed microservices architecture designed to scale efficiently while maintaining high performance. The system is divided into a frontend presentation layer, a backend API layer, an asynchronous task processing engine, and a persistence layer managed via Supabase.

## Architecture Architecture

    [ Client Browser ] (React + Vite + Tailwind CSS)
            |
            v
    [ FastAPI Backend ] (REST API & WebSockets)
            |
            +--> [ Supabase ] (PostgreSQL Database & Authentication)
            |
            v
    [ Redis Message Broker ]
            |
            v
    [ Celery Workers ]
            |
            +--> Scanner Modules (Nuclei, Network, Web Vulnerabilities, SSL)
            +--> Machine Learning & Threat Intelligence Analysis
            +--> Report Generation

## Component Details

### 1. Frontend Layer
- **Technologies:** React, Vite, Tailwind CSS.
- **Responsibilities:** Renders the user interface, maintains real-time WebSocket connections for scan progress updates, and visualizes complex scan data and analytics dashboard.

### 2. API Layer
- **Technologies:** FastAPI (Python).
- **Responsibilities:** Exposes RESTful endpoints for frontend consumption, manages user sessions via Supabase Auth, routes scan requests to the task queue, and serves real-time events through WebSockets.

### 3. Asynchronous Processing
- **Technologies:** Celery, Redis.
- **Responsibilities:** Manages long-running security scans. Redis acts as the message broker, distributing scan tasks across multiple background Celery workers to prevent API blocking.

### 4. Data Layer & Authentication
- **Technologies:** Supabase (PostgreSQL), Supabase Auth.
- **Responsibilities:** PostgeSQL handles all persistent storage including user profiles, scan histories, and vulnerabilities. Supabase Auth provides secure authentication and identity management.
