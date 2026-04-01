# Deployment Guide

## Prerequisites

- Docker and Docker Compose
- Supabase account and project setup

## Local Development Setup

1. **Clone the repository**
   Clone the SecureScan Pro repository to your local machine.

2. **Configure Environment Variables**
   Copy the example environment files for both the frontend and backend.
   - In the `backend` directory, create a `.env` file based on `.env.example`. You will need to provide your Supabase URL, Supabase Service Role Key, and Redis connection strings.
   - In the `frontend` directory, configure your environment variables to point to the local FastAPI instance and provide Supabase public keys.

3. **Start the Infrastructure**
   The application relies on Redis for the Celery message queue. Spin up the necessary services using Docker Compose:
   `docker-compose up -d`

4. **Run the Backend API**
   Navigate to the `backend` directory, activate your Python virtual environment, install dependencies from `requirements.txt`, and start the FastAPI server:
   `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`

5. **Start the Celery Worker**
   In a separate terminal within the `backend` directory, start the Celery worker to process scans:
   `celery -A app.celery_worker.celery_app worker --loglevel=info`

6. **Run the Frontend Development Server**
   Navigate to the `frontend` directory, install node modules, and start the Vite development server:
   `npm install`
   `npm run dev`

## Production Deployment

For production environments, the application is containerized.
- The **Frontend** can be built into static files using `npm run build` and served via Nginx or a CDN.
- The **Backend** and **Celery Workers** are packaged via Dockerfiles out-of-the-box. Deploy these containers to any platform that supports Docker containers.
- **Database** and **Authentication** are managed by Supabase, reducing operational overhead. Ensure your Supabase instance is properly secured and scaled according to your load requirements.
