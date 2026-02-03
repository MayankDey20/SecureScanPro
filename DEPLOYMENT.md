# SecureScan Pro - Deployment Guide

## Architecture Overview

This application requires:
- **Frontend**: Static React app (can be deployed to Netlify)
- **Backend**: FastAPI with Celery workers (needs container hosting)
- **Database**: Supabase (PostgreSQL)
- **Cache/Queue**: Redis
- **Background Jobs**: Celery workers + Beat scheduler

---

## Option 1: Netlify (Frontend) + Railway (Backend)

### Step 1: Deploy Backend to Railway

1. **Sign up at [Railway.app](https://railway.app)**

2. **Create a new project**
   - Click "New Project" → "Deploy from GitHub repo"
   - Connect your GitHub account and select this repository

3. **Add services** (create 4 separate services):

   **Service 1: API**
   ```
   Name: api
   Root Directory: backend
   Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```

   **Service 2: Worker**
   ```
   Name: worker
   Root Directory: backend
   Start Command: celery -A app.celery_worker worker --loglevel=info
   ```

   **Service 3: Beat Scheduler**
   ```
   Name: beat
   Root Directory: backend
   Start Command: celery -A app.celery_worker beat --loglevel=info
   ```

   **Service 4: Redis**
   ```
   Click "New" → "Database" → "Add Redis"
   ```

4. **Configure environment variables** for API, Worker, and Beat services:
   ```
   SUPABASE_URL=your-supabase-url
   SUPABASE_ANON_KEY=your-supabase-anon-key
   SUPABASE_SERVICE_KEY=your-supabase-service-key
   SECRET_KEY=generate-a-secure-random-key
   REDIS_URL=${{Redis.REDIS_URL}}
   CELERY_BROKER_URL=${{Redis.REDIS_URL}}/1
   CELERY_RESULT_BACKEND=${{Redis.REDIS_URL}}/2
   DEBUG=False
   CORS_ORIGINS=["https://your-netlify-site.netlify.app"]
   ```

5. **Deploy** - Railway will automatically deploy all services

6. **Get your API URL** - Copy the public URL from the API service (e.g., `https://api-production-xxxx.railway.app`)

### Step 2: Deploy Frontend to Netlify

1. **Sign up at [Netlify](https://netlify.com)**

2. **Connect repository**
   - Click "Add new site" → "Import an existing project"
   - Connect GitHub and select this repository

3. **Configure build settings**:
   ```
   Base directory: frontend
   Build command: npm run build
   Publish directory: frontend/dist
   ```

4. **Add environment variables** in Netlify dashboard:
   ```
   VITE_API_URL=https://your-railway-api-url.railway.app/api/v1
   VITE_SUPABASE_URL=your-supabase-url
   VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
   ```

5. **Deploy** - Netlify will build and deploy your frontend

6. **Update netlify.toml** - Edit line 10 with your Railway backend URL

---

## Option 2: All-in-One Container Platform

Deploy everything together on platforms that support Docker Compose:

### Render.com
1. Create account at [Render.com](https://render.com)
2. Click "New" → "Blueprint"
3. Connect repository
4. Render will detect your `docker-compose.yml`
5. Add environment variables
6. Deploy

### DigitalOcean App Platform
1. Create account at [DigitalOcean](https://digitalocean.com)
2. Go to App Platform
3. Create new app from GitHub
4. Select "Docker Compose"
5. Configure domains and environment variables
6. Deploy

### Fly.io
1. Install Fly CLI: `brew install flyctl`
2. Login: `fly auth login`
3. Create app: `fly launch`
4. Deploy: `fly deploy`

---

## Option 3: Self-Hosted (VPS)

Deploy to any VPS (DigitalOcean, AWS EC2, Linode, etc.):

1. **Provision a server** (minimum 2GB RAM)

2. **Install Docker**:
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   ```

3. **Clone repository**:
   ```bash
   git clone your-repo-url
   cd securescan-pro
   ```

4. **Configure environment**:
   ```bash
   cp backend/.env.example backend/.env
   nano backend/.env  # Add your credentials
   ```

5. **Deploy with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

6. **Setup Nginx reverse proxy** (for SSL):
   ```bash
   apt install nginx certbot python3-certbot-nginx
   certbot --nginx -d yourdomain.com
   ```

---

## Required External Services

### Supabase (Database)
- Already configured ✅
- No additional setup needed
- Free tier available

### Optional: External Threat Intelligence APIs

Add these to `backend/.env` for enhanced scanning:

```bash
# NVD (National Vulnerability Database) - Free
NVD_API_KEY=get-from-nvd.nist.gov

# Shodan - Paid
SHODAN_API_KEY=get-from-shodan.io

# AbuseIPDB - Free tier available
ABUSEIPDB_API_KEY=get-from-abuseipdb.com

# VirusTotal - Free tier available
VIRUSTOTAL_API_KEY=get-from-virustotal.com
```

---

## Post-Deployment Checklist

- [ ] Backend API is accessible and returning 200 on `/health`
- [ ] Frontend loads and can connect to backend
- [ ] User registration works
- [ ] Scans can be started and complete successfully
- [ ] Celery workers are processing tasks
- [ ] Redis is connected
- [ ] Supabase tables have proper RLS policies
- [ ] SSL certificates are installed (for production)
- [ ] Environment variables are set correctly
- [ ] CORS is configured for your frontend domain

---

## Monitoring

### Railway
- Built-in logs and metrics
- View at: Project → Service → Metrics

### Netlify
- Analytics dashboard
- Build logs
- Function logs

### Flower (Celery Monitoring)
- Accessible at: `https://your-backend-url/flower`
- Monitor task execution and workers

---

## Scaling Considerations

1. **Database**: Upgrade Supabase plan as needed
2. **Workers**: Increase Celery worker count for concurrent scans
3. **Cache**: Upgrade Redis for larger datasets
4. **API**: Enable horizontal scaling on Railway/Render

---

## Troubleshooting

### Backend not connecting to Supabase
- Check environment variables are set
- Verify Supabase URL format: `https://xxx.supabase.co`
- Confirm service key has proper permissions

### Frontend can't reach API
- Check CORS settings in backend
- Verify API URL in frontend env vars
- Ensure API is publicly accessible

### Scans not running
- Check Celery worker logs
- Verify Redis connection
- Ensure background tasks are enabled

### Database errors
- Run migrations: See `backend/migrations/002_update_existing_schema.sql`
- Check RLS policies are set up correctly
- Verify service role has permissions

---

## Need Help?

1. Check logs: `docker-compose logs -f [service-name]`
2. Test API: `curl https://your-api-url/health`
3. Check Supabase: Dashboard → Database → Tables
4. Monitor tasks: Access Flower dashboard

For platform-specific issues:
- Railway: https://railway.app/help
- Netlify: https://docs.netlify.com
- Render: https://render.com/docs
