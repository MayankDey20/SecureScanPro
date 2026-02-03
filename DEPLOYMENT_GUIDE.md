# 🚀 Fly.io + Netlify Deployment Guide

## Prerequisites
- Fly.io account (free tier available)
- Netlify account (free tier available)
- Fly CLI installed: `brew install flyctl` (macOS)
- GitHub repository pushed

---

## PART 1: Backend on Fly.io

### Step 1: Install Fly CLI & Login
```bash
# Install Fly CLI (macOS)
brew install flyctl

# Login
fly auth login
```

### Step 2: Deploy Redis
```bash
# Create Redis instance (free tier)
fly redis create

# Save the Redis URL shown (format: redis://...)
# Example: redis://default:password@fly-securescan-redis.upstash.io:6379
```

### Step 3: Deploy API
```bash
cd backend

# Launch the app (will detect fly.toml)
fly launch --copy-config --yes

# Set environment variables
fly secrets set \
SUPABASE_URL=https://gdcooiiderywiekarpvt.supabase.co \
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdkY29vaWlkZXJ5d2lla2FycHZ0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzAwMjQxODgsImV4cCI6MjA4NTYwMDE4OH0.g_r0b0pNRFJ0bmdBgcPXLO1-o1J3M_31lDmjwgC3T2w \
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdkY29vaWlkZXJ5d2lla2FycHZ0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDAyNDE4OCwiZXhwIjoyMDg1NjAwMTg4fQ.g_JESMYaDfjQ3tfS415cSJBtbqaTY2CxhHMt_0TQkJc \
SUPABASE_JWT_SECRET=CfiZ7KWIXUFdVDpjjf1hIqQh+4M+LDJqFMGwo8q6XdrsoFIBO2oY7IVteDfKu2VCQOuK2dzSHCnu9pIjh8lkRA== \
SECRET_KEY=hello12345securekey67890examplekey \
REDIS_URL=redis://default:password@your-redis-url.upstash.io:6379 \
CELERY_BROKER_URL=redis://default:password@your-redis-url.upstash.io:6379 \
CELERY_RESULT_BACKEND=redis://default:password@your-redis-url.upstash.io:6379 \
ALGORITHM=HS256 \
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Deploy
fly deploy

# Get your API URL
fly status
# Example: https://securescan-api.fly.dev
```

### Step 4: Deploy Celery Worker (Optional)
```bash
# Create worker app with custom Dockerfile
fly launch --name securescan-worker --dockerfile Dockerfile.worker --no-deploy

# Set same secrets as API
fly secrets set -a securescan-worker \
SUPABASE_URL=... \
REDIS_URL=... \
CELERY_BROKER_URL=... \
CELERY_RESULT_BACKEND=...

# Deploy worker
fly deploy -a securescan-worker
```

### Step 5: Deploy Celery Beat (Optional)
```bash
# Create beat scheduler app
fly launch --name securescan-beat --dockerfile Dockerfile.beat --no-deploy

# Set same secrets
fly secrets set -a securescan-beat \
REDIS_URL=... \
CELERY_BROKER_URL=... \
CELERY_RESULT_BACKEND=...

# Deploy beat
fly deploy -a securescan-beat
```

---

## PART 2: Frontend on Netlify

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Add Fly.io and Netlify deployment configs"
git push
```

### Step 2: Deploy to Netlify
1. Go to [https://app.netlify.com/](https://app.netlify.com/)
2. Click **"Add new site"** → **"Import an existing project"**
3. Connect to GitHub → Select your `SecureScanPro` repository
4. Configure build settings:
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `frontend/dist`
5. Click **"Show advanced"** → **"Add environment variable"**:
   ```
   VITE_API_URL=https://securescan-api.fly.dev
   VITE_SUPABASE_URL=https://gdcooiiderywiekarpvt.supabase.co
   VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdkY29vaWlkZXJ5d2lla2FycHZ0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzAwMjQxODgsImV4cCI6MjA4NTYwMDE4OH0.g_r0b0pNRFJ0bmdBgcPXLO1-o1J3M_31lDmjwgC3T2w
   ```
6. Click **"Deploy site"**

### Step 3: Update CORS (Backend)
After deployment, add your Netlify URL to backend CORS:

```bash
# In backend/app/main.py, update CORS origins:
# origins = ["https://your-app.netlify.app"]

# Then redeploy backend
cd backend
fly deploy
```

---

## PART 3: Verify Deployment

### Test API
```bash
curl https://securescan-api.fly.dev/health
# Expected: {"status": "healthy"}
```

### Test Frontend
Visit your Netlify URL: `https://your-app.netlify.app`

### Monitor Logs
```bash
# API logs
fly logs -a securescan-api

# Worker logs
fly logs -a securescan-worker

# Beat logs
fly logs -a securescan-beat
```

---

## 🎯 Free Tier Limits

### Fly.io (Completely Free)
- **API**: 3 shared-cpu-1x VMs with 256MB RAM each
- **Worker/Beat**: Same as above
- **Redis**: Free via Upstash (25MB)
- **Bandwidth**: 160GB outbound/month

### Netlify (Completely Free)
- **Bandwidth**: 100GB/month
- **Build minutes**: 300 minutes/month
- **Sites**: Unlimited

---

## 🔧 Useful Commands

```bash
# Restart API
fly apps restart securescan-api

# Scale API
fly scale count 2 -a securescan-api

# SSH into container
fly ssh console -a securescan-api

# Check status
fly status -a securescan-api

# View secrets
fly secrets list -a securescan-api

# Update secret
fly secrets set SECRET_KEY=newsecret -a securescan-api
```

---

## ✅ Deployment Checklist

- [ ] Fly CLI installed
- [ ] Redis created on Fly/Upstash
- [ ] Backend deployed (API)
- [ ] Secrets configured
- [ ] Worker deployed (optional)
- [ ] Beat deployed (optional)
- [ ] Frontend deployed to Netlify
- [ ] CORS updated with Netlify URL
- [ ] Health check passing
- [ ] Frontend connecting to backend
- [ ] Supabase authentication working

---

## 🐛 Troubleshooting

### Backend won't start
```bash
fly logs -a securescan-api
# Check for missing env vars or Python errors
```

### Frontend can't reach backend
1. Check VITE_API_URL in Netlify env vars
2. Verify CORS origins in backend
3. Check backend health: `curl https://securescan-api.fly.dev/health`

### Database connection issues
1. Verify SUPABASE_URL and keys
2. Check Supabase project status
3. Test connection from local: `python -c "from app.core.supabase_client import supabase; print(supabase)"`

---

**🎉 Congratulations! Your app is deployed on production-grade infrastructure.**
