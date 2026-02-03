# SecureScan Pro - Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Docker Deployment](#docker-deployment)
4. [Production Deployment](#production-deployment)
5. [Cloud Deployment](#cloud-deployment)
6. [Configuration](#configuration)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB SSD
- OS: Ubuntu 20.04+ / CentOS 8+ / macOS 10.15+

**Recommended:**
- CPU: 8+ cores
- RAM: 16+ GB
- Disk: 100+ GB SSD
- OS: Ubuntu 22.04 LTS

### Software Requirements

- Docker 20.10+
- Docker Compose 2.0+
- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Nginx 1.21+

## Local Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-org/securescan-pro.git
cd securescan-pro
```

### 2. Setup Frontend

```bash
# Install a local web server (optional)
npm install -g http-server

# Serve frontend
cd frontend
http-server -p 8080

# Or use Python
python -m http.server 8080
```

Access frontend at: `http://localhost:8080`

### 3. Setup Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Run migrations (when implemented)
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Access API at: `http://localhost:8000`
API Docs at: `http://localhost:8000/api/docs`

### 4. Setup Database

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE securescan;
CREATE USER securescan WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE securescan TO securescan;
\q

# Install Redis
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```

## Docker Deployment

### Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/securescan-pro.git
cd securescan-pro

# Create environment file
cp backend/.env.example backend/.env

# Edit configuration
nano backend/.env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

Access application:
- Frontend: `http://localhost`
- API: `http://localhost/api`
- API Docs: `http://localhost/api/docs`
- Flower (Celery Monitor): `http://localhost:5555`

### Service Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# Scale workers
docker-compose up -d --scale worker=5

# View service logs
docker-compose logs -f api
docker-compose logs -f worker

# Execute command in container
docker-compose exec api bash
docker-compose exec postgres psql -U securescan
```

### Database Management

```bash
# Backup database
docker-compose exec postgres pg_dump -U securescan securescan > backup.sql

# Restore database
docker-compose exec -T postgres psql -U securescan securescan < backup.sql

# Access database
docker-compose exec postgres psql -U securescan securescan
```

## Production Deployment

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install required tools
sudo apt install -y git nginx certbot python3-certbot-nginx
```

### 2. SSL Certificate Setup

```bash
# Obtain SSL certificate
sudo certbot --nginx -d securescan.pro -d api.securescan.pro

# Auto-renewal
sudo systemctl enable certbot.timer
```

### 3. Production Configuration

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/your-org/securescan-pro.git
cd securescan-pro

# Create production environment
sudo cp backend/.env.example backend/.env
sudo nano backend/.env
```

**Production .env:**
```bash
ENV=production
DEBUG=False
SECRET_KEY=<generate-strong-secret>

DATABASE_URL=postgresql://securescan:secure_password@postgres:5432/securescan
REDIS_URL=redis://:redis_password@redis:6379/0

# Security
CORS_ORIGINS=https://securescan.pro
JWT_SECRET_KEY=<generate-strong-secret>

# Performance
API_WORKERS=8
MAX_CONCURRENT_SCANS=50

# Monitoring
SENTRY_DSN=your_sentry_dsn
```

### 4. Start Production Services

```bash
# Start services
sudo docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify services
sudo docker-compose ps

# Check logs
sudo docker-compose logs -f
```

### 5. Nginx Configuration

```nginx
# /etc/nginx/sites-available/securescan.pro

upstream api_backend {
    least_conn;
    server localhost:8000;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name securescan.pro api.securescan.pro;
    return 301 https://$server_name$request_uri;
}

# Frontend
server {
    listen 443 ssl http2;
    server_name securescan.pro;

    ssl_certificate /etc/letsencrypt/live/securescan.pro/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/securescan.pro/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    root /opt/securescan-pro/frontend;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location /api/ {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # WebSocket
    location /api/v1/scan/ {
        proxy_pass http://api_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
    
    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}

# API subdomain
server {
    listen 443 ssl http2;
    server_name api.securescan.pro;

    ssl_certificate /etc/letsencrypt/live/securescan.pro/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/securescan.pro/privkey.pem;
    
    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/securescan.pro /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Cloud Deployment

### AWS Deployment

#### 1. EC2 Setup

```bash
# Launch EC2 instance
aws ec2 run-instances \
    --image-id ami-0c55b159cbfafe1f0 \
    --instance-type t3.xlarge \
    --key-name your-key \
    --security-group-ids sg-xxxxx \
    --subnet-id subnet-xxxxx \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=SecureScan-API}]'

# Connect to instance
ssh -i your-key.pem ubuntu@<instance-ip>
```

#### 2. RDS Database

```bash
# Create RDS PostgreSQL instance
aws rds create-db-instance \
    --db-instance-identifier securescan-db \
    --db-instance-class db.t3.medium \
    --engine postgres \
    --engine-version 15.3 \
    --master-username securescan \
    --master-user-password <strong-password> \
    --allocated-storage 100 \
    --backup-retention-period 7 \
    --multi-az
```

#### 3. ElastiCache Redis

```bash
# Create Redis cluster
aws elasticache create-cache-cluster \
    --cache-cluster-id securescan-redis \
    --cache-node-type cache.t3.medium \
    --engine redis \
    --num-cache-nodes 1
```

#### 4. S3 Bucket

```bash
# Create S3 bucket for reports
aws s3 mb s3://securescan-reports-prod

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket securescan-reports-prod \
    --versioning-configuration Status=Enabled
```

### Google Cloud Platform

```bash
# Create GKE cluster
gcloud container clusters create securescan-cluster \
    --zone us-central1-a \
    --num-nodes 3 \
    --machine-type n1-standard-4

# Deploy application
kubectl apply -f k8s/
```

### Digital Ocean

```bash
# Create Droplet
doctl compute droplet create securescan-api \
    --image ubuntu-22-04-x64 \
    --size s-4vcpu-8gb \
    --region nyc1

# Create managed database
doctl databases create securescan-db \
    --engine pg \
    --version 15 \
    --size db-s-2vcpu-4gb \
    --region nyc1
```

## Configuration

### Environment Variables

**Critical Variables:**
```bash
# Security
SECRET_KEY=<generate-with: openssl rand -hex 32>
JWT_SECRET_KEY=<generate-with: openssl rand -hex 32>

# Database
DATABASE_URL=postgresql://user:pass@host:5432/db

# Redis
REDIS_URL=redis://:password@host:6379/0
```

### Performance Tuning

**API Workers:**
```python
# Calculate workers: (2 x CPU cores) + 1
API_WORKERS = (2 * os.cpu_count()) + 1
```

**Database Connection Pool:**
```python
SQLALCHEMY_POOL_SIZE = 20
SQLALCHEMY_MAX_OVERFLOW = 10
SQLALCHEMY_POOL_TIMEOUT = 30
```

**Celery Workers:**
```bash
# High-priority scans
celery -A app.celery_worker worker -Q priority --concurrency=8

# Normal scans
celery -A app.celery_worker worker -Q scans --concurrency=16

# Reports
celery -A app.celery_worker worker -Q reports --concurrency=4
```

## Monitoring

### Prometheus Setup

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'api'
    static_configs:
      - targets: ['localhost:8000']
  
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']
  
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']
```

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Database health
docker-compose exec postgres pg_isready

# Redis health
docker-compose exec redis redis-cli ping
```

### Log Management

```bash
# Centralized logging with ELK Stack
docker-compose -f docker-compose.yml -f docker-compose.elk.yml up -d

# View aggregated logs
# Kibana: http://localhost:5601
```

## Troubleshooting

### Common Issues

**1. Database Connection Failed**
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready -U securescan

# Check connection string
echo $DATABASE_URL

# Test connection
docker-compose exec api python -c "from app.core.database import engine; print(engine.connect())"
```

**2. Redis Connection Failed**
```bash
# Check Redis status
docker-compose exec redis redis-cli ping

# Test connection
docker-compose exec redis redis-cli -a <password> ping
```

**3. High Memory Usage**
```bash
# Check container stats
docker stats

# Limit container memory
docker-compose up -d --scale worker=2 --memory="2g"
```

**4. Slow Scan Performance**
```bash
# Increase worker count
docker-compose up -d --scale worker=10

# Check queue size
docker-compose exec redis redis-cli LLEN celery

# Monitor Celery
# Flower: http://localhost:5555
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
export DEBUG_SQL=True

# Restart with debug
docker-compose restart api
docker-compose logs -f api
```

### Backup & Recovery

```bash
# Full backup
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh backup-2024-11-08.tar.gz

# Database only
docker-compose exec postgres pg_dump -U securescan securescan | gzip > backup.sql.gz
```

## Maintenance

### Updates

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build

# Apply migrations
docker-compose exec api alembic upgrade head

# Restart services
docker-compose up -d
```

### Security Updates

```bash
# Update base images
docker-compose pull

# Update dependencies
docker-compose exec api pip install -r requirements.txt --upgrade

# Restart
docker-compose restart
```

---

**For Support:**
- Documentation: https://docs.securescan.pro
- Email: support@securescan.pro
- Slack: securescan-community.slack.com
