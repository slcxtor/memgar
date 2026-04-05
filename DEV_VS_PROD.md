# Development vs Production - Configuration Guide
# =================================================

This document outlines the differences between development and production configurations.

## Quick Reference

| Feature | Development | Production |
|---------|-------------|------------|
| **Environment** | `development` | `production` |
| **Debug Mode** | `true` | `false` |
| **Database** | SQLite / Local PostgreSQL | PostgreSQL with replicas |
| **Redis** | Local, no password | Secured with password |
| **HTTPS** | HTTP only | HTTPS with Let's Encrypt |
| **CORS** | `*` (all origins) | Specific domains only |
| **Logging** | Console, verbose | Structured JSON, INFO level |
| **Error Pages** | Detailed stack traces | Generic error messages |
| **Session Duration** | Long (days) | Short (30 minutes) |
| **Rate Limiting** | Disabled / Lenient | Strict (60 req/min) |
| **Workers** | 1-2 | 4-8+ (autoscale) |
| **Monitoring** | Optional | Required (Prometheus, Sentry) |

## Docker Compose Differences

### Development (docker-compose.yml)

```yaml
services:
  backend:
    build: ./backend
    environment:
      - DEBUG=true
      - LOG_LEVEL=DEBUG
    volumes:
      - ./backend/app:/app/app  # Hot reload
    ports:
      - "8000:8000"  # Direct access
```

### Production (docker-compose.prod.yml)

```yaml
services:
  backend:
    image: ghcr.io/slck-tor/memgar-backend:latest
    environment:
      - DEBUG=false
      - LOG_LEVEL=INFO
    restart: always
    # No volume mounts (immutable)
    # No direct port exposure (via Nginx)
```

## Environment Variables

### Development

```env
# .env
ENVIRONMENT=development
DEBUG=true
SECRET_KEY=dev-secret-key-not-for-production

DATABASE_URL=postgresql://memgar:memgar@localhost:5432/memgar
REDIS_URL=redis://localhost:6379/0

# Permissive CORS
CORS_ORIGINS=*

# Verbose logging
LOG_LEVEL=DEBUG
LOG_FORMAT=text

# Lenient limits
RATE_LIMIT_PER_MINUTE=1000
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours
```

### Production

```env
# .env.prod
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<64-char-random-string>

DATABASE_URL=postgresql://memgar:<strong-password>@db-primary:5432/memgar
REDIS_URL=redis://:<strong-password>@redis:6379/0

# Strict CORS
CORS_ORIGINS=https://memgar.com,https://app.memgar.com

# Structured logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Production limits
RATE_LIMIT_PER_MINUTE=60
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Monitoring
SENTRY_DSN=https://...@sentry.io/...
PROMETHEUS_ENABLED=true
```

## Security Differences

### Development

- ✅ Weak passwords allowed
- ✅ HTTP connections
- ✅ Detailed error messages
- ✅ SQL query logging
- ✅ CORS from any origin
- ⚠️ Not secure for public internet

### Production

- ✅ Strong password requirements
- ✅ HTTPS enforced
- ✅ Generic error messages
- ✅ No SQL query logging
- ✅ CORS from specific domains
- ✅ Rate limiting enabled
- ✅ Security headers
- ✅ CSRF protection

## Database Configuration

### Development

```python
# Small connection pool
DATABASE_POOL_SIZE=5
DATABASE_MAX_OVERFLOW=10

# No SSL required
DATABASE_URL=postgresql://memgar:memgar@localhost:5432/memgar
```

### Production

```python
# Large connection pool
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# SSL required
DATABASE_URL=postgresql://memgar:password@db.example.com:5432/memgar?sslmode=require

# Read replicas
DATABASE_REPLICA_URLS=postgresql://memgar:password@db-replica-1:5432/memgar,...
```

## Celery Configuration

### Development

```python
# Single worker
celery -A app.celery_app worker --loglevel=debug --concurrency=1

# Synchronous execution (for testing)
CELERY_TASK_ALWAYS_EAGER=true
```

### Production

```python
# Multiple workers with autoscale
celery -A app.celery_app worker \
  --loglevel=info \
  --autoscale=8,4 \
  --max-tasks-per-child=1000

# Separate queues
celery -A app.celery_app worker -Q high_priority
celery -A app.celery_app worker -Q normal_priority
```

## Frontend Configuration

### Development

```javascript
// vite.config.ts
export default {
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:8000'  // Proxy to backend
    }
  }
}
```

### Production

```javascript
// Built and served via Nginx
// API calls go to api.memgar.com
const API_URL = process.env.VITE_API_URL || 'https://api.memgar.com'
```

## Nginx Configuration

### Development

```nginx
# Simple reverse proxy
server {
    listen 80;
    location / {
        proxy_pass http://localhost:3000;
    }
}
```

### Production

```nginx
# Full production config
server {
    listen 443 ssl http2;
    server_name memgar.com;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/memgar.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/memgar.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # Gzip compression
    gzip on;
    gzip_types text/plain application/json;
    
    # Rate limiting
    limit_req zone=api_limit burst=20 nodelay;
    
    location / {
        proxy_pass http://frontend:3000;
        proxy_cache my_cache;
    }
}
```

## Monitoring

### Development

- ✅ Console logs
- ✅ Optional Flower (Celery)
- ⚠️ No persistent monitoring

### Production

- ✅ Structured JSON logs
- ✅ Prometheus metrics
- ✅ Sentry error tracking
- ✅ Celery Flower dashboard
- ✅ Database query monitoring
- ✅ Alert system (PagerDuty, Slack)

## Backup Strategy

### Development

- Manual backups (if any)
- No automated backups

### Production

- ✅ Daily automated backups
- ✅ 30-day retention
- ✅ Encrypted backups
- ✅ Off-site storage (S3)
- ✅ Tested restore procedures
- ✅ Point-in-time recovery

## Scaling

### Development

- Single server
- 1 backend process
- 1 Celery worker
- Local database

### Production

- Load balancer
- Multiple backend replicas (4-8+)
- Multiple Celery workers (8-16+)
- Database with read replicas
- Redis cluster
- CDN for static assets

## Checklist for Production

Before deploying to production:

- [ ] Change `SECRET_KEY` to strong random value
- [ ] Change all default passwords
- [ ] Set `DEBUG=false`
- [ ] Configure SSL certificates
- [ ] Restrict CORS origins
- [ ] Enable rate limiting
- [ ] Configure monitoring (Sentry, Prometheus)
- [ ] Setup backup system
- [ ] Configure email for alerts
- [ ] Review security headers
- [ ] Test disaster recovery
- [ ] Document runbooks
- [ ] Setup CI/CD pipeline
- [ ] Load test the application

## Common Mistakes

1. ❌ Using development config in production
2. ❌ Leaving DEBUG=true in production
3. ❌ Using weak SECRET_KEY
4. ❌ No SSL in production
5. ❌ Overly permissive CORS
6. ❌ No rate limiting
7. ❌ No backup strategy
8. ❌ No monitoring
9. ❌ Direct port exposure
10. ❌ Default passwords

## Transitioning from Dev to Prod

### Step 1: Configuration

```bash
# Copy production template
cp backend/.env.prod.example backend/.env.prod

# Generate secrets
SECRET_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)

# Update .env.prod with these values
```

### Step 2: SSL Certificate

```bash
# Get Let's Encrypt certificate
certbot certonly --standalone -d memgar.com -d app.memgar.com

# Copy to nginx
cp /etc/letsencrypt/live/memgar.com/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/memgar.com/privkey.pem nginx/ssl/
```

### Step 3: Deploy

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Start services
docker-compose -f docker-compose.prod.yml up -d

# Run migrations
docker-compose -f docker-compose.prod.yml exec backend alembic upgrade head
```

### Step 4: Verify

```bash
# Check all services are healthy
docker-compose -f docker-compose.prod.yml ps

# Test HTTPS
curl https://memgar.com/health

# Check logs
docker-compose -f docker-compose.prod.yml logs
```

## Summary

**Development:**
- Fast iteration
- Detailed debugging
- Permissive security
- Local everything

**Production:**
- Security first
- Performance optimized
- Monitored and reliable
- Scalable and redundant

Always test production configuration in a staging environment first!
