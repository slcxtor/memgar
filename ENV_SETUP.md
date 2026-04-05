# Environment Configuration Guide
# ================================

This guide explains all environment variables and configuration options.

## Quick Setup

```bash
# Copy example file
cp backend/.env.example backend/.env

# Generate secrets
export SECRET_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export REDIS_PASSWORD=$(openssl rand -hex 16)

# Update .env file with generated secrets
```

---

## Environment Variables Reference

### Application Settings

```bash
# Environment type
ENVIRONMENT=development
# Options: development, staging, production

# Enable debug mode (development only!)
DEBUG=true
# Warning: NEVER set to true in production

# Application version
APP_VERSION=0.5.0
```

### Security

```bash
# JWT Secret Key (CRITICAL - must be strong and unique)
SECRET_KEY=your-secret-key-here-change-in-production
# Generate with: openssl rand -hex 32

# JWT algorithm
ALGORITHM=HS256

# Access token expiration (minutes)
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Refresh token expiration (days)
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Database

```bash
# PostgreSQL connection string
DATABASE_URL=postgresql://memgar:memgar_password@localhost:5432/memgar
# Format: postgresql://user:password@host:port/database

# Connection pool size
DATABASE_POOL_SIZE=10

# Maximum overflow connections
DATABASE_MAX_OVERFLOW=20
```

### Redis

```bash
# Redis connection
REDIS_URL=redis://localhost:6379/0
# With password: redis://:password@localhost:6379/0

# Redis password (optional but recommended)
REDIS_PASSWORD=
```

### Celery (Task Queue)

```bash
# Celery broker URL (usually Redis)
CELERY_BROKER_URL=redis://localhost:6379/1

# Celery result backend
CELERY_RESULT_BACKEND=redis://localhost:6379/2
```

### Email (SMTP)

```bash
# SMTP server
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

# SMTP credentials
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# From address
SMTP_FROM=noreply@memgar.com
```

**Gmail Setup:**
1. Enable 2-factor authentication
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use app password as SMTP_PASSWORD

### CORS (Cross-Origin Resource Sharing)

```bash
# Allowed origins (comma-separated)
CORS_ORIGINS=http://localhost:3000,http://localhost:3001,https://memgar.com
```

### Rate Limiting

```bash
# API rate limit (requests per minute)
RATE_LIMIT_PER_MINUTE=60

# Rate limit burst
RATE_LIMIT_BURST=100
```

### Monitoring

```bash
# Enable Prometheus metrics
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090

# Log level
LOG_LEVEL=INFO
# Options: DEBUG, INFO, WARNING, ERROR, CRITICAL

# Log format
LOG_FORMAT=json
# Options: json, text
```

### Enterprise Features

```bash
# Enable audit logging
ENABLE_AUDIT_LOGGING=true

# Enable RBAC
ENABLE_RBAC=true

# Enable multi-tenancy
ENABLE_MULTI_TENANCY=true
```

### Memgar Core

```bash
# Maximum content size (bytes)
MEMGAR_MAX_CONTENT_SIZE=1000000

# Analysis timeout (seconds)
MEMGAR_ANALYSIS_TIMEOUT=30

# Enable semantic analysis (requires models)
MEMGAR_ENABLE_SEMANTIC=false

# Enable LLM analysis
MEMGAR_ENABLE_LLM=false
```

---

## Environment-Specific Configurations

### Development (.env)

```bash
ENVIRONMENT=development
DEBUG=true
DATABASE_URL=postgresql://memgar:memgar@localhost:5432/memgar
REDIS_URL=redis://localhost:6379/0
LOG_LEVEL=DEBUG
```

### Staging (.env.staging)

```bash
ENVIRONMENT=staging
DEBUG=false
DATABASE_URL=postgresql://memgar:STRONG_PASSWORD@postgres-staging:5432/memgar
REDIS_URL=redis://:REDIS_PASSWORD@redis-staging:6379/0
LOG_LEVEL=INFO
SECRET_KEY=GENERATED_SECRET_KEY_STAGING
```

### Production (.env.prod)

```bash
ENVIRONMENT=production
DEBUG=false
DATABASE_URL=postgresql://memgar:STRONG_PASSWORD@postgres-prod:5432/memgar
REDIS_URL=redis://:REDIS_PASSWORD@redis-prod:6379/0
LOG_LEVEL=WARNING
SECRET_KEY=GENERATED_SECRET_KEY_PRODUCTION

# Production email
SMTP_HOST=smtp.sendgrid.net
SMTP_USER=apikey
SMTP_PASSWORD=YOUR_SENDGRID_API_KEY

# Strict CORS
CORS_ORIGINS=https://app.memgar.com,https://memgar.com

# Monitoring
PROMETHEUS_ENABLED=true
ENABLE_AUDIT_LOGGING=true
```

---

## Security Best Practices

### 🔐 Critical Settings

1. **SECRET_KEY**
   - ✅ Generate unique key per environment
   - ✅ Minimum 32 characters
   - ✅ Use openssl: `openssl rand -hex 32`
   - ❌ Never commit to git
   - ❌ Never reuse across environments

2. **Database Password**
   - ✅ Strong, random password
   - ✅ Different per environment
   - ❌ Never use default passwords

3. **Redis Password**
   - ✅ Set in production
   - ✅ Use strong password
   - ❌ Don't leave empty in production

### 🚫 Never Do This

```bash
# ❌ DON'T: Weak secrets
SECRET_KEY=secret123
DATABASE_URL=postgresql://user:password@localhost/db

# ❌ DON'T: Debug in production
DEBUG=true
ENVIRONMENT=production

# ❌ DON'T: Wide open CORS
CORS_ORIGINS=*
```

### ✅ Do This Instead

```bash
# ✅ DO: Strong, unique secrets
SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=postgresql://memgar:$(openssl rand -hex 16)@localhost/memgar

# ✅ DO: Production settings
DEBUG=false
ENVIRONMENT=production

# ✅ DO: Specific CORS origins
CORS_ORIGINS=https://app.memgar.com,https://memgar.com
```

---

## Docker Compose Environment

When using Docker Compose, environment variables can be set in:

1. **`.env` file** (root directory)
   ```bash
   POSTGRES_PASSWORD=your_password
   REDIS_PASSWORD=your_password
   ```

2. **`docker-compose.yml`**
   ```yaml
   services:
     backend:
       environment:
         - DATABASE_URL=postgresql://...
   ```

3. **Separate env file**
   ```yaml
   services:
     backend:
       env_file:
         - backend/.env
   ```

---

## Validation

Before deploying, validate your configuration:

```bash
# Check required variables are set
python -c "from app.config import settings; print(settings.SECRET_KEY)"

# Verify database connection
python -c "from app.database.session import engine; engine.connect()"

# Test Redis connection
redis-cli -u $REDIS_URL ping
```

---

## Troubleshooting

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Test connection
psql $DATABASE_URL -c "SELECT 1"

# Check credentials
echo $DATABASE_URL
```

### Redis Connection Failed

```bash
# Test Redis
redis-cli -u $REDIS_URL ping

# Check password
redis-cli -u $REDIS_URL AUTH $REDIS_PASSWORD
```

### JWT Token Issues

```bash
# Verify SECRET_KEY is set
python -c "from app.config import settings; print(len(settings.SECRET_KEY))"

# Should be >= 32 characters
```

---

## Next Steps

After configuring environment:

1. ✅ Generate strong secrets
2. ✅ Update database credentials
3. ✅ Configure email (optional)
4. ✅ Set CORS origins
5. ✅ Verify with: `make health`
6. ✅ Run migrations: `make migrate`
7. ✅ Seed data: `docker-compose exec backend python app/scripts/seed_db.py`

---

**Need help?** See `DEPLOYMENT.md` for complete production setup.
