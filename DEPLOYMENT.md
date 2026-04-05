# Memgar Enterprise - Production Deployment Guide

Complete guide for deploying Memgar Enterprise to production.

## 🎯 Quick Links

- [Server Requirements](#server-requirements)
- [SSL Setup](#ssl-certificates)
- [Database Configuration](#database-setup)
- [Deployment Steps](#deployment)
- [Monitoring](#monitoring)
- [Backup Strategy](#backup--recovery)

## Server Requirements

**Minimum Specs:**
- OS: Ubuntu 22.04 LTS
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD
- Docker 24.0+
- Docker Compose 2.20+

**Recommended for Production:**
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 100GB+ SSD

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/slck-tor/memgar-enterprise.git
cd memgar-enterprise

# 2. Configure environment
cp backend/.env.example backend/.env.production
# Edit with your values

# 3. Generate SSL certificates
./scripts/generate-ssl.sh

# 4. Deploy
docker compose -f docker-compose.prod.yml up -d

# 5. Run migrations
docker compose -f docker-compose.prod.yml exec backend alembic upgrade head
```

## Full Documentation

See complete deployment guide in `/docs/DEPLOYMENT_GUIDE.md`

---

**Version:** 0.5.0  
**Last Updated:** April 5, 2026
