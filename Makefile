# Memgar Enterprise - Makefile
# ============================

.PHONY: help install dev build up down logs test clean migrate

# Default target
help:
	@echo "Memgar Enterprise - Available Commands"
	@echo "======================================="
	@echo ""
	@echo "Development:"
	@echo "  make install    - Install all dependencies"
	@echo "  make dev        - Start development servers"
	@echo "  make test       - Run tests"
	@echo ""
	@echo "Docker:"
	@echo "  make build      - Build Docker images"
	@echo "  make up         - Start all services"
	@echo "  make down       - Stop all services"
	@echo "  make logs       - View service logs"
	@echo "  make restart    - Restart all services"
	@echo ""
	@echo "Database:"
	@echo "  make migrate    - Run database migrations"
	@echo "  make migration  - Create new migration"
	@echo "  make reset-db   - Reset database (WARNING: deletes all data)"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean      - Clean temporary files"
	@echo "  make format     - Format code (black, prettier)"
	@echo "  make lint       - Lint code (ruff, eslint)"

# =============================================================================
# DEVELOPMENT
# =============================================================================

install:
	@echo "Installing backend dependencies..."
	cd backend && pip install -r requirements.txt
	@echo "Installing frontend dependencies..."
	cd frontend && npm install
	@echo "Installing landing dependencies..."
	cd landing && npm install
	@echo "✓ All dependencies installed"

dev:
	@echo "Starting development servers..."
	@echo "Backend will be available at http://localhost:8000"
	@echo "Frontend will be available at http://localhost:3000"
	@echo "Landing will be available at http://localhost:3001"
	@echo ""
	docker-compose -f docker-compose.dev.yml up

test:
	@echo "Running backend tests..."
	cd backend && pytest
	@echo "Running frontend tests..."
	cd frontend && npm test

# =============================================================================
# DOCKER
# =============================================================================

build:
	@echo "Building Docker images..."
	docker-compose build

up:
	@echo "Starting all services..."
	docker-compose up -d
	@echo "✓ Services started"
	@echo ""
	@echo "Backend API:  http://localhost:8000"
	@echo "API Docs:     http://localhost:8000/docs"
	@echo "Dashboard:    http://localhost:3000"
	@echo "Landing:      http://localhost:3001"
	@echo "Flower:       http://localhost:5555"
	@echo ""
	@echo "View logs: make logs"

down:
	@echo "Stopping all services..."
	docker-compose down
	@echo "✓ Services stopped"

restart:
	@echo "Restarting all services..."
	docker-compose restart
	@echo "✓ Services restarted"

logs:
	docker-compose logs -f

logs-backend:
	docker-compose logs -f backend

logs-frontend:
	docker-compose logs -f frontend

logs-celery:
	docker-compose logs -f celery-worker

# =============================================================================
# DATABASE
# =============================================================================

migrate:
	@echo "Running database migrations..."
	docker-compose exec backend alembic upgrade head
	@echo "✓ Migrations complete"

migration:
	@echo "Creating new migration..."
	@read -p "Migration message: " msg; \
	docker-compose exec backend alembic revision --autogenerate -m "$$msg"

downgrade:
	@echo "Reverting last migration..."
	docker-compose exec backend alembic downgrade -1

reset-db:
	@echo "⚠️  WARNING: This will DELETE ALL DATA!"
	@read -p "Are you sure? (yes/no): " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		docker-compose exec backend alembic downgrade base && \
		docker-compose exec backend alembic upgrade head && \
		echo "✓ Database reset complete"; \
	else \
		echo "Cancelled"; \
	fi

# =============================================================================
# MAINTENANCE
# =============================================================================

clean:
	@echo "Cleaning temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "node_modules" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".next" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleaned"

format:
	@echo "Formatting code..."
	cd backend && black app/
	cd frontend && npx prettier --write src/
	cd landing && npx prettier --write src/
	@echo "✓ Code formatted"

lint:
	@echo "Linting backend..."
	cd backend && ruff check app/
	@echo "Linting frontend..."
	cd frontend && npm run lint
	@echo "Linting landing..."
	cd landing && npm run lint

# =============================================================================
# PRODUCTION
# =============================================================================

deploy-prod:
	@echo "Deploying to production..."
	docker-compose -f docker-compose.prod.yml up -d --build
	@echo "✓ Production deployment complete"

backup-db:
	@echo "Creating database backup..."
	docker-compose exec postgres pg_dump -U memgar memgar > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✓ Backup created"

# =============================================================================
# MONITORING
# =============================================================================

ps:
	docker-compose ps

stats:
	docker stats

health:
	@echo "Checking service health..."
	@curl -sf http://localhost:8000/health || echo "❌ Backend unhealthy"
	@curl -sf http://localhost:3000 || echo "❌ Frontend unhealthy"
	@curl -sf http://localhost:3001 || echo "❌ Landing unhealthy"
