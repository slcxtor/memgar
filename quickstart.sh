#!/bin/bash
# Memgar Enterprise - Quick Start Script
# =======================================

set -e

echo "🚀 Memgar Enterprise - Quick Start"
echo "==================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✓ Docker installed"
echo "✓ Docker Compose installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f backend/.env ]; then
    echo "Creating backend/.env file..."
    cp backend/.env.example backend/.env
    
    # Generate secret key
    SECRET_KEY=$(openssl rand -hex 32)
    sed -i "s/your-secret-key-here-change-in-production/$SECRET_KEY/" backend/.env
    
    echo "✓ Created backend/.env with generated SECRET_KEY"
    echo ""
fi

# Build and start services
echo "Building Docker images (this may take a few minutes)..."
docker-compose build

echo ""
echo "Starting services..."
docker-compose up -d

echo ""
echo "Waiting for services to be ready..."
sleep 10

# Run migrations
echo "Running database migrations..."
docker-compose exec -T backend alembic upgrade head

echo ""
echo "Seeding demo data..."
docker-compose exec -T backend python app/scripts/seed_db.py

echo ""
echo "✅ Memgar Enterprise is ready!"
echo ""
echo "Available services:"
echo "  Backend API:     http://localhost:8000"
echo "  API Docs:        http://localhost:8000/docs"
echo "  Dashboard:       http://localhost:3000"
echo "  Landing Page:    http://localhost:3001"
echo "  Celery Flower:   http://localhost:5555"
echo ""
echo "View logs: docker-compose logs -f"
echo "Stop services: docker-compose down"
echo ""
echo "Happy coding! 🎉"
