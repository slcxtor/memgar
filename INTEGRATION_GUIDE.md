# Memgar Enterprise - Integration with Main Repository
# ====================================================

This guide explains how to integrate the enterprise platform with the main Memgar core library.

## Architecture Overview

```
memgar/                          # Main repository (core library)
├── memgar/                      # Python package
│   ├── __init__.py
│   ├── analyzer.py
│   ├── patterns.py
│   └── ...
└── pyproject.toml

memgar-enterprise/               # Enterprise platform (this repo)
├── backend/
│   └── requirements.txt         # Includes: memgar>=0.5.0
├── frontend/
└── landing/
```

## Integration Methods

### Method 1: Use Published Package (Recommended)

**Step 1:** Publish memgar core to PyPI
```bash
cd /path/to/memgar-main
python -m build
twine upload dist/*
```

**Step 2:** Update enterprise requirements
```txt
# backend/requirements.txt
memgar>=0.5.0  # From PyPI
```

**Step 3:** Install in enterprise
```bash
cd memgar-enterprise/backend
pip install -r requirements.txt
```

### Method 2: Local Development

**Step 1:** Install memgar in editable mode
```bash
# From memgar-enterprise/backend/
pip install -e /path/to/memgar-main
```

**Step 2:** Update docker-compose.yml
```yaml
backend:
  volumes:
    - ../memgar-main/memgar:/usr/local/lib/python3.11/site-packages/memgar
```

### Method 3: Git Submodule

**Step 1:** Add as submodule
```bash
cd memgar-enterprise
git submodule add https://github.com/slck-tor/memgar.git core
```

**Step 2:** Update requirements.txt
```txt
# backend/requirements.txt
-e ./core  # Local editable install
```

## Repository Structure Options

### Option A: Monorepo (Single Repository)

```
memgar/
├── core/                    # Core library (Python package)
│   ├── memgar/
│   ├── tests/
│   └── pyproject.toml
│
├── enterprise/              # Enterprise platform
│   ├── backend/
│   ├── frontend/
│   └── landing/
│
└── README.md
```

**Pros:**
- Single source of truth
- Easier version management
- Simplified CI/CD

**Cons:**
- Larger repository
- Mixed concerns

### Option B: Separate Repositories (Current)

```
memgar/                      # Core library
└── ...

memgar-enterprise/           # Enterprise platform
└── ...
```

**Pros:**
- Clear separation
- Independent versioning
- Smaller repositories

**Cons:**
- Version synchronization needed
- Multiple repositories to manage

## Recommended Approach

**For Development:**
1. Keep separate repositories
2. Use local editable install for development
3. Use published package for production

**Setup:**
```bash
# Development environment
cd memgar-enterprise/backend
pip install -e ../../memgar  # Local development

# Production environment
# Use published package from PyPI
```

## Version Synchronization

### Strategy 1: Lock Versions

```txt
# backend/requirements.txt
memgar==0.5.0  # Exact version
```

### Strategy 2: Compatible Versions

```txt
# backend/requirements.txt
memgar>=0.5.0,<0.6.0  # Compatible range
```

### Strategy 3: Latest Stable

```txt
# backend/requirements.txt
memgar>=0.5.0  # Minimum version
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Checkout memgar core
        uses: actions/checkout@v3
        with:
          repository: slck-tor/memgar
          path: core
      
      - name: Install dependencies
        run: |
          cd backend
          pip install -e ../core
          pip install -r requirements.txt
      
      - name: Run tests
        run: pytest
```

## Docker Integration

### Development Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy memgar core
COPY core/ /opt/memgar/
RUN pip install -e /opt/memgar

# Copy backend
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

### Production Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install from PyPI
RUN pip install memgar==0.5.0

# Rest of the build...
```

## Testing Strategy

### Unit Tests (Core Library)
```bash
cd memgar
pytest tests/
```

### Integration Tests (Enterprise)
```bash
cd memgar-enterprise/backend
pytest tests/
```

### End-to-End Tests
```bash
cd memgar-enterprise
docker-compose up -d
pytest tests/e2e/
```

## Migration Path

### Current State → Production

1. **Publish Core to PyPI**
   ```bash
   cd memgar
   python -m build
   twine upload dist/*
   ```

2. **Update Enterprise Requirements**
   ```bash
   cd memgar-enterprise/backend
   # Edit requirements.txt: memgar>=0.5.0
   pip install -r requirements.txt
   ```

3. **Deploy**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d --build
   ```

## Development Workflow

### Scenario 1: Working on Core Features

```bash
# 1. Make changes in memgar core
cd memgar
vim memgar/analyzer.py

# 2. Test in enterprise
cd ../memgar-enterprise
docker-compose restart backend

# 3. Verify
curl http://localhost:8000/api/v1/analysis/analyze
```

### Scenario 2: Working on Enterprise Features

```bash
# 1. Make changes in enterprise
cd memgar-enterprise/backend
vim app/api/v1/analysis.py

# 2. Test
docker-compose restart backend
```

## Version Release Process

### 1. Release Core Library

```bash
cd memgar
# Update version in pyproject.toml
git tag v0.5.0
git push --tags
python -m build
twine upload dist/*
```

### 2. Update Enterprise

```bash
cd memgar-enterprise/backend
# Update requirements.txt: memgar==0.5.0
git commit -am "Update memgar core to v0.5.0"
git tag enterprise-v0.5.0
git push --tags
```

## Troubleshooting

### Issue: Version Mismatch

```bash
# Check installed version
pip show memgar

# Reinstall
pip install --force-reinstall memgar==0.5.0
```

### Issue: Import Errors

```bash
# Verify installation
python -c "from memgar import Memgar; print(Memgar.__version__)"

# Check sys.path
python -c "import sys; print('\n'.join(sys.path))"
```

### Issue: Docker Build Fails

```bash
# Clear Docker cache
docker-compose build --no-cache

# Verify requirements
docker-compose run backend pip list
```

## Best Practices

1. **Version Pinning**: Always pin memgar version in production
2. **Testing**: Test enterprise with latest core changes
3. **Documentation**: Update docs when core API changes
4. **Changelog**: Maintain CHANGELOG.md in both repos
5. **Compatibility**: Follow semantic versioning

## Summary

**Recommended Setup:**
- ✅ Separate repositories for core and enterprise
- ✅ Use PyPI package in production
- ✅ Use local editable install for development
- ✅ Pin versions in production
- ✅ Use compatible ranges in development

This gives you the best of both worlds: flexibility in development and stability in production.
