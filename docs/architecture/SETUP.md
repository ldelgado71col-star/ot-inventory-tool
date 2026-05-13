# Development Environment Setup

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop
- Git
- VS Code (recommended)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ldelgado71col-star/ot-inventory-tool.git
cd ot-inventory-tool
```

### 2. Set up the backend

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp config/.env.example config/.env
# Edit config/.env with your local settings
```

### 4. Start the database

```bash
docker compose -f infrastructure/docker/docker-compose.dev.yml up -d db
```

### 5. Run database migrations

```bash
cd backend
alembic upgrade head
```

### 6. Start the backend API

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at: http://localhost:8000
API docs at: http://localhost:8000/docs

### 7. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend will be available at: http://localhost:3000

## Run with Docker Compose (Full Stack)

```bash
docker compose -f infrastructure/docker/docker-compose.dev.yml up --build
```

## Run Tests

```bash
# Backend tests
cd backend
pytest tests/ -v

# Frontend tests
cd frontend
npm run test
```

## Environment Variables

See `config/.env.example` for all required variables.

| Variable | Description |
|---|---|
| DATABASE_URL | PostgreSQL connection string |
| SECRET_KEY | JWT signing key |
| SCAN_ENABLED | Enable/disable active scanning |
| PASSIVE_INTERFACE | Network interface for passive capture |
| LOG_LEVEL | Logging level (INFO, DEBUG, WARNING) |
