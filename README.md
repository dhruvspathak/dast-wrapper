# DAST Wrapper Platform

Application Security Orchestration & Validation Platform

## Overview

This platform orchestrates, automates, validates, replays, and triages security findings from tools like OWASP ZAP, Burp Suite, Checkmarx DAST, nuclei, sqlmap, and browser automation frameworks.

## Features

- **Context-driven onboarding** with YAML configuration
- **Playwright-based authentication** for enterprise applications
- **ZAP orchestration** with authenticated scanning
- **Replay engine** for finding validation
- **IDOR/BOLA validator** for authorization testing
- **AI-assisted triage** (Phase 2)
- **HTML reporting** with evidence and remediation

## Quick Start

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- OWASP ZAP (optional, can run in container)

### Setup

1. Install dependencies:
```bash
pip install -e .
```

2. Create database tables:
```bash
python create_tables.py
```

3. Start services:
```bash
docker-compose up -d postgres redis zap
```

4. Start Celery worker:
```bash
celery -A app.workers.celery_app worker --loglevel=info
```

5. Start the application:
```bash
uvicorn app.api.main:app --reload
```

### Usage Flow

1. **Upload Configuration**: POST `/api/v1/scans/upload-config` with YAML file
2. **Authenticate**: POST `/api/v1/auth/authenticate` with config_id and role
3. **Start Scan**: POST `/api/v1/scans/start-scan` with config_id
4. **Monitor Progress**: GET `/api/v1/scans/scan-status/{job_id}`
5. **Get Findings**: GET `/api/v1/scans/findings/{scan_id}`
6. **Generate Report**: POST `/api/v1/reports/generate-report/{scan_id}`
7. **View Report**: GET `/api/v1/reports/report/{report_id}/download`

### Web Dashboard

Visit `http://localhost:8000/` for a simple web interface to interact with the API.

### Usage

1. Upload a YAML configuration file via `/api/v1/scans/upload-config`
2. Authenticate using Playwright via `/api/v1/auth/authenticate`
3. Start a scan via `/api/v1/scans/start-scan`
4. Monitor progress and get findings
5. Generate reports via `/api/v1/reports/generate-report`

### Sample Configuration

See `configs/sample.yaml` for an example application configuration.

## Architecture

- **Backend**: FastAPI with async SQLAlchemy
- **Jobs**: Celery with Redis
- **Database**: PostgreSQL
- **Browser Automation**: Playwright
- **Scanning**: ZAP API, nuclei, sqlmap
- **Reporting**: Jinja2 templates

## Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
black .
isort .
mypy .
```

## API Documentation

Once running, visit `http://localhost:8000/docs` for interactive API docs.

## License

[License information]
