# DAST Orchestration Platform

Enterprise Application Security Orchestration and Validation Platform built with FastAPI, Celery, Redis, PostgreSQL, OWASP ZAP, Playwright, Docker Compose, and Nginx.

## Deployment Architecture

```text
Internet
  -> Nginx
  -> FastAPI API Layer
  -> Redis Queue + Celery Workers
  -> Replay Engine / Validation Engine
  -> Scanner Containers
  -> Playwright Browser Containers
```

## Repository Layout

```text
app/
  api/         FastAPI routes and bootstrap
  core/        config, logging, middleware
  auth/        Playwright authentication/session helpers
  scanners/    scanner plugin contracts and implementations
  replay/      replay engine
  validators/  authorization and business logic validators
  ai/          AI-assisted triage layer
  reporting/   report generation
  workers/     Celery app and tasks
  db/          async SQLAlchemy setup
  models/      database models
  schemas/     Pydantic schemas
  utils/       security helpers
docker/        container entrypoints and scanner/browser images
nginx/         reverse proxy config
infra/         Terraform for EC2 deployment
configs/       scan configuration inputs
reports/       generated reports
docs/          architecture and deployment notes
tests/         test suite
```

## Quick Start

```bash
cp .env.example .env
docker compose up -d
```

The only public service is Nginx:

- API docs: `http://localhost/docs`
- Liveness: `http://localhost/health/live`
- Readiness: `http://localhost/health/ready`

Redis, Postgres, ZAP, and Playwright are internal-only container services.

## Core APIs

- Upload config: `POST /api/v1/scans/upload-config`
- Start scan: `POST /api/v1/scans/start-scan`
- Check scan: `GET /api/v1/scans/scan-status/{job_id}`
- Findings: `GET /api/v1/scans/findings/{scan_id}`
- Generate report: `POST /api/v1/reports/generate-report/{scan_id}`

## Operations

Deploy on Ubuntu Server 24.04 LTS:

```bash
./scripts/bootstrap-ubuntu.sh
./scripts/deploy.sh
```

Terraform for AWS EC2 lives in `infra/terraform`. See [docs/deployment.md](docs/deployment.md).

## Development

```bash
pip install -e .[dev]
pytest
python -m compileall app
```

## Security Notes

- Production secrets belong in `.env` or your secret manager, never in Git.
- Logs are JSON structured and redact token-like fields.
- Scanner and browser containers are isolated on an internal Docker network.
- AI triage is an augmentation layer and is not required for scan orchestration.
