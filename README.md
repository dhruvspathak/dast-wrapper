# Authorization-Aware DAST Orchestration Platform

This backend is an MVP authorization attack orchestration engine for DAST workflows. It is not a generic scanner wrapper. The core workflow authenticates multiple identities, crawls authenticated application states, stores all traffic, discovers object references, replays requests across identities, validates deterministic authorization failures, and builds an internal authorization graph.

## Architecture

The backend is Python 3.12+, FastAPI, async SQLAlchemy, PostgreSQL, Redis, Playwright, httpx, NetworkX, Alembic, and OWASP ZAP as the initial scanner backend.

Primary modules:

- `app/auth`: identity/session management and Playwright authentication intelligence.
- `app/crawling`: authenticated crawling and object discovery.
- `app/storage`: mandatory traffic persistence.
- `app/attack_engine`: BOLA, IDOR, horizontal privilege escalation, vertical privilege escalation, and broken access control replay logic.
- `app/validation`: deterministic false-positive reduction using status, body, schema, sensitive fields, and semantic indicators.
- `app/graph`: NetworkX authorization graph for users, roles, objects, endpoints, permissions, and attack edges.
- `app/orchestration`: retry-safe workflow state plus Redis queue boundary.
- `app/scanners`: scanner adapter abstraction with ZAP implementation.
- `app/models`: SQLAlchemy domain models.
- `app/api/routes`: FastAPI routes for onboarding, identities, scans, findings, and graph retrieval.

## Data Model

The authorization MVP adds these tables:

- `identities`: per-application users, role labels, auth headers, encrypted credential placeholders.
- `sessions`: isolated browser/session state per identity, including cookies, local storage, session storage, tokens, auth headers, and traffic history.
- `endpoints`: discovered HTTP endpoints with normalized paths.
- `object_references`: numeric IDs, UUIDs, tenant hints, owner-linked references.
- `traffic_logs`: full captured request/response traffic.
- `attack_attempts`: replay attempts across identities and mutated authorization contexts.
- `validation_results`: deterministic verdicts and evidence.
- `scan_jobs`: authorization scan lifecycle.
- `workflow_states`: idempotent orchestration stages and retry metadata.
- `authorization_graph_snapshots`: serialized NetworkX graph payloads.

Legacy scanner tables remain for backward compatibility.

## Workflow

1. Create an application.
2. Add at least two identities with role labels and login configuration.
3. Start an authorization scan.
4. The worker authenticates each identity with Playwright and persists browser state.
5. The crawler visits authenticated pages and stores all observed traffic.
6. Object discovery extracts IDs, UUIDs, tenant identifiers, and ownership hints.
7. The attack engine replays successful requests across identities.
8. The validation engine compares baseline and replay responses deterministically.
9. The graph engine records users, roles, endpoints, objects, permissions, and confirmed/likely attack edges.
10. ZAP receives context through the scanner adapter and can run as the initial backend scanner.

## API Examples

Create an application:

```bash
curl -X POST http://localhost:8000/api/v1/applications \
  -H "Content-Type: application/json" \
  -d '{"name":"Example Commerce","base_url":"http://localhost:3000","config":{}}'
```

Add identities:

```bash
curl -X POST "http://localhost:8000/api/v1/applications/{application_id}/identities" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "Alice Buyer",
    "role": "buyer",
    "username": "alice@example.com",
    "password": "alice-password",
    "login_config": {
      "login_url": "http://localhost:3000/login",
      "username_selector": "input[name=email]",
      "password_selector": "input[name=password]",
      "submit_selector": "button[type=submit]"
    }
  }'
```

Start an authorization scan:

```bash
curl -X POST http://localhost:8000/api/v1/authorization/scans \
  -H "Content-Type: application/json" \
  -d '{"application_id":"{application_id}","scanner_backend":"zap","config":{"max_pages":50}}'
```

Check status:

```bash
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}
```

Get findings:

```bash
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}/findings
```

Get authorization graph:

```bash
curl "http://localhost:8000/api/v1/authorization/applications/{application_id}/graph?scan_job_id={scan_job_id}"
```

## Docker

```bash
docker compose up --build
```

Services include:

- `api`: FastAPI backend.
- `worker`: Celery worker for orchestration execution.
- `postgres`: PostgreSQL 16.
- `redis`: Redis queue/cache.
- `zap`: OWASP ZAP backend.
- `playwright`: browser automation support container.
- `nginx`: reverse proxy.

Run migrations:

```bash
alembic upgrade head
```

## Seed Example

See `configs/authorization-mvp-seed.yaml` for an example application with two horizontal buyer identities and one admin identity.

## MVP Boundaries

Implemented intentionally without AI remediation, compliance reports, Burp integration, Kubernetes, SaaS billing, SSO, PDF exports, or multi-tenancy. The scanner abstraction is ready for more backends, but only ZAP is implemented.
