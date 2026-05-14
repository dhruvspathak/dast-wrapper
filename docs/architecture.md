# Architecture

The platform is deployed as a single-node Docker Compose stack on Ubuntu Server 24.04 LTS.

```text
Internet
  -> Nginx
  -> FastAPI API
  -> Redis broker/result backend
  -> Celery worker queues
  -> Replay and validation engines
  -> Scanner containers
  -> Playwright browser container
```

## Service Boundaries

- `nginx`: only public entrypoint. Handles proxying, headers, upload limits, and rate-limit placeholders.
- `api`: FastAPI application. Owns API lifecycle, request validation, DB access, and orchestration.
- `worker`: Celery worker consuming `scan`, `replay`, `validation`, and `report` queues.
- `postgres`: internal database only.
- `redis`: internal Celery broker/result backend only.
- `zap`: internal OWASP ZAP API/proxy only.
- `playwright`: isolated browser runtime with persistent state volume.

## Networks

- `frontend`: Nginx to API.
- `backend`: API/worker to Redis and Postgres.
- `scanner`: worker to scanner and browser runtimes.

Redis, Postgres, ZAP, and Playwright are not exposed to the host.

## Scanner Plugins

Scanner integration is routed through `app.scanners.base.ScannerPlugin` and `app.scanners.registry.scanner_registry`.
ZAP is the first registered plugin. Additional scanners such as nuclei and sqlmap should implement the same interface and register themselves without changing orchestration code.

Every plugin must normalize scanner-native output into `app.schemas.canonical.Finding`.
Scanner-native fields are stored only as `raw` evidence and must not be consumed directly by orchestration, replay, authorization validation, AI triage, or reporting.

```text
scanner plugin
  -> canonical Finding / RequestData / ResponseData
  -> replay diff engine
  -> authorization validation engine
  -> AI triage from normalized evidence
  -> report artifacts
```

## Canonical Models

Canonical Pydantic models live in `app/schemas/canonical.py`:

- `Finding`
- `RequestData`
- `ResponseData`
- `ReplayResult`
- `ValidationResult`
- `AuthContext`
- `ScanExecution`
- `ReportArtifact`

SQLAlchemy persistence mirrors these contracts in `app/models`. New tables and columns are added through Alembic migrations.

## Auth Context Engine

`app.auth.context_manager.AuthContextManager` owns session persistence and retrieval.
An `AuthContext` contains role, workspace, headers, cookies, local storage, session storage, refresh token metadata, expiry, and Playwright storage-state path.
Sensitive fields are redacted before logging or returning operational metadata.

Playwright authentication uses isolated browser contexts per workspace/application/role and persists storage state under `/browser-state`.
This prevents role contamination and lets replay/scanner code consume deterministic role-scoped auth material.

## Replay Diff Engine

`app.replay.diff_engine.ReplayDiffEngine` compares replay evidence using:

- status transitions
- normalized body similarity
- response fingerprints
- timing deltas
- JSON shape summaries
- ownership metadata deltas
- short unified diff excerpts

Status code comparison alone is never treated as sufficient validation.

## Authorization Validation

`app.validators.authorization_engine.AuthorizationValidationEngine` performs role-based replay, token swapping, and identifier mutation for likely ownership identifiers:

- `user_id`
- `plan_id`
- `report_id`
- `org_id`
- `activity_id`
- `tenant_id`
- `workspace_id`

It produces a canonical `ValidationResult` with confidence, exploitability, evidence, and remediation guidance.

## Queues

- `scan`: scanner execution.
- `replay`: replay validation.
- `validation`: IDOR/BOLA/business-logic validation.
- `report`: report generation.

Celery is configured with late acknowledgements, worker-loss rejection, and prefetch of one task per worker process to reduce duplicate long-running scan side effects.

## Governance

The platform includes production-safe defaults:

- active scan limits per workspace
- scan cancellation state and Celery revocation
- scan timeouts
- Celery hard/soft time limits
- worker child recycling
- memory-per-child caps
- replay concurrency and host scope controls

## Observability

Structured JSON logs include correlation IDs and redact credentials.

Health endpoints:

- `/health/live`: process liveness
- `/health/ready`: API, Postgres, Redis readiness
- `/health/deep`: Postgres, Redis queue depth, ZAP, Playwright TCP, and process memory

Nginx emits JSON access logs with correlation IDs and rate-limit placeholders.
