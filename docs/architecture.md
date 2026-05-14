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

## Queues

- `scan`: scanner execution.
- `replay`: replay validation.
- `validation`: IDOR/BOLA/business-logic validation.
- `report`: report generation.

Celery is configured with late acknowledgements, worker-loss rejection, and prefetch of one task per worker process to reduce duplicate long-running scan side effects.
