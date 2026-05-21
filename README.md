# Authorization-Aware DAST Orchestration Platform

This backend is an MVP authorization attack orchestration engine for DAST workflows. It is not a generic scanner wrapper. The core workflow authenticates multiple identities, crawls authenticated application states, stores all traffic, discovers object references, replays requests across identities, validates deterministic authorization failures, and builds an internal authorization graph.

The attack intelligence layer goes beyond raw replay. It tracks request lineage, normalizes dynamic responses, scores ownership confidence, models workflow transitions, executes typed attack strategies, and persists forensic evidence for reproducibility.

## Architecture

The backend is Python 3.12+, FastAPI, async SQLAlchemy, PostgreSQL, Redis, Playwright, httpx, NetworkX, Alembic, and OWASP ZAP as the initial scanner backend.

Primary modules:

- `app/auth`: identity/session management and Playwright authentication intelligence.
- `app/crawling`: authenticated crawling and object discovery.
- `app/storage`: mandatory traffic persistence.
- `app/attack_engine`: attack abstraction framework for BOLA, horizontal escalation, vertical escalation, tenant boundary, and workflow transition attacks.
- `app/validation`: deterministic false-positive reduction using normalization, status, body, schema, sensitive fields, semantic indicators, and validation reasons.
- `app/replay/lineage.py`: request lineage traversal and attack chain reconstruction.
- `app/workflows`: workflow state transition inference and workflow abuse support.
- `app/intelligence`: application mapping, authorization expectations, adaptive attack planning, object relationship inference, attack chaining, reasoning, and scan strategy planning.
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
- `traffic_logs`: full captured request/response traffic with parent request, source type, replay depth, attack chain, and normalized hashes.
- `attack_chains`: crawl, object discovery, replay, validation, and evidence grouped into reconstructable attack paths.
- `attack_attempts`: replay attempts across identities and mutated authorization contexts.
- `validation_results`: deterministic verdicts, normalized diffs, confidence, validation reasons, and evidence.
- `workflow_transitions`: inferred lifecycle transitions such as created to approved or pending to paid.
- `evidence_records`: baseline/replay requests and responses, normalized diffs, validation evidence, confidence, and attack chain linkage.
- `application_map_snapshots`: inferred entities, workflows, endpoint clusters, object groups, tenant boundaries, and privilege boundaries.
- `authorization_expectations`: dynamically inferred expected access models.
- `object_relationships`: ownership chains and nested resource relationships.
- `reasoning_findings`: deterministic authorization reasoning outputs.
- `scan_strategies`: prioritized contextual attack plans and noise controls.
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
7. Typed attack strategies execute BOLA, horizontal escalation, vertical escalation, tenant boundary, and workflow transition attacks.
8. The intelligence layer builds an application map, authorization expectations, object relationships, adaptive attack plans, and scan strategy.
9. The validation engine normalizes dynamic values and compares baseline and replay responses deterministically.
10. Evidence records persist baseline request/response, replay request/response, normalized diffs, validation reasons, confidence, and attack chain.
11. The reasoner combines graph, workflow, ownership, role, and validation evidence into deterministic explanations.
12. The graph engine records users, roles, endpoints, objects, workflows, permissions, attack chains, validation edges, and evidence-backed attack paths.
13. ZAP receives context through the scanner adapter and can run as the initial backend scanner.

## Attack Intelligence

Implemented attack strategies:

- `BOLAAttack`: replays object-specific requests across identities.
- `HorizontalEscalationAttack`: replays successful access across identities.
- `VerticalEscalationAttack`: focuses on state-changing requests that may require higher privilege.
- `TenantBoundaryAttack`: targets tenant and organization identifiers.
- `WorkflowTransitionAttack`: detects and replays lifecycle transitions such as approval, payment, publishing, and archiving.

Response normalization removes timestamps, UUIDs, JWTs, CSRF tokens, session IDs, request IDs, tracking IDs, cursors, and pagination markers before deterministic comparison.

## Contextual Reasoning

The intelligence layer infers:

- entities and endpoint clusters such as `/orders/{id}`, `/orders/{id}/approve`, and `/orders/{id}/refund`;
- object relationships such as invoice -> account -> tenant;
- expected access rules such as buyer should not approve orders or tenant A should not access tenant B objects;
- role-specific workflows and suspicious state transitions;
- adaptive attack chains such as create -> switch identity -> approve -> validate;
- prioritized scan strategy to focus on high-risk objects and privileged workflows.

Advanced validation detects partial data leakage, hidden field exposure, metadata leakage, pagination leakage, row count anomalies, and access pattern anomalies.

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

Investigation endpoints:

```bash
curl http://localhost:8000/api/v1/authorization/attack-chains/{attack_chain_id}
curl http://localhost:8000/api/v1/authorization/traffic/{traffic_log_id}/lineage
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}/workflow-timeline
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}/application-map
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}/reasoning
curl http://localhost:8000/api/v1/authorization/scans/{scan_job_id}/graph-snapshots
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
