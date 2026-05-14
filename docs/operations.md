# Operations Guide

## Health

- `/health/live`: API process is alive.
- `/health/ready`: API, Postgres, and Redis are reachable.
- `/health/deep`: dependency health, Redis queue depths, ZAP, Playwright, and process memory.

## Queue Governance

Celery queues:

- `scan`
- `replay`
- `validation`
- `report`

Defaults limit active scans per workspace and cap worker task runtime. Tune queue concurrency alongside container memory limits.

## Cancellation

Use:

```bash
curl -X POST "http://localhost/api/v1/scans/cancel/<scan_id>?workspace_id=default"
```

Cancellation marks the scan as cancelling and revokes the Celery task.

## Deployment

Production deploy uses:

```bash
./scripts/validate-env.sh
./scripts/deploy.sh
./scripts/healthcheck.sh
```

The GitHub Actions workflow runs the same scripts over SSH on pushes to `main`.

## Troubleshooting Checklist

- Check `docker compose ps` for unhealthy services.
- Check `/health/deep` for dependency failures and queue depth.
- Inspect `docker compose logs --tail=200 api worker`.
- Ensure `REPLAY_ALLOWED_HOSTS` includes only approved target hosts.
- Keep ZAP heap below the container memory limit.
- Clear or rotate `/browser-state` only when role sessions are intentionally reset.
