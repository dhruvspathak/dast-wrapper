#!/usr/bin/env bash
set -euo pipefail

base_url="${HEALTHCHECK_URL:-http://localhost/health/deep}"
attempts="${HEALTHCHECK_ATTEMPTS:-30}"

for attempt in $(seq 1 "${attempts}"); do
  if curl -fsS "${base_url}" >/tmp/dast-health.json; then
    cat /tmp/dast-health.json
    exit 0
  fi
  echo "Health check failed (${attempt}/${attempts}); retrying..."
  sleep 5
done

docker compose ps
docker compose logs --tail=200 api worker nginx
exit 1
