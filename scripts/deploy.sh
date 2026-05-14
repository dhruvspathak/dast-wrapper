#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo ".env is missing. Copy .env.example to .env and set production values." >&2
  exit 1
fi

./scripts/validate-env.sh

previous_revision="$(git rev-parse --short HEAD || true)"
echo "Deploying revision ${previous_revision}"

docker compose build
docker compose up -d --remove-orphans
docker compose run --rm api alembic upgrade head
docker compose ps

echo "Rollback placeholder: git checkout <previous-known-good> && docker compose up -d --build"
