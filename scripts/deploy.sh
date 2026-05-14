#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo ".env is missing. Copy .env.example to .env and set production values." >&2
  exit 1
fi

docker compose pull
docker compose build
docker compose up -d
docker compose ps
