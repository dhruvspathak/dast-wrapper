#!/usr/bin/env bash
set -euo pipefail

required=(
  POSTGRES_DB
  POSTGRES_USER
  POSTGRES_PASSWORD
  SECRET_KEY
)

if [ ! -f .env ]; then
  echo ".env is missing" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

for name in "${required[@]}"; do
  if [ -z "${!name:-}" ]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 1
  fi
done

if [ "${SECRET_KEY}" = "your-secret-key-here" ]; then
  echo "SECRET_KEY must be changed for deployment" >&2
  exit 1
fi
