# Production Deployment

Target: one Ubuntu Server 24.04 LTS EC2 instance, Docker Compose, Nginx reverse proxy.

## 1. Provision Infrastructure

Use the lightweight Terraform module in `infra/terraform`.

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

The module creates:

- EC2 instance
- Security group
- Elastic IP
- IAM instance profile
- Encrypted EBS volume

It does not create ECS, EKS, or Kubernetes.

## 2. Bootstrap Ubuntu

On the EC2 instance:

```bash
./scripts/bootstrap-ubuntu.sh
```

Log out and back in after Docker installation so group membership applies.

## 3. Configure Environment

```bash
cp .env.example .env
```

Set production values:

- `POSTGRES_PASSWORD`
- `SECRET_KEY`
- `OPENAI_API_KEY` if AI triage is enabled
- `API_CORS_ORIGINS`
- `ZAP_JAVA_OPTS`

Do not commit production `.env` files.

## 4. Start The Platform

```bash
./scripts/deploy.sh
```

Or directly:

```bash
docker compose up -d
```

## 5. Health Checks

```bash
curl http://localhost/health/live
curl http://localhost/health/ready
curl http://localhost/health/deep
```

`scripts/healthcheck.sh` runs the deployment health gate used by CI/CD.

## 6. GitHub Actions Deployment

`.github/workflows/deploy.yml` deploys pushes to `main` to one Ubuntu 24.04 EC2 host over SSH.

Required repository or environment secrets:

- `EC2_HOST`
- `EC2_USER`
- `EC2_SSH_KEY`
- `EC2_APP_DIR`
- optional `EC2_SSH_PORT`

The workflow:

1. SSHes into the EC2 instance.
2. Fetches and fast-forwards `main`.
3. Validates `.env`.
4. Rebuilds Docker Compose services.
5. Runs Alembic migrations.
6. Runs deep health checks.
7. Fails deployment when health checks fail.

## 7. Operational Notes

- Public access is through Nginx only.
- Redis, Postgres, ZAP, and Playwright are internal-only Compose services.
- ZAP scans can be long-running. Tune `ZAP_SCAN_TIMEOUT_SECONDS`, `ZAP_POLL_INTERVAL_SECONDS`, and `ZAP_POLL_MAX_ERRORS`.
- Tune `MAX_ACTIVE_SCANS`, `WORKER_CONCURRENCY`, `CELERY_TASK_TIME_LIMIT_SECONDS`, and container memory limits together.
- Set `REPLAY_ALLOWED_HOSTS` in production to prevent out-of-scope replay.
- Scale workers on the single node with:

```bash
docker compose up -d --scale worker=2
```

Keep EC2 memory limits in mind when scaling workers and ZAP.

## Troubleshooting

- `docker compose ps`: service state and health.
- `docker compose logs --tail=200 api worker`: API and worker failures.
- `curl http://localhost/health/deep`: dependency and queue status.
- `docker compose exec redis redis-cli llen scan`: scan queue depth.
- `docker compose exec postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"`: database readiness.
- Check ZAP memory with container stats when scans stall.
- Check Playwright storage volume if role sessions appear contaminated.
