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
```

## 6. Operational Notes

- Public access is through Nginx only.
- Redis, Postgres, ZAP, and Playwright are internal-only Compose services.
- ZAP scans can be long-running. Tune `ZAP_SCAN_TIMEOUT_SECONDS`, `ZAP_POLL_INTERVAL_SECONDS`, and `ZAP_POLL_MAX_ERRORS`.
- Scale workers on the single node with:

```bash
docker compose up -d --scale worker=2
```

Keep EC2 memory limits in mind when scaling workers and ZAP.
