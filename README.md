# DriftGuard

**Detect drift. Fix it. Keep your cloud honest.**

Open-source Terraform drift detection with security impact scoring, cost delta calculation, and automatic GitHub PR remediation.

## The Problem

You write Terraform. You apply it. Someone logs into AWS and manually changes a security group, disables S3 encryption, or makes your RDS database publicly accessible. Your Terraform state no longer reflects reality — and you have no idea until something breaks or gets breached.

This is infrastructure drift. DriftGuard catches it automatically.

## What It Does

- Detects drift between your terraform.tfstate and live AWS
- Scores security impact against CIS AWS Benchmarks and MITRE ATT&CK
- Calculates monthly cost delta per drifted resource
- Generates the exact Terraform HCL patch to fix each finding
- Opens a GitHub PR automatically with the fix

## Quick Start

```bash
git clone https://github.com/EdwinJdevops/driftguard.git
cd driftguard
pip install fastapi uvicorn boto3 httpx structlog rich typer --break-system-packages
PYTHONPATH=. python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Dashboard: http://localhost:3000
API Docs: http://localhost:8000/docs

## Test Without AWS

```bash
python3 test_engine.py
```

Runs a full drift simulation with no AWS account needed.

## Stack

Python 3.12 · FastAPI · Celery · PostgreSQL · Redis · AWS ECS Fargate · Terraform · GitHub Actions · Docker

## Supported AWS Resources

aws_instance · aws_security_group · aws_s3_bucket · aws_db_instance · aws_iam_role · aws_iam_policy · aws_eks_cluster · aws_nat_gateway

## Author

Edwin Jonathan Chibuike — Cloud and DevOps Engineer, Lagos Nigeria

GitHub: EdwinJdevops
Blog: edwinjonathand-devops.hashnode.dev
LinkedIn: linkedin.com/in/edwin-jonathan-1094093b0

MIT License
