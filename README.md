# DriftGuard

Terraform drift detection for AWS. Compares `terraform.tfstate` against live AWS API state, scores each discrepancy against CIS AWS Benchmarks and MITRE ATT&CK, calculates the monthly cost delta, and generates a Terraform patch to restore the declared state.

## The problem

Terraform state describes what your infrastructure should look like. It does not verify that your infrastructure still looks like that. A security group rule changed through the console, an S3 bucket with encryption disabled mid-incident, an RDS instance flipped to publicly accessible — none of it shows up in `terraform plan` unless someone happens to apply against the same resource again. Most teams find out during an audit or after an incident.

DriftGuard checks continuously instead.

## What it does

| Stage | Behavior |
|---|---|
| Parse | Reads `terraform.tfstate`, either uploaded directly or pulled from an S3 backend |
| Collect | Queries live AWS state for the same resources via boto3 — EC2, S3, RDS, Security Groups, IAM |
| Diff | Compares every tracked attribute, flags additions, deletions, and modifications |
| Score | Maps each discrepancy to CIS AWS Benchmark controls and MITRE ATT&CK techniques, assigns severity |
| Price | Calculates monthly cost delta for resources where drift changes billing (instance resizing, NAT gateways) |
| Patch | Generates the Terraform HCL block needed to restore declared state |

## What it does not do

- It does not modify your infrastructure. It reads AWS state and reads Terraform state. Nothing is written to either.
- It does not auto-apply patches. The generated HCL is output for review, not executed.
- It does not support multi-cloud yet. AWS only. Azure and GCP collectors are not built.
- It is not a replacement for `terraform plan`. Plan tells you what *will* change. DriftGuard tells you what already changed outside your control.

## Architecture

```
terraform.tfstate ──┐
                     ├──▶ DriftAnalyzer ──▶ DriftResult[] ──▶ PostureScorer ──▶ score (0-100)
Live AWS API ────────┘         │
                                ▼
                       Terraform HCL patch
                                │
                                ▼
                    Persisted to PostgreSQL (DriftFinding)
```

The API is stateless per request. Scans run as FastAPI background tasks, writing results to PostgreSQL in a separate transaction from the request that triggered them — this matters because background tasks open their own DB session and will not see uncommitted data from the request session.

## Stack

- **API**: FastAPI, async throughout
- **DB**: SQLAlchemy 2.0 async ORM, PostgreSQL in production, SQLite for local dev/CI
- **Auth**: API keys, SHA-256 hashed at rest, never stored or logged in plaintext
- **AWS access**: boto3, either via passed credentials per-scan or an assumed IAM role
- **Rate limiting**: slowapi, per-route limits tuned to endpoint cost
- **Testing**: pytest, 21 unit tests on the drift engine plus integration tests against `moto`-mocked AWS

## Resource coverage

| Resource | Tracked attributes |
|---|---|
| `aws_instance` | instance_type, vpc_security_group_ids, iam_instance_profile |
| `aws_s3_bucket` | versioning, server_side_encryption_configuration, acl |
| `aws_security_group` | ingress, egress |
| `aws_db_instance` | instance_class, publicly_accessible, storage_encrypted |
| `aws_iam_role` | assume_role_policy |
| `aws_iam_policy` | policy document |

Anything outside this list is not yet collected. Extending coverage means adding a method to `AWSStateCollector` and a rule entry to `SECURITY_RULES` in `backend/engines/drift.py`.

## Running it

### Local, no AWS account needed

```bash
git clone https://github.com/EdwinJdevops/driftguard.git
cd driftguard
pip install -r requirements.txt
pytest backend/tests/ -v
```

This runs the full drift engine test suite against synthetic state — no AWS credentials required, nothing leaves your machine.

### Full stack

```bash
pip install -r requirements.txt
uvicorn backend.api.main:app --reload
```

API at `http://localhost:8000`, interactive docs at `/docs`. Defaults to SQLite if `DATABASE_URL` is unset.

```bash
python3 -m http.server 3000 --directory frontend
```

Dashboard at `http://localhost:3000`. First load prompts account creation — this issues an API key shown exactly once.

### Production database

SQLite is fine for testing the engine. It is not fine for a deployed instance — Render and most free-tier hosts wipe the filesystem on restart, which means every scan result disappears. Use Postgres:

```bash
# Neon (free tier, no expiry, unlike Render's 90-day free Postgres)
DATABASE_URL=postgresql+asyncpg://user:pass@host/driftguard
```

## API

Every authenticated route expects `Authorization: Bearer dg_live_...`.

```bash
# Create an organization, get an API key (shown once)
curl -X POST $API/signup \
  -d '{"org_name": "Acme", "org_slug": "acme"}'

# Create a workspace
curl -X POST $API/workspaces \
  -H "Authorization: Bearer $KEY" \
  -d '{"name": "production", "region": "us-east-1"}'

# Trigger a scan
curl -X POST $API/workspaces/$WS_ID/scan \
  -H "Authorization: Bearer $KEY" \
  -d @terraform.tfstate

# Poll for results
curl $API/scans/$SCAN_ID -H "Authorization: Bearer $KEY"
```

Full schema at `/docs`.

## Known limitations

- No GitHub App integration yet — auto-PR creation is built (`backend/integrations/github.py`) but not wired into the scan pipeline. Currently a manual call.
- Scheduled scanning (`scan_interval_minutes` on a workspace) is stored but not enforced. Celery Beat task exists, dispatch logic does not.
- No multi-tenant resource isolation testing under load. Built for correctness, not yet load-tested.
- IAM least-privilege policy for the scanning role is not published. Until it is, scope credentials manually to read-only access on EC2, S3, RDS, IAM describe actions.

## Testing

```bash
pytest backend/tests/ -v
```

21 tests covering: state parsing, drift detection (modified/added/deleted resources), severity scoring, CIS compliance mapping, cost delta calculation, Terraform patch generation, posture scoring, and fingerprint determinism.

Integration tests use `moto` to mock AWS responses — they exercise the full pipeline including a real RDS instance flipped to public, verified against the actual severity and compliance output, not assumed.

## License

MIT.

## Author

Edwin Jonathan Chibuike. Cloud and DevOps Engineer, Lagos, Nigeria.

[github.com/EdwinJdevops](https://github.com/EdwinJdevops) · [linkedin.com/in/edwin-jonathan-1094093b0](https://linkedin.com/in/edwin-jonathan-1094093b0)
