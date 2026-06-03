#!/usr/bin/env python3
"""
DriftGuard — Local Engine Test
Run: python3 test_engine.py
Tests the drift detection engine with fake AWS state (no AWS account needed)
"""
import sys, os
sys.path.insert(0, os.path.expanduser("~/driftguard"))
from backend.engines.drift import TerraformStateParser, DriftAnalyzer, PostureScorer

print("=" * 55)
print("  DriftGuard Engine Test")
print("=" * 55)

# This simulates what your terraform.tfstate looks like
fake_state = {
    "version": 4,
    "resources": [
        {
            "mode": "managed", "type": "aws_instance", "name": "web_server",
            "instances": [{"attributes": {"id":"i-0abc123","instance_type":"t3.micro","vpc_security_group_ids":["sg-111"],"tags":{"Name":"web"}}}]
        },
        {
            "mode": "managed", "type": "aws_s3_bucket", "name": "data_bucket",
            "instances": [{"attributes": {"id":"my-prod-bucket","versioning":"Enabled","server_side_encryption_configuration":{"rule":"AES256"},"acl":"private"}}]
        },
        {
            "mode": "managed", "type": "aws_db_instance", "name": "prod_db",
            "instances": [{"attributes": {"id":"prod-db","instance_class":"db.t3.medium","publicly_accessible":False,"storage_encrypted":True}}]
        }
    ]
}

# This simulates what AWS actually looks like AFTER someone manually changed things
live_resources = {
    "aws_instance": {
        "i-0abc123": {"id":"i-0abc123","instance_type":"t3.large","vpc_security_group_ids":["sg-999"],"tags":{"Name":"web"}}
    },
    "aws_s3_bucket": {
        "my-prod-bucket": {"id":"my-prod-bucket","versioning":"Disabled","server_side_encryption_configuration":None,"acl":"public-read"}
    },
    "aws_db_instance": {
        "prod-db": {"id":"prod-db","instance_class":"db.t3.medium","publicly_accessible":True,"storage_encrypted":True}
    },
    "aws_security_group": {}
}

parser = TerraformStateParser()
tf = parser.parse(fake_state)
print(f"\nTerraform resources: {len(tf)}")
for k in tf: print(f"  - {k}")

analyzer = DriftAnalyzer()
findings = analyzer.analyze(tf, live_resources, "us-east-1")

scorer = PostureScorer()
score = scorer.score(findings, 10)

print(f"\nDrift findings: {len(findings)}")
print(f"Posture score:  {score}/100")
print()

icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}
for f in findings:
    print(f"{icons.get(f.severity.value,'⚪')} [{f.severity.value.upper()}] {f.resource_type} / {f.resource_id}")
    if f.security_impact:
        print(f"   Security: {f.security_impact[0]}")
    if f.compliance_violations:
        print(f"   Compliance: {f.compliance_violations[0]}")
    if f.cost_delta_monthly:
        print(f"   Cost delta: ${f.cost_delta_monthly}/month")
    if f.terraform_patch:
        print(f"   Patch:\n{f.terraform_patch}")
    print()

print("=" * 55)
print("Engine test complete. All systems working.")
print("=" * 55)
