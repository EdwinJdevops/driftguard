"""
DriftGuard — Drift Engine Test Suite

Run: pytest backend/tests/test_drift_engine.py -v
"""

import pytest
from backend.engines.drift import (
    TerraformStateParser,
    DriftAnalyzer,
    PostureScorer,
    DriftType,
    Severity,
)


# ── FIXTURES ─────────────────────────────────────────────────────────────

@pytest.fixture
def parser():
    return TerraformStateParser()


@pytest.fixture
def analyzer():
    return DriftAnalyzer()


@pytest.fixture
def scorer():
    return PostureScorer()


@pytest.fixture
def clean_tfstate():
    return {
        "version": 4,
        "resources": [
            {
                "mode": "managed", "type": "aws_instance", "name": "web",
                "instances": [{"attributes": {
                    "id": "i-0abc123", "instance_type": "t3.micro",
                    "vpc_security_group_ids": ["sg-111"],
                }}],
            },
            {
                "mode": "managed", "type": "aws_s3_bucket", "name": "data",
                "instances": [{"attributes": {
                    "id": "my-bucket", "versioning": "Enabled",
                    "server_side_encryption_configuration": {"rule": "AES256"},
                    "acl": "private",
                }}],
            },
            {
                "mode": "managed", "type": "aws_db_instance", "name": "prod_db",
                "instances": [{"attributes": {
                    "id": "prod-db", "instance_class": "db.t3.medium",
                    "publicly_accessible": False, "storage_encrypted": True,
                }}],
            },
        ],
    }


# ── PARSER TESTS ─────────────────────────────────────────────────────────

def test_parser_extracts_managed_resources(parser, clean_tfstate):
    result = parser.parse(clean_tfstate)
    assert len(result) == 3
    assert "aws_instance.web" in result
    assert result["aws_instance.web"]["id"] == "i-0abc123"


def test_parser_ignores_data_sources(parser):
    state = {
        "resources": [
            {"mode": "data", "type": "aws_ami", "name": "latest", "instances": []},
            {"mode": "managed", "type": "aws_instance", "name": "web",
             "instances": [{"attributes": {"id": "i-1"}}]},
        ]
    }
    result = parser.parse(state)
    assert len(result) == 1
    assert "aws_instance.web" in result


def test_parser_handles_empty_state(parser):
    result = parser.parse({"resources": []})
    assert result == {}


def test_parser_handles_missing_resources_key(parser):
    result = parser.parse({})
    assert result == {}


# ── DRIFT DETECTION — NO DRIFT ───────────────────────────────────────────

def test_no_drift_when_states_match(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.micro", "vpc_security_group_ids": ["sg-111"]}},
        "aws_s3_bucket": {"my-bucket": {"id": "my-bucket", "versioning": "Enabled", "server_side_encryption_configuration": {"rule": "AES256"}, "acl": "private"}},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": False, "storage_encrypted": True}},
        "aws_security_group": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    assert len(findings) == 0


# ── DRIFT DETECTION — MODIFIED RESOURCES ────────────────────────────────

def test_detects_ec2_instance_type_drift(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.large", "vpc_security_group_ids": ["sg-111"]}},
        "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    ec2_findings = [f for f in findings if f.resource_type == "aws_instance"]
    assert len(ec2_findings) == 1
    assert ec2_findings[0].drift_type == DriftType.MODIFIED
    assert "instance_type" in str(ec2_findings[0].diff_summary)


def test_ec2_instance_type_drift_calculates_cost_delta(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.large", "vpc_security_group_ids": ["sg-111"]}},
        "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    ec2_finding = next(f for f in findings if f.resource_type == "aws_instance")
    # t3.large (60.74) - t3.micro (7.59) = 53.15
    assert ec2_finding.cost_delta_monthly == pytest.approx(53.15, abs=0.01)


def test_rds_made_public_is_critical_severity(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {}, "aws_s3_bucket": {}, "aws_security_group": {},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": True, "storage_encrypted": True}},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    db_finding = next(f for f in findings if f.resource_type == "aws_db_instance")
    assert db_finding.severity == Severity.CRITICAL
    assert any("CIS AWS 2.3.2" in v for v in db_finding.compliance_violations)


def test_s3_encryption_removed_flags_compliance_violation(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {}, "aws_db_instance": {}, "aws_security_group": {},
        "aws_s3_bucket": {"my-bucket": {"id": "my-bucket", "versioning": "Enabled", "server_side_encryption_configuration": None, "acl": "private"}},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    s3_finding = next(f for f in findings if f.resource_type == "aws_s3_bucket")
    assert any("CIS AWS 2.1.1" in v for v in s3_finding.compliance_violations)
    assert len(s3_finding.security_impact) > 0


def test_s3_versioning_disabled_detected(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {}, "aws_db_instance": {}, "aws_security_group": {},
        "aws_s3_bucket": {"my-bucket": {"id": "my-bucket", "versioning": "Disabled", "server_side_encryption_configuration": {"rule": "AES256"}, "acl": "private"}},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    s3_finding = next(f for f in findings if f.resource_type == "aws_s3_bucket")
    assert any("CIS AWS 2.1.3" in v for v in s3_finding.compliance_violations)


# ── DRIFT DETECTION — DELETED / ADDED RESOURCES ─────────────────────────

def test_resource_deleted_outside_terraform(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {},  # i-0abc123 missing — deleted outside Terraform
        "aws_s3_bucket": {"my-bucket": {"id": "my-bucket", "versioning": "Enabled", "server_side_encryption_configuration": {"rule": "AES256"}, "acl": "private"}},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": False, "storage_encrypted": True}},
        "aws_security_group": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    deleted = [f for f in findings if f.drift_type == DriftType.DELETED]
    assert len(deleted) == 1
    assert deleted[0].resource_id == "i-0abc123"
    assert deleted[0].severity == Severity.HIGH


def test_resource_added_outside_terraform(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {
            "i-0abc123": {"id": "i-0abc123", "instance_type": "t3.micro", "vpc_security_group_ids": ["sg-111"]},
            "i-shadow999": {"id": "i-shadow999", "instance_type": "t3.medium", "vpc_security_group_ids": []},
        },
        "aws_s3_bucket": {"my-bucket": {"id": "my-bucket", "versioning": "Enabled", "server_side_encryption_configuration": {"rule": "AES256"}, "acl": "private"}},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": False, "storage_encrypted": True}},
        "aws_security_group": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    added = [f for f in findings if f.drift_type == DriftType.ADDED]
    assert len(added) == 1
    assert added[0].resource_id == "i-shadow999"
    assert added[0].severity == Severity.MEDIUM


# ── SECURITY GROUP RULES ────────────────────────────────────────────────

def test_security_group_open_ssh_flags_cis_violation(analyzer):
    tf_resources = {
        "aws_security_group.web": {"type": "aws_security_group", "name": "web", "id": "sg-001", "attributes": {"id": "sg-001", "ingress": []}}
    }
    live_resources = {
        "aws_security_group": {"sg-001": {
            "id": "sg-001",
            "ingress": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }},
        "aws_instance": {}, "aws_s3_bucket": {}, "aws_db_instance": {},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    sg_finding = next(f for f in findings if f.resource_type == "aws_security_group")
    assert sg_finding.severity == Severity.HIGH
    assert any("CIS AWS 4.1" in v for v in sg_finding.compliance_violations)


# ── TERRAFORM PATCH GENERATION ──────────────────────────────────────────

def test_patch_generated_for_modified_resource(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {}, "aws_s3_bucket": {}, "aws_security_group": {},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": True, "storage_encrypted": True}},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    db_finding = next(f for f in findings if f.resource_type == "aws_db_instance")
    assert db_finding.terraform_patch is not None
    assert 'resource "aws_db_instance"' in db_finding.terraform_patch
    assert "publicly_accessible = false" in db_finding.terraform_patch


def test_no_patch_generated_for_deleted_resource(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {"aws_instance": {}, "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {}}
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    deleted = next(f for f in findings if f.drift_type == DriftType.DELETED and f.resource_type == "aws_instance")
    assert deleted.terraform_patch is None


# ── POSTURE SCORER ───────────────────────────────────────────────────────

def test_posture_score_100_when_no_findings(scorer):
    assert scorer.score([], 10) == 100.0


def test_posture_score_100_when_zero_resources(scorer):
    assert scorer.score([], 0) == 100.0


def test_posture_score_decreases_with_critical_finding(analyzer, parser, clean_tfstate, scorer):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {}, "aws_s3_bucket": {}, "aws_security_group": {},
        "aws_db_instance": {"prod-db": {"id": "prod-db", "instance_class": "db.t3.medium", "publicly_accessible": True, "storage_encrypted": True}},
    }
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    score = scorer.score(findings, 10)
    assert score < 100.0
    assert score >= 0.0


def test_posture_score_never_negative(scorer, analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    # Maximum possible drift — everything missing
    live_resources = {"aws_instance": {}, "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {}}
    findings = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    score = scorer.score(findings, 3)
    assert score >= 0.0


# ── FINGERPRINT (used for dedup across scans) ───────────────────────────

def test_fingerprint_is_deterministic(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_resources = {
        "aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.large", "vpc_security_group_ids": ["sg-111"]}},
        "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {},
    }
    findings1 = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    findings2 = analyzer.analyze(tf_resources, live_resources, "us-east-1")
    assert findings1[0].fingerprint == findings2[0].fingerprint


def test_fingerprint_differs_for_different_drift(analyzer, parser, clean_tfstate):
    tf_resources = parser.parse(clean_tfstate)
    live_a = {"aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.large", "vpc_security_group_ids": ["sg-111"]}}, "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {}}
    live_b = {"aws_instance": {"i-0abc123": {"id": "i-0abc123", "instance_type": "t3.xlarge", "vpc_security_group_ids": ["sg-111"]}}, "aws_s3_bucket": {}, "aws_db_instance": {}, "aws_security_group": {}}
    f1 = analyzer.analyze(tf_resources, live_a, "us-east-1")[0]
    f2 = analyzer.analyze(tf_resources, live_b, "us-east-1")[0]
    assert f1.fingerprint != f2.fingerprint
