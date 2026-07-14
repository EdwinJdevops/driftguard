"""
DriftGuard — Drift Detection Engine

Compares live AWS infrastructure state against Terraform state files.
Produces structured DriftResult objects with severity, security impact,
cost delta, and a suggested Terraform patch for auto-PR creation.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import boto3
import structlog

log = structlog.get_logger(__name__)


class DriftType(str, Enum):
    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DriftResult:
    resource_type: str
    resource_id: str
    resource_name: str | None
    region: str
    drift_type: DriftType
    severity: Severity
    expected_state: dict[str, Any]
    actual_state: dict[str, Any]
    diff_summary: str
    security_impact: list[str]
    compliance_violations: list[str]
    cost_delta_monthly: float | None
    terraform_patch: str | None
    fingerprint: str = field(init=False)

    def __post_init__(self):
        raw = f"{self.resource_type}:{self.resource_id}:{json.dumps(self.actual_state, sort_keys=True, default=str)}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]


SECURITY_RULES: dict[str, dict[str, list[str]]] = {
    "aws_security_group": {
        "ingress": ["Security group inbound rules modified — verify no unintended public exposure"],
        "egress": ["Security group outbound rules modified — potential data exfiltration risk"],
    },
    "aws_s3_bucket": {
        "acl": ["S3 bucket ACL changed — verify public access is not enabled"],
        "versioning": ["S3 versioning disabled — data recovery capability reduced"],
        "server_side_encryption_configuration": [
            "S3 encryption config changed — verify data at rest is still encrypted",
        ],
        "logging": ["S3 access logging modified — audit trail may be incomplete"],
    },
    "aws_iam_role": {
        "assume_role_policy": [
            "IAM trust policy modified — verify principal access has not been over-permissioned",
        ],
    },
    "aws_iam_policy": {
        "policy": ["IAM policy document changed — review for privilege escalation or wildcard permissions"],
    },
    "aws_instance": {
        "vpc_security_group_ids": ["EC2 security groups modified — verify network exposure is unchanged"],
        "iam_instance_profile": ["EC2 IAM instance profile changed — verify attached role permissions"],
    },
    "aws_db_instance": {
        "publicly_accessible": [
            "CRITICAL: RDS instance public accessibility changed — database may be exposed to the internet",
        ],
        "storage_encrypted": ["RDS storage encryption changed — data at rest protection status modified"],
    },
    "aws_eks_cluster": {
        "endpoint_public_access": ["EKS API server public access configuration changed"],
    },
}

EC2_MONTHLY_COSTS: dict[str, float] = {
    "t2.micro": 8.47, "t2.small": 16.94, "t2.medium": 33.87,
    "t3.micro": 7.59, "t3.small": 15.18, "t3.medium": 30.37,
    "t3.large": 60.74, "t3.xlarge": 121.47,
    "m5.large": 70.08, "m5.xlarge": 140.16, "m5.2xlarge": 280.32,
    "c5.large": 62.05, "c5.xlarge": 124.10,
    "r5.large": 91.25, "r5.xlarge": 182.50,
}

NAT_GATEWAY_MONTHLY_COST = 32.0


class TerraformStateParser:
    """Parses a terraform.tfstate file into a flat resource map."""

    def parse(self, state_content: dict) -> dict[str, dict]:
        resources: dict[str, dict] = {}
        for resource in state_content.get("resources", []):
            if resource.get("mode") != "managed":
                continue
            rtype = resource["type"]
            rname = resource["name"]
            for instance in resource.get("instances", []):
                attrs = instance.get("attributes", {})
                rid = attrs.get("id") or f"{rtype}.{rname}"
                key = f"{rtype}.{rname}"
                resources[key] = {"type": rtype, "name": rname, "id": rid, "attributes": attrs}
        return resources


class AWSStateCollector:
    """Fetches live resource state from AWS APIs."""

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region

    def collect_ec2_instances(self) -> dict[str, dict]:
        ec2 = self.session.client("ec2", region_name=self.region)
        resources = {}
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance.get("State", {}).get("Name") == "terminated":
                            continue
                        iid = instance["InstanceId"]
                        resources[iid] = {
                            "id": iid,
                            "instance_type": instance.get("InstanceType"),
                            "vpc_security_group_ids": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                            "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
                        }
        except Exception as e:
            log.error("Failed to collect EC2 instances", error=str(e))
        return resources

    def collect_s3_buckets(self) -> dict[str, dict]:
        s3 = self.session.client("s3")
        resources = {}
        try:
            response = s3.list_buckets()
            for bucket in response.get("Buckets", []):
                name = bucket["Name"]
                data: dict[str, Any] = {"id": name}
                try:
                    v = s3.get_bucket_versioning(Bucket=name)
                    data["versioning"] = v.get("Status", "Disabled")
                except Exception:
                    pass
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    data["server_side_encryption_configuration"] = enc.get("ServerSideEncryptionConfiguration")
                except Exception:
                    data["server_side_encryption_configuration"] = None
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    is_public = any(
                        "AllUsers" in g.get("Grantee", {}).get("URI", "")
                        for g in acl.get("Grants", [])
                    )
                    data["acl"] = "public-read" if is_public else "private"
                except Exception:
                    pass
                resources[name] = data
        except Exception as e:
            log.error("Failed to collect S3 buckets", error=str(e))
        return resources

    def collect_security_groups(self) -> dict[str, dict]:
        ec2 = self.session.client("ec2", region_name=self.region)
        resources = {}
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sgid = sg["GroupId"]
                    resources[sgid] = {
                        "id": sgid,
                        "ingress": sg.get("IpPermissions", []),
                        "egress": sg.get("IpPermissionsEgress", []),
                    }
        except Exception as e:
            log.error("Failed to collect security groups", error=str(e))
        return resources

    def collect_rds_instances(self) -> dict[str, dict]:
        rds = self.session.client("rds", region_name=self.region)
        resources = {}
        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    dbid = db["DBInstanceIdentifier"]
                    resources[dbid] = {
                        "id": dbid,
                        "instance_class": db.get("DBInstanceClass"),
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                    }
        except Exception as e:
            log.error("Failed to collect RDS instances", error=str(e))
        return resources

    def collect_all(self) -> dict[str, dict[str, dict]]:
        return {
            "aws_instance": self.collect_ec2_instances(),
            "aws_s3_bucket": self.collect_s3_buckets(),
            "aws_security_group": self.collect_security_groups(),
            "aws_db_instance": self.collect_rds_instances(),
        }


class DriftAnalyzer:
    """Core drift analysis engine."""

    SKIP_KEYS = {"arn", "id", "tags_all", "tags", "last_modified", "created_time"}

    def analyze(
        self,
        tf_resources: dict[str, dict],
        live_resources: dict[str, dict[str, dict]],
        region: str,
    ) -> list[DriftResult]:
        findings: list[DriftResult] = []

        live_flat: dict[str, dict] = {}
        for rtype, instances in live_resources.items():
            for rid, attrs in instances.items():
                live_flat[f"{rtype}/{rid}"] = {"type": rtype, "id": rid, "attrs": attrs}

        for tf_key, tf_resource in tf_resources.items():
            rtype, rid, rname = tf_resource["type"], tf_resource["id"], tf_resource["name"]
            tf_attrs = tf_resource["attributes"]
            live_key = f"{rtype}/{rid}"

            if live_key not in live_flat:
                findings.append(self._build_finding(
                    rtype, rid, rname, region, DriftType.DELETED, tf_attrs, {}
                ))
                continue

            live_attrs = live_flat[live_key]["attrs"]
            diffs = self._compute_diff(tf_attrs, live_attrs)
            if diffs:
                findings.append(self._build_finding(
                    rtype, rid, rname, region, DriftType.MODIFIED, tf_attrs, live_attrs, diffs
                ))

        tf_ids = {r["id"] for r in tf_resources.values()}
        for live_key, live_info in live_flat.items():
            if live_info["id"] not in tf_ids:
                findings.append(self._build_finding(
                    live_info["type"], live_info["id"], None, region,
                    DriftType.ADDED, {}, live_info["attrs"]
                ))

        return findings

    def _compute_diff(self, expected: dict, actual: dict) -> dict[str, tuple]:
        diffs = {}
        all_keys = (set(expected.keys()) | set(actual.keys())) - self.SKIP_KEYS
        for key in all_keys:
            ev, av = expected.get(key), actual.get(key)
            if ev != av:
                diffs[key] = (ev, av)
        return diffs

    def _build_finding(
        self, rtype, rid, rname, region, drift_type, expected, actual, diffs=None,
    ) -> DriftResult:
        diffs = diffs or {}
        security_impact = self._assess_security_impact(rtype, diffs)
        severity = self._calculate_severity(rtype, drift_type, diffs, security_impact)
        cost_delta = self._estimate_cost_delta(rtype, drift_type, diffs)
        diff_summary = self._generate_diff_summary(rtype, rid, drift_type, diffs)
        terraform_patch = self._generate_terraform_patch(rtype, rname or rid, diffs)
        compliance = self._check_compliance(rtype, actual)

        return DriftResult(
            resource_type=rtype, resource_id=rid, resource_name=rname, region=region,
            drift_type=drift_type, severity=severity, expected_state=expected,
            actual_state=actual, diff_summary=diff_summary, security_impact=security_impact,
            compliance_violations=compliance, cost_delta_monthly=cost_delta,
            terraform_patch=terraform_patch,
        )

    def _assess_security_impact(self, rtype: str, diffs: dict) -> list[str]:
        impacts = []
        rules = SECURITY_RULES.get(rtype, {})
        for attr in diffs:
            impacts.extend(rules.get(attr, []))
        return list(dict.fromkeys(impacts))  # dedupe, preserve order

    def _check_compliance(self, rtype: str, actual: dict) -> list[str]:
        violations = []
        if rtype == "aws_s3_bucket":
            if actual.get("server_side_encryption_configuration") is None:
                violations.append("CIS AWS 2.1.1: Ensure S3 bucket is encrypted")
            if actual.get("versioning") == "Disabled":
                violations.append("CIS AWS 2.1.3: Ensure S3 bucket versioning is enabled")
        if rtype == "aws_db_instance":
            if actual.get("publicly_accessible"):
                violations.append("CIS AWS 2.3.2: Ensure RDS instances are not publicly accessible")
            if not actual.get("storage_encrypted"):
                violations.append("CIS AWS 2.3.1: Ensure RDS instances are encrypted")
        if rtype == "aws_security_group":
            for rule in actual.get("ingress", []):
                ranges = rule.get("IpRanges", []) + rule.get("Ipv6Ranges", [])
                for r in ranges:
                    cidr = r.get("CidrIp") or r.get("CidrIpv6", "")
                    if cidr in ("0.0.0.0/0", "::/0") and rule.get("FromPort") in (22, 3389):
                        port = rule.get("FromPort")
                        violations.append(
                            f"CIS AWS 4.{'1' if port == 22 else '2'}: "
                            f"Restrict {'SSH' if port == 22 else 'RDP'} access from 0.0.0.0/0"
                        )
        return violations

    def _calculate_severity(self, rtype, drift_type, diffs, security_impact) -> Severity:
        if rtype in ("aws_iam_role", "aws_iam_policy") and diffs:
            return Severity.CRITICAL
        if rtype == "aws_db_instance" and diffs.get("publicly_accessible", (None, None))[1]:
            return Severity.CRITICAL
        if rtype == "aws_security_group" and ("ingress" in diffs or "egress" in diffs):
            return Severity.HIGH
        if drift_type == DriftType.DELETED:
            return Severity.HIGH
        if drift_type == DriftType.ADDED:
            return Severity.MEDIUM
        if security_impact:
            return Severity.MEDIUM
        return Severity.LOW

    def _estimate_cost_delta(self, rtype, drift_type, diffs) -> float | None:
        if rtype == "aws_instance" and "instance_type" in diffs:
            old_type, new_type = diffs["instance_type"]
            old_cost = EC2_MONTHLY_COSTS.get(old_type, 0)
            new_cost = EC2_MONTHLY_COSTS.get(new_type, 0)
            if old_cost or new_cost:
                return round(new_cost - old_cost, 2)
        if rtype == "aws_nat_gateway":
            if drift_type == DriftType.ADDED:
                return NAT_GATEWAY_MONTHLY_COST
            if drift_type == DriftType.DELETED:
                return -NAT_GATEWAY_MONTHLY_COST
        return None

    def _generate_diff_summary(self, rtype, rid, drift_type, diffs) -> str:
        if drift_type == DriftType.DELETED:
            return f"Resource {rtype} ({rid}) exists in Terraform state but was not found in AWS. Possibly deleted manually."
        if drift_type == DriftType.ADDED:
            return f"Resource {rtype} ({rid}) exists in AWS but is not tracked in Terraform state."
        if not diffs:
            return f"Resource {rtype} ({rid}) has unresolvable drift."
        lines = [f"Resource {rtype} ({rid}) has {len(diffs)} attribute(s) that differ:\n"]
        for attr, (ev, av) in list(diffs.items())[:10]:
            lines.append(f"  • {attr}: expected={json.dumps(ev, default=str)[:100]} actual={json.dumps(av, default=str)[:100]}")
        return "\n".join(lines)

    def _generate_terraform_patch(self, rtype, rname, diffs) -> str | None:
        if not diffs:
            return None
        lines = ['# DriftGuard patch — restores declared state', f'resource "{rtype}" "{rname}" {{']
        for attr, (expected_val, _) in diffs.items():
            if expected_val is None:
                continue
            if isinstance(expected_val, bool):
                lines.append(f'  {attr} = {str(expected_val).lower()}')
            elif isinstance(expected_val, (int, float)):
                lines.append(f'  {attr} = {expected_val}')
            elif isinstance(expected_val, str):
                lines.append(f'  {attr} = "{expected_val}"')
            else:
                lines.append(f'  # {attr} = <complex value — review manually>')
        lines.append("}")
        return "\n".join(lines)


class PostureScorer:
    """Calculates a 0-100 security posture score for the workspace."""

    WEIGHTS = {
        Severity.CRITICAL: 20.0, Severity.HIGH: 10.0,
        Severity.MEDIUM: 4.0, Severity.LOW: 1.0, Severity.INFO: 0.2,
    }

    def score(self, findings: list[DriftResult], total_resources: int) -> float:
        if total_resources == 0:
            return 100.0
        deductions = sum(
            self.WEIGHTS.get(f.severity, 1.0) + len(f.compliance_violations) * 2.0
            for f in findings
        )
        return round(max(0, 100 - deductions), 1)
