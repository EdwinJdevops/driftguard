from __future__ import annotations
import json, hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class DriftType(str, Enum):
    ADDED = "added"
    DELETED = "deleted"
    MODIFIED = "modified"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class DriftResult:
    resource_type: str
    resource_id: str
    region: str
    drift_type: DriftType
    severity: Severity
    expected_state: dict
    actual_state: dict
    diff_summary: str
    security_impact: list
    compliance_violations: list
    cost_delta_monthly: float | None
    terraform_patch: str | None

class TerraformStateParser:
    def parse(self, state: dict) -> dict:
        resources = {}
        for r in state.get("resources", []):
            if r.get("mode") != "managed": continue
            for inst in r.get("instances", []):
                attrs = inst.get("attributes", {})
                key = f"{r['type']}.{r['name']}"
                resources[key] = {"type": r["type"], "name": r["name"], "id": attrs.get("id", key), "attributes": attrs}
        return resources

class DriftAnalyzer:
    def analyze(self, tf_resources, live_resources, region):
        findings = []
        live_flat = {}
        for rtype, instances in live_resources.items():
            for rid, attrs in instances.items():
                live_flat[f"{rtype}/{rid}"] = {"type": rtype, "id": rid, "attrs": attrs}

        for key, tf in tf_resources.items():
            rtype, rid = tf["type"], tf["id"]
            live_key = f"{rtype}/{rid}"
            if live_key not in live_flat:
                findings.append(self._build(rtype, rid, region, DriftType.DELETED, tf["attributes"], {}))
                continue
            diffs = {k: (tf["attributes"].get(k), live_flat[live_key]["attrs"].get(k))
                     for k in set(tf["attributes"]) | set(live_flat[live_key]["attrs"])
                     if tf["attributes"].get(k) != live_flat[live_key]["attrs"].get(k)
                     and k not in ("arn","id","tags_all")}
            if diffs:
                findings.append(self._build(rtype, rid, region, DriftType.MODIFIED, tf["attributes"], live_flat[live_key]["attrs"], diffs))
        return findings

    def _build(self, rtype, rid, region, dtype, expected, actual, diffs=None):
        diffs = diffs or {}
        security = self._security(rtype, diffs)
        compliance = self._compliance(rtype, diffs, actual)
        severity = self._severity(rtype, dtype, diffs, security)
        cost = self._cost(rtype, expected, actual, diffs)
        summary = self._summary(rtype, rid, dtype, diffs)
        patch = self._patch(rtype, rid, diffs)
        return DriftResult(rtype, rid, region, dtype, severity, expected, actual, summary, security, compliance, cost, patch)

    def _security(self, rtype, diffs):
        rules = {
            "aws_security_group": {"ingress": ["Security group inbound rules modified — verify no unintended public exposure"]},
            "aws_s3_bucket": {"server_side_encryption_configuration": ["S3 encryption changed — data at rest may be unprotected"],"versioning": ["S3 versioning disabled — data recovery capability reduced"]},
            "aws_db_instance": {"publicly_accessible": ["CRITICAL: RDS instance may be exposed to the internet"]},
            "aws_iam_role": {"assume_role_policy": ["IAM trust policy modified — verify no privilege escalation"]},
        }
        impacts = []
        for attr in diffs:
            for msg in rules.get(rtype, {}).get(attr, []):
                impacts.append(msg)
        return impacts

    def _compliance(self, rtype, diffs, actual):
        violations = []
        if rtype == "aws_db_instance" and actual.get("publicly_accessible"):
            violations.append("CIS AWS 2.3.2: RDS must not be publicly accessible")
        if rtype == "aws_s3_bucket" and not actual.get("server_side_encryption_configuration"):
            violations.append("CIS AWS 2.1.1: S3 bucket must be encrypted")
        return violations

    def _severity(self, rtype, dtype, diffs, security):
        if rtype in ("aws_iam_role", "aws_iam_policy"): return Severity.CRITICAL
        if rtype == "aws_db_instance" and diffs.get("publicly_accessible", (None,None))[1]: return Severity.CRITICAL
        if rtype == "aws_security_group" and ("ingress" in diffs or "egress" in diffs): return Severity.HIGH
        if dtype == DriftType.DELETED: return Severity.HIGH
        if security: return Severity.MEDIUM
        return Severity.LOW

    def _cost(self, rtype, expected, actual, diffs):
        costs = {"t3.micro":7.59,"t3.small":15.18,"t3.medium":30.37,"t3.large":60.74,"t3.xlarge":121.47,"m5.large":70.08}
        if rtype == "aws_instance" and "instance_type" in diffs:
            old, new = diffs["instance_type"]
            return round((costs.get(new,0) - costs.get(old,0)), 2)
        return None

    def _summary(self, rtype, rid, dtype, diffs):
        if dtype == DriftType.DELETED:
            return f"{rtype} ({rid}) exists in Terraform but was NOT found in AWS. Deleted manually."
        lines = [f"{rtype} ({rid}) has {len(diffs)} drifted attribute(s):"]
        for k,(ev,av) in list(diffs.items())[:8]:
            lines.append(f"  {k}: expected={json.dumps(ev)[:60]}  actual={json.dumps(av)[:60]}")
        return "\n".join(lines)

    def _patch(self, rtype, rid, diffs):
        if not diffs: return None
        lines = [f'# DriftGuard patch — restores Terraform-declared state', f'resource "{rtype}" "{rid}" {{']
        for attr,(ev,_) in diffs.items():
            if isinstance(ev, bool): lines.append(f'  {attr} = {str(ev).lower()}')
            elif isinstance(ev, (int,float)): lines.append(f'  {attr} = {ev}')
            elif isinstance(ev, str): lines.append(f'  {attr} = "{ev}"')
            else: lines.append(f'  # {attr} = <review manually>')
        lines.append("}")
        return "\n".join(lines)

class PostureScorer:
    def score(self, findings, total):
        if not total: return 100.0
        weights = {"critical":20,"high":10,"medium":4,"low":1}
        deductions = sum(weights.get(f.severity.value,1) + len(f.compliance_violations)*2 for f in findings)
        return round(max(0, 100 - deductions), 1)
