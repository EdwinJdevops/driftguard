"""Provider-native drift evidence primitives.

The evidence core is intentionally independent from the legacy AWS collector
engine. Terraform/OpenTofu plan JSON is the source of drift semantics; cloud
APIs are enrichment sources, not truth substitutes.
"""

from .attribution import (
    AttributionResult,
    AuditEventMatch,
    attribute_aws_drift,
)
from .models import CloudResourceLocator, DriftEvidence, EvidenceBundle
from .terraform_plan import PlanEvidenceError, analyze_plan_json

__all__ = [
    "AttributionResult",
    "AuditEventMatch",
    "CloudResourceLocator",
    "DriftEvidence",
    "EvidenceBundle",
    "PlanEvidenceError",
    "analyze_plan_json",
    "attribute_aws_drift",
]
