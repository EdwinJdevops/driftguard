"""Provider-native drift evidence primitives.

The evidence core is intentionally independent from the legacy AWS collector
engine. Terraform/OpenTofu plan JSON is the source of drift semantics; cloud
APIs are enrichment sources, not truth substitutes.
"""

from .models import DriftEvidence, EvidenceBundle
from .terraform_plan import PlanEvidenceError, analyze_plan_json

__all__ = [
    "DriftEvidence",
    "EvidenceBundle",
    "PlanEvidenceError",
    "analyze_plan_json",
]
