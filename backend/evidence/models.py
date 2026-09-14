from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

IaCEngine = Literal["terraform", "opentofu", "unknown"]


class DriftEvidence(BaseModel):
    """One provider-native drift observation with all raw values omitted."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["resource_drift"] = "resource_drift"
    resource_address: str = Field(min_length=1)
    module_address: str | None = None
    resource_type: str = Field(min_length=1)
    resource_name: str = Field(min_length=1)
    resource_index: str | int | None = None
    provider_name: str | None = None
    actions: list[str]
    changed_paths: list[str]
    sensitive_paths: list[str]


class EvidenceBundle(BaseModel):
    """Versioned, redacted output of DriftGuard plan adjudication."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    iac_engine: IaCEngine = "unknown"
    iac_engine_version: str | None = None
    source_format_version: str = Field(min_length=1)
    plan_timestamp: str | None = None
    redaction_policy: Literal["omit_change_values"] = "omit_change_values"
    findings: list[DriftEvidence]
    skipped_nonmanaged: int = Field(default=0, ge=0)

    @property
    def finding_count(self) -> int:
        return len(self.findings)
