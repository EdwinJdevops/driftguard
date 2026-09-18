from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

IaCEngine = Literal["terraform", "opentofu", "unknown"]


class CloudResourceLocator(BaseModel):
    """Non-sensitive cloud identity metadata used for optional enrichment."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["aws"]
    arn: str | None = None
    id: str | None = None
    name: str | None = None
    region: str | None = None

    @model_validator(mode="after")
    def require_identifier(self):
        if not any((self.arn, self.id, self.name)):
            raise ValueError("Cloud resource locator requires arn, id, or name.")
        return self


class DriftEvidence(BaseModel):
    """One provider-native drift observation with all raw values omitted."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["resource_drift"] = "resource_drift"
    resource_address: str = Field(min_length=1)
    previous_resource_address: str | None = None
    module_address: str | None = None
    deposed_key: str | None = None
    resource_type: str = Field(min_length=1)
    resource_name: str = Field(min_length=1)
    resource_index: str | int | None = None
    provider_name: str | None = None
    cloud_locator: CloudResourceLocator | None = None
    actions: list[str]
    changed_paths: list[str]
    sensitive_paths: list[str]
    unknown_paths: list[str]


class EvidenceBundle(BaseModel):
    """Versioned, redacted output of DriftGuard plan adjudication."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1"] = "1.1"
    iac_engine: IaCEngine = "unknown"
    iac_engine_version: str | None = None
    source_format_version: str = Field(min_length=1)
    plan_timestamp: str | None = None
    plan_applyable: bool | None = None
    plan_complete: bool | None = None
    redaction_policy: Literal["omit_change_values"] = "omit_change_values"
    findings: list[DriftEvidence]
    skipped_nonmanaged: int = Field(default=0, ge=0)

    @property
    def finding_count(self) -> int:
        return len(self.findings)
