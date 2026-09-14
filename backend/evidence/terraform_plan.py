from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import DriftEvidence, EvidenceBundle, IaCEngine


class PlanEvidenceError(ValueError):
    """Raised when plan JSON cannot be safely interpreted as evidence."""


_MISSING = object()


def analyze_plan_json(
    plan: Mapping[str, Any],
    *,
    iac_engine: IaCEngine = "unknown",
) -> EvidenceBundle:
    """Convert Terraform/OpenTofu plan JSON into a redacted evidence bundle.

    Drift semantics come exclusively from the plan's ``resource_drift``
    collection. DriftGuard does not infer remote drift by diffing arbitrary
    Terraform state attributes against partial cloud-API observations.

    Raw ``before`` and ``after`` values are used only in-process to identify
    changed JSON-pointer paths. They are never copied into the returned model.
    This is a hard boundary because ``terraform show -json`` can contain
    sensitive values in plaintext.
    """
    if not isinstance(plan, Mapping):
        raise PlanEvidenceError("Plan JSON must be an object.")

    format_version = plan.get("format_version")
    if not isinstance(format_version, str) or not format_version:
        raise PlanEvidenceError("Plan JSON is missing a valid format_version.")
    if format_version.split(".", 1)[0] != "1":
        raise PlanEvidenceError(
            f"Unsupported plan JSON major format version: {format_version}."
        )

    if plan.get("errored") is True:
        raise PlanEvidenceError(
            "Refusing to produce drift evidence from an errored plan because the observation may be incomplete."
        )

    resource_drift = plan.get("resource_drift", [])
    if not isinstance(resource_drift, list):
        raise PlanEvidenceError("resource_drift must be an array when present.")

    findings: list[DriftEvidence] = []
    skipped_nonmanaged = 0

    for position, raw in enumerate(resource_drift):
        if not isinstance(raw, Mapping):
            raise PlanEvidenceError(f"resource_drift[{position}] must be an object.")

        mode = raw.get("mode")
        if not isinstance(mode, str):
            raise PlanEvidenceError(f"resource_drift[{position}] is missing mode.")
        if mode != "managed":
            skipped_nonmanaged += 1
            continue

        address = _required_string(raw, "address", position)
        resource_type = _required_string(raw, "type", position)
        resource_name = _required_string(raw, "name", position)

        module_address = raw.get("module_address")
        if module_address is not None and not isinstance(module_address, str):
            raise PlanEvidenceError(
                f"resource_drift[{position}].module_address must be a string when present."
            )

        provider_name = raw.get("provider_name")
        if provider_name is not None and not isinstance(provider_name, str):
            raise PlanEvidenceError(
                f"resource_drift[{position}].provider_name must be a string when present."
            )

        resource_index = raw.get("index")
        if resource_index is not None and not isinstance(resource_index, (str, int)):
            raise PlanEvidenceError(
                f"resource_drift[{position}].index must be a string or integer when present."
            )

        change = raw.get("change")
        if not isinstance(change, Mapping):
            raise PlanEvidenceError(f"resource_drift[{position}] is missing change.")

        actions = change.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or any(not isinstance(action, str) for action in actions)
        ):
            raise PlanEvidenceError(
                f"resource_drift[{position}].change.actions must be a non-empty string array."
            )

        changed_paths = sorted(_diff_paths(change.get("before"), change.get("after")))
        sensitive_paths = sorted(
            _sensitive_paths(change.get("before_sensitive"))
            | _sensitive_paths(change.get("after_sensitive"))
        )

        findings.append(
            DriftEvidence(
                resource_address=address,
                module_address=module_address,
                resource_type=resource_type,
                resource_name=resource_name,
                resource_index=resource_index,
                provider_name=provider_name,
                actions=actions,
                changed_paths=changed_paths,
                sensitive_paths=sensitive_paths,
            )
        )

    engine_version = plan.get("terraform_version")
    if not isinstance(engine_version, str):
        engine_version = None

    plan_timestamp = plan.get("timestamp")
    if not isinstance(plan_timestamp, str):
        plan_timestamp = None

    return EvidenceBundle(
        iac_engine=iac_engine,
        iac_engine_version=engine_version,
        source_format_version=format_version,
        plan_timestamp=plan_timestamp,
        findings=findings,
        skipped_nonmanaged=skipped_nonmanaged,
    )


def _required_string(raw: Mapping[str, Any], key: str, position: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise PlanEvidenceError(f"resource_drift[{position}].{key} must be a non-empty string.")
    return value


def _pointer_child(pointer: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


def _diff_paths(before: Any, after: Any, pointer: str = "") -> set[str]:
    """Return changed paths as RFC 6901 JSON pointers without retaining values."""
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        changed: set[str] = set()
        for key in set(before) | set(after):
            child = _pointer_child(pointer, key)
            left = before.get(key, _MISSING)
            right = after.get(key, _MISSING)
            if left is _MISSING or right is _MISSING:
                changed.add(child)
            else:
                changed |= _diff_paths(left, right, child)
        return changed

    if isinstance(before, list) and isinstance(after, list):
        changed = set()
        for index in range(max(len(before), len(after))):
            child = _pointer_child(pointer, index)
            if index >= len(before) or index >= len(after):
                changed.add(child)
            else:
                changed |= _diff_paths(before[index], after[index], child)
        return changed

    if before != after:
        return {pointer}
    return set()


def _sensitive_paths(mask: Any, pointer: str = "") -> set[str]:
    """Collect sensitive locations from Terraform/OpenTofu sensitivity masks."""
    if mask is True:
        return {pointer}
    if mask in (False, None):
        return set()

    if isinstance(mask, Mapping):
        paths: set[str] = set()
        for key, value in mask.items():
            paths |= _sensitive_paths(value, _pointer_child(pointer, key))
        return paths

    if isinstance(mask, list):
        paths = set()
        for index, value in enumerate(mask):
            paths |= _sensitive_paths(value, _pointer_child(pointer, index))
        return paths

    raise PlanEvidenceError("Sensitive-value mask contains an unsupported shape.")
