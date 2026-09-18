from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import CloudResourceLocator, DriftEvidence, EvidenceBundle, IaCEngine


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

    # A Terraform/OpenTofu state JSON document also has format_version and
    # terraform_version, but plan representations include an explicit boolean
    # `errored` field. Requiring it prevents a state file from being silently
    # interpreted as a clean plan with no resource_drift entries.
    errored = plan.get("errored")
    if not isinstance(errored, bool):
        raise PlanEvidenceError(
            "Input is not a plan representation: expected boolean plan field 'errored'."
        )
    if errored:
        raise PlanEvidenceError(
            "Refusing to produce drift evidence from an errored plan because the observation may be incomplete."
        )

    applyable = _optional_bool(plan, "applyable")
    complete = _optional_bool(plan, "complete")

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

        previous_address = _optional_string(raw, "previous_address", position)
        module_address = _optional_string(raw, "module_address", position)
        deposed_key = _optional_string(raw, "deposed", position)
        provider_name = _optional_string(raw, "provider_name", position)

        resource_index = raw.get("index")
        if resource_index is not None and (
            isinstance(resource_index, bool)
            or not isinstance(resource_index, (str, int))
        ):
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
            _mask_paths(change.get("before_sensitive"), "sensitive-value")
            | _mask_paths(change.get("after_sensitive"), "sensitive-value")
        )
        unknown_paths = sorted(
            _mask_paths(change.get("after_unknown"), "unknown-value")
        )
        cloud_locator = _extract_cloud_locator(
            provider_name=provider_name,
            change=change,
            blocked_paths=set(sensitive_paths) | set(unknown_paths),
        )

        findings.append(
            DriftEvidence(
                resource_address=address,
                previous_resource_address=previous_address,
                module_address=module_address,
                deposed_key=deposed_key,
                resource_type=resource_type,
                resource_name=resource_name,
                resource_index=resource_index,
                provider_name=provider_name,
                cloud_locator=cloud_locator,
                actions=actions,
                changed_paths=changed_paths,
                sensitive_paths=sensitive_paths,
                unknown_paths=unknown_paths,
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
        plan_applyable=applyable,
        plan_complete=complete,
        findings=findings,
        skipped_nonmanaged=skipped_nonmanaged,
    )


def _optional_bool(raw: Mapping[str, Any], key: str) -> bool | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise PlanEvidenceError(f"Plan field '{key}' must be boolean when present.")
    return value


def _required_string(raw: Mapping[str, Any], key: str, position: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise PlanEvidenceError(f"resource_drift[{position}].{key} must be a non-empty string.")
    return value


def _optional_string(raw: Mapping[str, Any], key: str, position: int) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise PlanEvidenceError(
            f"resource_drift[{position}].{key} must be a non-empty string when present."
        )
    return value


def _pointer_child(pointer: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


def _diff_paths(before: Any, after: Any, pointer: str = "") -> set[str]:
    """Return changed paths as RFC 6901 JSON pointers without retaining values.

    JSON plan output loses the distinction between Terraform/OpenTofu lists,
    sets, and tuples: all three lower to JSON arrays. Without provider schema,
    numeric array indexes can therefore create false precision (especially for
    sets whose ordering is not semantic). If an array changes, v1 reports its
    parent path rather than inventing element-level identity.
    """
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
        return {pointer} if before != after else set()

    if before != after:
        return {pointer}
    return set()


def _mask_paths(mask: Any, label: str, pointer: str = "") -> set[str]:
    """Collect true locations from Terraform/OpenTofu boolean-shape masks."""
    if mask is True:
        return {pointer}
    if mask in (False, None):
        return set()

    if isinstance(mask, Mapping):
        paths: set[str] = set()
        for key, value in mask.items():
            paths |= _mask_paths(value, label, _pointer_child(pointer, key))
        return paths

    if isinstance(mask, list):
        paths = set()
        for index, value in enumerate(mask):
            paths |= _mask_paths(value, label, _pointer_child(pointer, index))
        return paths

    raise PlanEvidenceError(f"{label.capitalize()} mask contains an unsupported shape.")


def _extract_cloud_locator(
    *,
    provider_name: str | None,
    change: Mapping[str, Any],
    blocked_paths: set[str],
) -> CloudResourceLocator | None:
    """Extract only well-known, non-sensitive AWS identity metadata.

    This function is intentionally conservative. It does not copy arbitrary
    provider state into evidence and it refuses any candidate field covered by
    Terraform/OpenTofu sensitive or unknown masks.
    """
    if provider_name != "registry.terraform.io/hashicorp/aws":
        return None
    if "" in blocked_paths:
        return None

    before = change.get("before")
    after = change.get("after")

    def pick(field: str) -> str | None:
        if _pointer_child("", field) in blocked_paths:
            return None
        for candidate in (after, before):
            if not isinstance(candidate, Mapping):
                continue
            value = candidate.get(field)
            if isinstance(value, str) and value:
                return value
        return None

    arn = pick("arn")
    resource_id = pick("id")
    name = pick("name")
    region = pick("region")
    if not any((arn, resource_id, name)):
        return None

    return CloudResourceLocator(
        provider="aws",
        arn=arn,
        id=resource_id,
        name=name,
        region=region,
    )
