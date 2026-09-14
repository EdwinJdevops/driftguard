from __future__ import annotations

import pytest

from backend.evidence import PlanEvidenceError, analyze_plan_json


def _plan(*drift: dict, **overrides) -> dict:
    plan = {
        "format_version": "1.2",
        "terraform_version": "1.16.2",
        "timestamp": "2026-09-14T10:00:00Z",
        "applyable": True,
        "complete": True,
        "errored": False,
        "resource_drift": list(drift),
    }
    plan.update(overrides)
    return plan


def _drift(
    *,
    address: str = 'module.compute.aws_instance.web["blue"]',
    mode: str = "managed",
    before: object | None = None,
    after: object | None = None,
    before_sensitive: object | None = None,
    after_sensitive: object | None = None,
    after_unknown: object | None = None,
    actions: list[str] | None = None,
    previous_address: str | None = None,
    deposed: str | None = None,
) -> dict:
    raw = {
        "address": address,
        "module_address": "module.compute",
        "mode": mode,
        "type": "aws_instance",
        "name": "web",
        "index": "blue",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {
            "actions": actions or ["update"],
            "before": before if before is not None else {"instance_type": "t3.micro"},
            "after": after if after is not None else {"instance_type": "t3.large"},
            "before_sensitive": before_sensitive if before_sensitive is not None else {},
            "after_sensitive": after_sensitive if after_sensitive is not None else {},
            "after_unknown": after_unknown if after_unknown is not None else {},
        },
    }
    if previous_address is not None:
        raw["previous_address"] = previous_address
    if deposed is not None:
        raw["deposed"] = deposed
    return raw


def test_preserves_absolute_resource_identity_from_plan_json():
    bundle = analyze_plan_json(_plan(_drift()), iac_engine="terraform")

    assert bundle.finding_count == 1
    finding = bundle.findings[0]
    assert finding.resource_address == 'module.compute.aws_instance.web["blue"]'
    assert finding.module_address == "module.compute"
    assert finding.resource_index == "blue"
    assert finding.provider_name == "registry.terraform.io/hashicorp/aws"
    assert bundle.plan_applyable is True
    assert bundle.plan_complete is True


def test_preserves_previous_address_and_deposed_object_identity():
    drift = _drift(
        previous_address='module.old.aws_instance.web["blue"]',
        deposed="deadbeef",
    )

    finding = analyze_plan_json(_plan(drift)).findings[0]

    assert finding.previous_resource_address == 'module.old.aws_instance.web["blue"]'
    assert finding.deposed_key == "deadbeef"


def test_emits_changed_paths_without_persisting_raw_values():
    secret_before = "super-secret-before"
    secret_after = "super-secret-after"
    plan = _plan(
        _drift(
            before={"instance_type": "t3.micro", "password": secret_before},
            after={"instance_type": "t3.large", "password": secret_after},
            before_sensitive={"password": True},
            after_sensitive={"password": True},
        )
    )

    bundle = analyze_plan_json(plan)
    finding = bundle.findings[0]

    assert finding.changed_paths == ["/instance_type", "/password"]
    assert finding.sensitive_paths == ["/password"]

    serialized = bundle.model_dump_json()
    assert secret_before not in serialized
    assert secret_after not in serialized
    assert "t3.micro" not in serialized
    assert "t3.large" not in serialized


def test_changed_paths_use_json_pointer_escaping():
    plan = _plan(
        _drift(
            before={"tags": {"team/name~legacy": "platform"}},
            after={"tags": {"team/name~legacy": "security"}},
        )
    )

    finding = analyze_plan_json(plan).findings[0]
    assert finding.changed_paths == ["/tags/team~1name~0legacy"]


def test_array_changes_collapse_to_parent_path_without_provider_schema():
    plan = _plan(
        _drift(
            before={"rules": [{"name": "a"}, {"name": "b"}]},
            after={"rules": [{"name": "b"}, {"name": "a"}]},
        )
    )

    finding = analyze_plan_json(plan).findings[0]

    assert finding.changed_paths == ["/rules"]
    assert "/rules/0/name" not in finding.changed_paths


def test_unknown_value_mask_is_preserved_without_exposing_values():
    plan = _plan(
        _drift(
            before={"endpoint": "old.example"},
            after={"endpoint": None},
            after_unknown={"endpoint": True},
        )
    )

    finding = analyze_plan_json(plan).findings[0]

    assert finding.changed_paths == ["/endpoint"]
    assert finding.unknown_paths == ["/endpoint"]


def test_whole_resource_deletion_is_root_pointer_change():
    drift = _drift(
        before={"id": "i-123", "instance_type": "t3.micro"},
        after=None,
        actions=["delete"],
    )
    # Explicitly override the helper's None fallback.
    drift["change"]["after"] = None

    finding = analyze_plan_json(_plan(drift)).findings[0]

    assert finding.actions == ["delete"]
    assert finding.changed_paths == [""]


def test_nonmanaged_entries_are_not_adjudicated_as_managed_drift():
    bundle = analyze_plan_json(_plan(_drift(mode="data")))

    assert bundle.findings == []
    assert bundle.skipped_nonmanaged == 1


def test_refuses_state_json_instead_of_reporting_false_clean_plan():
    state = {
        "format_version": "1.0",
        "terraform_version": "1.16.2",
        "values": {"root_module": {"resources": []}},
    }

    with pytest.raises(PlanEvidenceError, match="not a plan representation"):
        analyze_plan_json(state)


def test_refuses_errored_plan_as_incomplete_evidence():
    with pytest.raises(PlanEvidenceError, match="errored plan"):
        analyze_plan_json(_plan(_drift(), errored=True))


def test_refuses_unknown_major_plan_format():
    with pytest.raises(PlanEvidenceError, match="Unsupported plan JSON major"):
        analyze_plan_json(_plan(_drift(), format_version="2.0"))


def test_empty_resource_drift_is_valid_clean_evidence_bundle():
    bundle = analyze_plan_json(_plan(), iac_engine="opentofu")

    assert bundle.iac_engine == "opentofu"
    assert bundle.finding_count == 0
    assert bundle.redaction_policy == "omit_change_values"
