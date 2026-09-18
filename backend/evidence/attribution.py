from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from .models import DriftEvidence

AttributionStatus = Literal[
    "attributed",
    "not_found",
    "ambiguous",
    "unsupported",
    "error",
]

_SSM_PROVIDER = "registry.terraform.io/hashicorp/aws"
_SSM_VALUE_PATH = "/value"
_SSM_EVENT_NAME = "PutParameter"
_SSM_EVENT_SOURCE = "ssm.amazonaws.com"


class CloudTrailLookupClient(Protocol):
    def lookup_events(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class AuditEventMatch:
    event_id: str
    event_name: str
    event_time: datetime
    event_source: str
    actor_session: str | None


@dataclass(frozen=True, slots=True)
class AttributionResult:
    status: AttributionStatus
    resource_address: str
    adapter: str
    candidate_count: int
    candidate_event_ids: tuple[str, ...]
    event: AuditEventMatch | None
    reason: str


def attribute_aws_drift(
    finding: DriftEvidence,
    *,
    cloudtrail: CloudTrailLookupClient,
    start_time: datetime,
    end_time: datetime,
) -> AttributionResult:
    """Find a bounded CloudTrail audit candidate for one AWS drift finding.

    A successful result means exactly one event satisfied a service-specific,
    deterministic matching contract. It does not claim to prove human intent or
    business causality.

    Raw CloudTrailEvent payloads are parsed only in memory. This function never
    returns request parameters or event payloads because those can contain
    sensitive values.
    """
    _validate_window(start_time, end_time)

    if finding.provider_name != _SSM_PROVIDER:
        return _unsupported(
            finding,
            "CloudTrail attribution currently supports only the canonical HashiCorp AWS provider.",
        )
    if finding.resource_type != "aws_ssm_parameter":
        return _unsupported(
            finding,
            f"No CloudTrail attribution adapter exists for {finding.resource_type!r}.",
        )
    if _SSM_VALUE_PATH not in finding.changed_paths:
        return _unsupported(
            finding,
            "The SSM adapter currently attributes only drift that includes /value.",
        )

    locator = finding.cloud_locator
    if locator is None or locator.provider != "aws":
        return _unsupported(
            finding,
            "SSM attribution requires a non-sensitive AWS cloud locator.",
        )

    resource_name = locator.name or locator.id
    if not resource_name:
        return _unsupported(
            finding,
            "SSM attribution requires a parameter name or provider ID.",
        )

    try:
        events = _lookup_put_parameter_events(
            cloudtrail,
            start_time=start_time,
            end_time=end_time,
        )
    except Exception as exc:
        return AttributionResult(
            status="error",
            resource_address=finding.resource_address,
            adapter="aws_ssm_parameter",
            candidate_count=0,
            candidate_event_ids=(),
            event=None,
            reason=f"CloudTrail lookup failed safely: {type(exc).__name__}.",
        )

    candidates: list[AuditEventMatch] = []
    for raw_event in events:
        try:
            candidate = _match_ssm_value_mutation(
                raw_event,
                resource_name=resource_name,
                start_time=start_time,
                end_time=end_time,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return AttributionResult(
                status="error",
                resource_address=finding.resource_address,
                adapter="aws_ssm_parameter",
                candidate_count=0,
                candidate_event_ids=(),
                event=None,
                reason=f"CloudTrail event could not be interpreted safely: {type(exc).__name__}.",
            )
        if candidate is not None:
            candidates.append(candidate)

    candidate_ids = tuple(sorted(candidate.event_id for candidate in candidates))
    if not candidates:
        return AttributionResult(
            status="not_found",
            resource_address=finding.resource_address,
            adapter="aws_ssm_parameter",
            candidate_count=0,
            candidate_event_ids=(),
            event=None,
            reason=(
                "No PutParameter event matched the exact parameter name with "
                "overwrite=true inside the requested time window."
            ),
        )
    if len(candidates) > 1:
        return AttributionResult(
            status="ambiguous",
            resource_address=finding.resource_address,
            adapter="aws_ssm_parameter",
            candidate_count=len(candidates),
            candidate_event_ids=candidate_ids,
            event=None,
            reason=(
                "Multiple PutParameter mutation events matched; DriftGuard refuses "
                "to choose one as the drift source."
            ),
        )

    return AttributionResult(
        status="attributed",
        resource_address=finding.resource_address,
        adapter="aws_ssm_parameter",
        candidate_count=1,
        candidate_event_ids=candidate_ids,
        event=candidates[0],
        reason=(
            "Exactly one CloudTrail PutParameter event matched the exact parameter "
            "name with overwrite=true inside the bounded time window."
        ),
    )


def _validate_window(start_time: datetime, end_time: datetime) -> None:
    for label, value in (("start_time", start_time), ("end_time", end_time)):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{label} must be timezone-aware.")
    if start_time.astimezone(UTC) >= end_time.astimezone(UTC):
        raise ValueError("start_time must be earlier than end_time.")


def _unsupported(finding: DriftEvidence, reason: str) -> AttributionResult:
    return AttributionResult(
        status="unsupported",
        resource_address=finding.resource_address,
        adapter="none",
        candidate_count=0,
        candidate_event_ids=(),
        event=None,
        reason=reason,
    )


def _lookup_put_parameter_events(
    cloudtrail: CloudTrailLookupClient,
    *,
    start_time: datetime,
    end_time: datetime,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "LookupAttributes": [
            {"AttributeKey": "EventName", "AttributeValue": _SSM_EVENT_NAME}
        ],
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": 50,
    }
    events: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()

    while True:
        response = cloudtrail.lookup_events(**params)
        page = response.get("Events", [])
        if not isinstance(page, list):
            raise TypeError("CloudTrail Events must be a list.")
        if any(not isinstance(event, dict) for event in page):
            raise TypeError("CloudTrail event entries must be objects.")
        events.extend(page)

        token = response.get("NextToken")
        if token is None:
            break
        if not isinstance(token, str) or not token:
            raise TypeError("CloudTrail NextToken must be a non-empty string.")
        if token in seen_tokens:
            raise ValueError("CloudTrail pagination repeated a NextToken.")
        seen_tokens.add(token)
        params["NextToken"] = token

    return events


def _match_ssm_value_mutation(
    event: dict[str, Any],
    *,
    resource_name: str,
    start_time: datetime,
    end_time: datetime,
) -> AuditEventMatch | None:
    if event.get("EventName") != _SSM_EVENT_NAME:
        return None

    raw_payload = event.get("CloudTrailEvent")
    if not isinstance(raw_payload, str):
        raise TypeError("CloudTrailEvent must be a JSON string.")
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        raise TypeError("CloudTrailEvent JSON must decode to an object.")
    if payload.get("eventSource") != _SSM_EVENT_SOURCE:
        return None

    request = payload.get("requestParameters")
    if not isinstance(request, dict):
        raise TypeError("PutParameter requestParameters must be an object.")
    if request.get("name") != resource_name:
        return None
    # overwrite=false is the create path in this contract. It is explicitly not
    # accepted as evidence for a drift mutation.
    if request.get("overwrite") is not True:
        return None

    event_id = event.get("EventId")
    if not isinstance(event_id, str) or not event_id:
        raise TypeError("Matched CloudTrail event is missing EventId.")

    event_time = event.get("EventTime")
    if not isinstance(event_time, datetime):
        raise TypeError("Matched CloudTrail event is missing datetime EventTime.")
    if event_time.tzinfo is None or event_time.utcoffset() is None:
        raise ValueError("Matched CloudTrail EventTime must be timezone-aware.")
    event_time = event_time.astimezone(UTC)
    if not (start_time.astimezone(UTC) <= event_time <= end_time.astimezone(UTC)):
        return None

    username = event.get("Username")
    actor_session = username if isinstance(username, str) and username else None
    return AuditEventMatch(
        event_id=event_id,
        event_name=_SSM_EVENT_NAME,
        event_time=event_time,
        event_source=_SSM_EVENT_SOURCE,
        actor_session=actor_session,
    )
