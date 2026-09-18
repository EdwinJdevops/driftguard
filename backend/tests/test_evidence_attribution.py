from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from backend.evidence.attribution import attribute_aws_drift
from backend.evidence.models import CloudResourceLocator, DriftEvidence


class FakeCloudTrail:
    def __init__(self, pages: list[dict] | None = None, error: Exception | None = None):
        self.pages = pages or [{"Events": []}]
        self.error = error
        self.calls: list[dict] = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        index = len(self.calls) - 1
        return self.pages[index]


def _finding(
    *,
    resource_type: str = "aws_ssm_parameter",
    changed_paths: list[str] | None = None,
    locator: CloudResourceLocator | None = None,
) -> DriftEvidence:
    return DriftEvidence(
        resource_address="aws_ssm_parameter.proof",
        resource_type=resource_type,
        resource_name="proof",
        provider_name="registry.terraform.io/hashicorp/aws",
        cloud_locator=locator
        or CloudResourceLocator(
            provider="aws",
            arn="arn:aws:ssm:us-east-1:123456789012:parameter/driftguard/proof/test",
            id="/driftguard/proof/test",
            name="/driftguard/proof/test",
            region="us-east-1",
        ),
        actions=["update"],
        changed_paths=changed_paths or ["/value", "/version"],
        sensitive_paths=["/value"],
        unknown_paths=[],
    )


def _event(
    *,
    event_id: str,
    overwrite: bool,
    name: str = "/driftguard/proof/test",
    when: datetime | None = None,
    secret: str = "DO_NOT_PERSIST",
) -> dict:
    when = when or datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    return {
        "EventId": event_id,
        "EventName": "PutParameter",
        "EventTime": when,
        "Username": "proof-session",
        "CloudTrailEvent": json.dumps(
            {
                "eventSource": "ssm.amazonaws.com",
                "requestParameters": {
                    "name": name,
                    "overwrite": overwrite,
                    "value": secret,
                },
            }
        ),
    }


START = datetime(2026, 9, 18, 11, 55, tzinfo=UTC)
END = datetime(2026, 9, 18, 12, 5, tzinfo=UTC)


def test_unique_overwrite_event_is_attributed_without_returning_raw_payload():
    client = FakeCloudTrail(
        pages=[
            {
                "Events": [
                    _event(event_id="create", overwrite=False),
                    _event(event_id="mutation", overwrite=True),
                ]
            }
        ]
    )

    result = attribute_aws_drift(
        _finding(),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )

    assert result.status == "attributed"
    assert result.candidate_count == 1
    assert result.candidate_event_ids == ("mutation",)
    assert result.event is not None
    assert result.event.event_id == "mutation"
    assert result.event.actor_session == "proof-session"
    assert "DO_NOT_PERSIST" not in repr(result)

    call = client.calls[0]
    assert call["LookupAttributes"] == [
        {"AttributeKey": "EventName", "AttributeValue": "PutParameter"}
    ]
    assert call["StartTime"] == START
    assert call["EndTime"] == END
    assert call["MaxResults"] == 50


def test_multiple_exact_mutations_are_ambiguous_not_latest_wins():
    client = FakeCloudTrail(
        pages=[
            {
                "Events": [
                    _event(event_id="older", overwrite=True),
                    _event(
                        event_id="newer",
                        overwrite=True,
                        when=datetime(2026, 9, 18, 12, 1, tzinfo=UTC),
                    ),
                ]
            }
        ]
    )

    result = attribute_aws_drift(
        _finding(),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )

    assert result.status == "ambiguous"
    assert result.candidate_count == 2
    assert result.candidate_event_ids == ("newer", "older")
    assert result.event is None


def test_exact_resource_name_is_required():
    client = FakeCloudTrail(
        pages=[
            {
                "Events": [
                    _event(
                        event_id="other",
                        overwrite=True,
                        name="/driftguard/proof/other",
                    )
                ]
            }
        ]
    )

    result = attribute_aws_drift(
        _finding(),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )

    assert result.status == "not_found"


def test_pagination_is_exhaustive_and_duplicate_token_fails_closed():
    client = FakeCloudTrail(
        pages=[
            {"Events": [], "NextToken": "page-2"},
            {"Events": [_event(event_id="mutation", overwrite=True)]},
        ]
    )

    result = attribute_aws_drift(
        _finding(),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )

    assert result.status == "attributed"
    assert len(client.calls) == 2
    assert client.calls[1]["NextToken"] == "page-2"

    repeated = FakeCloudTrail(
        pages=[
            {"Events": [], "NextToken": "repeat"},
            {"Events": [], "NextToken": "repeat"},
        ]
    )
    failed = attribute_aws_drift(
        _finding(),
        cloudtrail=repeated,
        start_time=START,
        end_time=END,
    )
    assert failed.status == "error"


def test_unsupported_resource_or_non_value_drift_never_calls_cloudtrail():
    client = FakeCloudTrail()

    unsupported_type = attribute_aws_drift(
        _finding(resource_type="aws_instance"),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )
    unsupported_path = attribute_aws_drift(
        _finding(changed_paths=["/tags"]),
        cloudtrail=client,
        start_time=START,
        end_time=END,
    )

    assert unsupported_type.status == "unsupported"
    assert unsupported_path.status == "unsupported"
    assert client.calls == []


def test_cloudtrail_failure_and_malformed_event_fail_closed():
    failed_client = FakeCloudTrail(error=RuntimeError("simulated"))
    failed = attribute_aws_drift(
        _finding(),
        cloudtrail=failed_client,
        start_time=START,
        end_time=END,
    )
    assert failed.status == "error"
    assert "simulated" not in failed.reason

    malformed = FakeCloudTrail(
        pages=[
            {
                "Events": [
                    {
                        "EventId": "broken",
                        "EventName": "PutParameter",
                        "EventTime": datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
                        "CloudTrailEvent": "{not-json}",
                    }
                ]
            }
        ]
    )
    result = attribute_aws_drift(
        _finding(),
        cloudtrail=malformed,
        start_time=START,
        end_time=END,
    )
    assert result.status == "error"


def test_attribution_window_must_be_timezone_aware_and_ordered():
    client = FakeCloudTrail()
    naive = datetime(2026, 9, 18, 12, 0)

    with pytest.raises(ValueError, match="timezone-aware"):
        attribute_aws_drift(
            _finding(),
            cloudtrail=client,
            start_time=naive,
            end_time=END,
        )

    with pytest.raises(ValueError, match="earlier"):
        attribute_aws_drift(
            _finding(),
            cloudtrail=client,
            start_time=END,
            end_time=START,
        )
