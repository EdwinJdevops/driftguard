from __future__ import annotations

import json

from backend.evidence.cli import main


def _plan_with_secret(secret_before: str, secret_after: str) -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.2",
        "errored": False,
        "resource_drift": [
            {
                "address": "aws_ssm_parameter.example",
                "mode": "managed",
                "type": "aws_ssm_parameter",
                "name": "example",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"],
                    "before": {"value": secret_before},
                    "after": {"value": secret_after},
                    "before_sensitive": {"value": True},
                    "after_sensitive": {"value": True},
                },
            }
        ],
    }


def test_local_cli_emits_redacted_evidence_to_stdout(tmp_path, capsys):
    before = "secret-before-value"
    after = "secret-after-value"
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(_plan_with_secret(before, after)))

    rc = main([str(plan_path), "--engine", "terraform"])

    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["iac_engine"] == "terraform"
    assert payload["findings"][0]["changed_paths"] == ["/value"]
    assert payload["findings"][0]["sensitive_paths"] == ["/value"]
    assert before not in captured.out
    assert after not in captured.out
    assert captured.err == ""


def test_local_cli_writes_only_redacted_evidence_to_file(tmp_path, capsys):
    before = "never-persist-before"
    after = "never-persist-after"
    plan_path = tmp_path / "plan.json"
    output_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps(_plan_with_secret(before, after)))

    rc = main([
        str(plan_path),
        "--engine",
        "opentofu",
        "--output",
        str(output_path),
    ])

    assert rc == 0
    assert capsys.readouterr().out == ""
    output = output_path.read_text()
    assert '"iac_engine": "opentofu"' in output
    assert before not in output
    assert after not in output


def test_local_cli_rejects_errored_plan_without_echoing_values(tmp_path, capsys):
    secret = "must-not-appear-in-error"
    plan = _plan_with_secret(secret, "other")
    plan["errored"] = True
    plan_path = tmp_path / "errored.json"
    plan_path.write_text(json.dumps(plan))

    rc = main([str(plan_path)])

    assert rc == 2
    captured = capsys.readouterr()
    assert "errored plan" in captured.err
    assert secret not in captured.err
    assert secret not in captured.out
