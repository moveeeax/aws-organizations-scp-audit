from __future__ import annotations

import io
import json

import pytest

from scp_audit.cli import main

from .helpers import write_bundle


def test_healthy_example_exits_zero(capsys):
    assert main(["--input", "examples/healthy-org"]) == 0
    assert "No findings." in capsys.readouterr().out


def test_messy_example_exits_one(capsys):
    assert main(["--input", "examples/messy-org/bundle.json"]) == 1
    out = capsys.readouterr().out
    assert "TARGET_ONLY_FULL_ACCESS" in out
    assert "finding(s)" in out


def test_fail_on_none_still_prints(capsys):
    assert main(["--input", "examples/messy-org/bundle.json", "--fail-on", "none"]) == 0
    assert "MALFORMED_DOCUMENT" in capsys.readouterr().out


def test_fail_on_high_ignores_lower(capsys):
    assert main(["--input", "examples/messy-org/bundle.json", "--only", "OU_NO_OWN_POLICY",
                 "--fail-on", "high"]) == 0
    assert "OU_NO_OWN_POLICY" in capsys.readouterr().out


def test_json_output_shape(capsys):
    assert main(["--input", "examples/messy-org/bundle.json", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["policies"] == 7
    assert payload["summary"]["by_severity"]["high"] >= 1
    assert {"check", "severity", "resource", "detail"} == set(payload["findings"][0])


def test_csv_output_has_a_header(capsys):
    assert main(["--input", "examples/messy-org/bundle.json", "--format", "csv"]) == 1
    first = capsys.readouterr().out.splitlines()[0]
    assert first == "severity,check,resource,detail"


def test_unreadable_input_exits_two_with_one_line(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["--input", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.strip().splitlines()) == 1
    assert captured.err.startswith("aws-organizations-scp-audit:")


def test_non_organizations_json_exits_two(capsys, tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"Reservations": []}), encoding="utf-8")
    assert main(["--input", str(other)]) == 2
    assert "no AWS Organizations data" in capsys.readouterr().err


def test_unknown_check_id_is_rejected():
    with pytest.raises(SystemExit) as excinfo:
        main(["--input", "examples/healthy-org", "--only", "NO_SUCH_CHECK"])
    assert excinfo.value.code == 2


def test_stdin_input(monkeypatch, capsys):
    payload = {
        "Policies": [{"Id": "p-orphan01", "Name": "DenyLeave", "AwsManaged": False}],
        "Targets": {"p-orphan01": []},
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert main(["--input", "-"]) == 1
    assert "POLICY_NO_TARGETS" in capsys.readouterr().out


def test_management_account_flag(capsys, tmp_path):
    bundle = {
        "Policies": [{"Id": "p-FullAWSAccess", "Name": "FullAWSAccess", "AwsManaged": True}],
        "Targets": {"p-FullAWSAccess": [{"TargetId": "111111111111", "Type": "ACCOUNT"}]},
        "Accounts": [{"Id": "111111111111", "ParentId": "r-ab12"}],
        "Roots": [{"Id": "r-ab12"}],
    }
    path = write_bundle(tmp_path, bundle)
    assert main(["--input", path, "--only", "TARGET_ONLY_FULL_ACCESS"]) == 1
    assert main(["--input", path, "--only", "TARGET_ONLY_FULL_ACCESS",
                 "--management-account", "111111111111"]) == 0
    assert "No findings." in capsys.readouterr().out


def test_mixed_flags_are_all_loaded(capsys):
    code = main(
        [
            "--input", "examples/healthy-org/policies.json",
            "--documents", "examples/healthy-org/p-regionlock01.json",
            "--documents", "examples/healthy-org/p-denyroot002.json",
            "--targets", "examples/healthy-org/targets.json",
            "--accounts", "examples/healthy-org/inventory.json",
        ]
    )
    assert code == 0
    assert "3 policies" in capsys.readouterr().out
