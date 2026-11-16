"""Shared test helpers: build org models straight from AWS-shaped JSON."""

from __future__ import annotations

import json
from pathlib import Path

from scp_audit.loader import load
from scp_audit.model import Org

FULL_ACCESS = {
    "Id": "p-FullAWSAccess",
    "Name": "FullAWSAccess",
    "Type": "SERVICE_CONTROL_POLICY",
    "AwsManaged": True,
}


def write_bundle(tmp_path: Path, bundle: dict, name: str = "bundle.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return str(path)


def org_from(tmp_path: Path, bundle: dict) -> Org:
    return load([write_bundle(tmp_path, bundle)])


def policy(policy_id: str, name: str, statements: list[dict], **extra) -> dict:
    """A list-policies entry carrying its document inline (the loader accepts that)."""
    entry = {
        "Id": policy_id,
        "Name": name,
        "Type": "SERVICE_CONTROL_POLICY",
        "AwsManaged": False,
        "Content": json.dumps({"Version": "2012-10-17", "Statement": statements}),
    }
    entry.update(extra)
    return entry


def target(target_id: str, kind: str = "ACCOUNT", name: str = "") -> dict:
    return {"TargetId": target_id, "Type": kind, "Name": name or target_id}


def checks_of(findings) -> list[str]:
    return [finding.check for finding in findings]
