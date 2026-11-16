"""Table, JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json
from typing import Sequence

from .checks import Finding
from .model import SEVERITY_ORDER, Org

_HEADERS = ("SEVERITY", "CHECK", "RESOURCE", "DETAIL")


def summary(org: Org, findings: Sequence[Finding]) -> dict[str, object]:
    by_check: dict[str, int] = {}
    by_severity = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        by_check[finding.check] = by_check.get(finding.check, 0) + 1
        by_severity[finding.severity] += 1
    return {
        "policies": len(org.policies),
        "targets": len(org.targets),
        "accounts": len(org.accounts),
        "organizational_units": len(org.ous),
        "findings": len(findings),
        "by_severity": by_severity,
        "by_check": dict(sorted(by_check.items())),
    }


def render(org: Org, findings: Sequence[Finding], fmt: str) -> str:
    if fmt == "json":
        return _render_json(org, findings)
    if fmt == "csv":
        return _render_csv(findings)
    return _render_table(org, findings)


def _render_json(org: Org, findings: Sequence[Finding]) -> str:
    payload = {
        "summary": summary(org, findings),
        "findings": [finding.as_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _render_csv(findings: Sequence[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([h.lower() for h in _HEADERS])
    for finding in findings:
        writer.writerow([finding.severity, finding.check, finding.resource, finding.detail])
    return buffer.getvalue().rstrip("\n")


def _render_table(org: Org, findings: Sequence[Finding]) -> str:
    counts = summary(org, findings)
    scanned = (
        f"{counts['policies']} policies, {counts['targets']} attached targets, "
        f"{counts['accounts']} accounts, {counts['organizational_units']} OUs"
    )
    if not findings:
        return f"Scanned {scanned}\nNo findings."

    rows = [
        (finding.severity.upper(), finding.check, finding.resource, finding.detail)
        for finding in findings
    ]
    widths = [
        max(len(_HEADERS[i]), max(len(row[i]) for row in rows)) for i in range(3)
    ]
    lines = [f"Scanned {scanned}", ""]
    header = "  ".join(_HEADERS[i].ljust(widths[i]) for i in range(3)) + "  " + _HEADERS[3]
    lines.append(header)
    lines.append("-" * len(header))
    for row in rows:
        lines.append(
            "  ".join(row[i].ljust(widths[i]) for i in range(3)) + "  " + row[3]
        )
    tally = ", ".join(
        f"{severity} {counts['by_severity'][severity]}"
        for severity in sorted(SEVERITY_ORDER, key=lambda s: -SEVERITY_ORDER[s])
        if counts["by_severity"][severity]
    )
    lines.append("")
    lines.append(f"{len(findings)} finding(s): {tally}")
    return "\n".join(lines)
