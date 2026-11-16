"""Command line entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .checks import CHECKS, Finding, run_checks, unknown_check_ids
from .loader import OrgInputError, load
from .model import SEVERITY_ORDER
from .render import render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2

_EPILOG = "checks:\n" + "\n".join(
    f"  {check.id:<24} {check.severity:<6} {check.title}" for check in CHECKS
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-organizations-scp-audit",
        description=(
            "Audit AWS Organizations service control policies offline, from the JSON "
            "that list-policies, describe-policy, list-targets-for-policy and the "
            "account/OU listings already give you."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input",
        "-i",
        action="append",
        default=[],
        metavar="PATH",
        help="file, directory or - for stdin; repeatable",
    )
    parser.add_argument(
        "--documents",
        action="append",
        default=[],
        metavar="PATH",
        help="describe-policy output (file or directory); repeatable",
    )
    parser.add_argument(
        "--targets",
        action="append",
        default=[],
        metavar="PATH",
        help="list-targets-for-policy output (file or directory); repeatable",
    )
    parser.add_argument(
        "--accounts",
        action="append",
        default=[],
        metavar="PATH",
        help="list-accounts output; repeatable",
    )
    parser.add_argument(
        "--ous",
        action="append",
        default=[],
        metavar="PATH",
        help="list-organizational-units-for-parent / list-roots output; repeatable",
    )
    parser.add_argument(
        "--management-account",
        default="",
        metavar="ID",
        help=(
            "management (payer) account id; SCPs never apply to it, so it is left out of "
            "TARGET_ONLY_FULL_ACCESS. Picked up automatically from describe-organization output."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--severity",
        choices=("low", "medium", "high"),
        default="low",
        help="report findings at or above this severity (default: low)",
    )
    parser.add_argument(
        "--only",
        default="",
        metavar="IDS",
        help="comma-separated check ids to run exclusively",
    )
    parser.add_argument(
        "--skip",
        default="",
        metavar="IDS",
        help="comma-separated check ids to leave out",
    )
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "none"),
        default="medium",
        help="exit 1 when a finding at or above this severity remains (default: medium)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = list(args.input) + list(args.documents) + list(args.targets)
    paths += list(args.accounts) + list(args.ous)
    if not paths:
        paths = ["-"] if not sys.stdin.isatty() else []
    if not paths:
        parser.error("no input: pass --input PATH or pipe JSON on stdin")

    only = [item for item in args.only.split(",") if item.strip()]
    skip = [item for item in args.skip.split(",") if item.strip()]
    bad = unknown_check_ids(only + skip)
    if bad:
        parser.error(f"unknown check id(s): {', '.join(bad)}")

    try:
        org = load(paths)
    except OrgInputError as exc:
        print(f"aws-organizations-scp-audit: {exc}", file=sys.stderr)
        return EXIT_INPUT

    if args.management_account:
        org.management_account_id = args.management_account

    findings = run_checks(org, only=only, skip=skip, severity=args.severity)
    print(render(org, findings, args.format))
    return EXIT_FINDINGS if _should_fail(findings, args.fail_on) else EXIT_OK


def _should_fail(findings: Sequence[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    floor = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= floor for f in findings)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
