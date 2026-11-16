from __future__ import annotations

import pytest

from scp_audit.checks import CHECK_IDS, run_checks, unknown_check_ids
from scp_audit.loader import load

from .helpers import FULL_ACCESS, checks_of, org_from, policy, target

DENY_LEAVE = [{"Sid": "DenyLeave", "Effect": "Deny", "Action": ["organizations:LeaveOrganization"], "Resource": "*"}]


def test_healthy_example_is_clean():
    org = load(["examples/healthy-org"])
    assert run_checks(org) == []


def test_messy_example_hits_every_check():
    org = load(["examples/messy-org/bundle.json"])
    found = set(checks_of(run_checks(org)))
    assert found == set(CHECK_IDS)


def test_unattached_policy_is_reported_once(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [FULL_ACCESS, policy("p-orphan01", "DenyLeave", DENY_LEAVE)],
            "Targets": {"p-FullAWSAccess": [target("r-ab12", "ROOT")], "p-orphan01": []},
        },
    )
    findings = run_checks(org, only=["POLICY_NO_TARGETS"])
    assert len(findings) == 1
    assert "p-orphan01" in findings[0].resource
    assert "DenyLeave" in findings[0].resource


def test_account_with_only_full_access(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [FULL_ACCESS],
            "Targets": {"p-FullAWSAccess": [target("555555555555", "ACCOUNT", "legacy")]},
            "Accounts": [{"Id": "555555555555", "Name": "legacy", "ParentId": "r-ab12"}],
            "Roots": [{"Id": "r-ab12"}],
        },
    )
    findings = run_checks(org, only=["TARGET_ONLY_FULL_ACCESS"])
    assert len(findings) == 1
    assert "555555555555" in findings[0].resource
    assert findings[0].severity == "high"


def test_inherited_guardrail_clears_the_account(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [FULL_ACCESS, policy("p-guard001", "DenyLeave", DENY_LEAVE)],
            "Targets": {
                "p-FullAWSAccess": [target("555555555555")],
                "p-guard001": [target("ou-ab12-cdef3456", "ORGANIZATIONAL_UNIT")],
            },
            "OrganizationalUnits": [{"Id": "ou-ab12-cdef3456", "ParentId": "r-ab12"}],
            "Accounts": [{"Id": "555555555555", "ParentId": "ou-ab12-cdef3456"}],
        },
    )
    assert run_checks(org, only=["TARGET_ONLY_FULL_ACCESS"]) == []


def test_management_account_is_never_flagged(tmp_path):
    bundle = {
        "Organization": {"MasterAccountId": "111111111111"},
        "Policies": [FULL_ACCESS],
        "Targets": {"p-FullAWSAccess": [target("111111111111")]},
        "Accounts": [{"Id": "111111111111", "ParentId": "r-ab12"}],
        "Roots": [{"Id": "r-ab12"}],
    }
    org = org_from(tmp_path, bundle)
    assert run_checks(org, only=["TARGET_ONLY_FULL_ACCESS"]) == []


def test_allow_only_policy(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [
                policy("p-allow0001", "AllowStuff", [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]),
                policy(
                    "p-notaction1",
                    "AllowExceptIam",
                    [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}],
                ),
            ],
            "Targets": {"p-allow0001": [target("222222222222")], "p-notaction1": [target("222222222222")]},
        },
    )
    findings = run_checks(org, only=["ALLOW_ONLY_POLICY"])
    assert [f.resource for f in findings] == ["p-allow0001 (AllowStuff)"]


@pytest.mark.parametrize(
    "statement, expected",
    [
        (
            {"Effect": "Deny", "Action": ["ec2:RunInstances"], "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:RequestTag/CostCenter": "x"}}},
            1,
        ),
        (
            {"Effect": "Deny", "Action": ["ec2:RunInstances"], "Resource": "*",
             "Condition": {"StringNotEqualsIfExists": {"aws:RequestTag/CostCenter": "x"}}},
            0,
        ),
        (
            {"Effect": "Deny", "Action": ["ec2:RunInstances"], "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:RequestTag/CostCenter": "x"},
                           "Null": {"aws:RequestTag/CostCenter": "true"}}},
            0,
        ),
        (
            {"Effect": "Deny", "Action": ["s3:PutObject"], "Resource": "*",
             "Condition": {"StringEquals": {"ec2:InstanceType": "t3.micro"}}},
            1,
        ),
        (
            {"Effect": "Deny", "Action": ["*"], "Resource": "*",
             "Condition": {"StringEquals": {"ec2:InstanceType": "t3.micro"}}},
            0,
        ),
        (
            {"Effect": "Deny", "Action": ["*"], "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:RequestedRegion": "eu-central-1"}}},
            0,
        ),
        (
            {"Effect": "Deny", "Action": ["iam:CreateUser"], "Resource": "*",
             "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
            1,
        ),
        (
            {"Effect": "Allow", "Action": ["*"], "Resource": "*",
             "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
            0,
        ),
    ],
)
def test_inert_condition_detection(tmp_path, statement, expected):
    org = org_from(
        tmp_path,
        {
            "Policies": [policy("p-cond00001", "Conditioned", [statement])],
            "Targets": {"p-cond00001": [target("222222222222")]},
        },
    )
    assert len(run_checks(org, only=["DENY_WITH_INERT_CONDITION"])) == expected


@pytest.mark.parametrize(
    "statement, expected",
    [
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, 1),
        ({"Effect": "Deny", "Action": ["*"], "Resource": ["*"]}, 1),
        ({"Effect": "Deny", "Action": "*"}, 1),
        ({"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}, 0),
        ({"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"Bool": {"x": "y"}}}, 0),
        ({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}, 0),
    ],
)
def test_wildcard_deny_all(tmp_path, statement, expected):
    org = org_from(
        tmp_path,
        {
            "Policies": [policy("p-wild00001", "Wide", [statement])],
            "Targets": {"p-wild00001": [target("222222222222")]},
        },
    )
    assert len(run_checks(org, only=["WILDCARD_DENY_ALL"])) == expected


def test_ou_without_its_own_policy(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [FULL_ACCESS, policy("p-guard001", "DenyLeave", DENY_LEAVE)],
            "Targets": {
                "p-FullAWSAccess": [target("ou-ab12-bare00000", "ORGANIZATIONAL_UNIT")],
                "p-guard001": [target("ou-ab12-guarded00", "ORGANIZATIONAL_UNIT")],
            },
            "OrganizationalUnits": [
                {"Id": "ou-ab12-bare00000", "Name": "Bare", "ParentId": "r-ab12"},
                {"Id": "ou-ab12-guarded00", "Name": "Guarded", "ParentId": "r-ab12"},
            ],
        },
    )
    findings = run_checks(org, only=["OU_NO_OWN_POLICY"])
    assert [f.resource for f in findings] == ["OU ou-ab12-bare00000 (Bare)"]


@pytest.mark.parametrize("count, severity", [(5, "medium"), (4, "low"), (3, None)])
def test_policy_limit(tmp_path, count, severity):
    policies = [policy(f"p-limit{i:05d}", f"P{i}", DENY_LEAVE) for i in range(count)]
    org = org_from(
        tmp_path,
        {
            "Policies": policies,
            "Targets": {p["Id"]: [target("222222222222")] for p in policies},
        },
    )
    findings = run_checks(org, only=["TARGET_AT_POLICY_LIMIT"])
    if severity is None:
        assert findings == []
    else:
        assert len(findings) == 1 and findings[0].severity == severity


@pytest.mark.parametrize(
    "content, fragment",
    [
        ('{"Statement": [', "not valid JSON"),
        ('{"Version": "2012-10-17"}', "no Statement element"),
        ('{"Statement": []}', "Statement is empty"),
        ('{"Statement": ["nope"]}', "not objects"),
        ('{"Statement": [{"Action": "*"}]}', "no Effect"),
        ('"just a string"', "not an object"),
    ],
)
def test_malformed_documents(tmp_path, content, fragment):
    org = org_from(
        tmp_path,
        {
            "Policies": [
                {"Id": "p-bad000001", "Name": "Bad", "Content": content},
                policy("p-good00001", "Good", DENY_LEAVE),
            ],
            "Targets": {"p-bad000001": [target("222222222222")], "p-good00001": [target("222222222222")]},
        },
    )
    findings = run_checks(org, only=["MALFORMED_DOCUMENT"])
    assert len(findings) == 1
    assert "p-bad000001" in findings[0].resource
    assert fragment in findings[0].detail
    # the other policy was still audited
    assert run_checks(org, only=["POLICY_NO_TARGETS"]) == []


def test_duplicate_statement_across_two_policies(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [
                policy("p-dupe00001", "First", DENY_LEAVE),
                policy("p-dupe00002", "Second", DENY_LEAVE),
            ],
            "Targets": {
                "p-dupe00001": [target("ou-ab12-cdef3456", "ORGANIZATIONAL_UNIT")],
                "p-dupe00002": [target("ou-ab12-cdef3456", "ORGANIZATIONAL_UNIT")],
            },
        },
    )
    findings = run_checks(org, only=["DUPLICATE_STATEMENT"])
    assert len(findings) == 1
    assert "p-dupe00001/DenyLeave" in findings[0].detail
    assert "p-dupe00002/DenyLeave" in findings[0].detail


def test_unknown_target_needs_an_inventory(tmp_path):
    bundle = {
        "Policies": [policy("p-guard001", "DenyLeave", DENY_LEAVE)],
        "Targets": {"p-guard001": [target("777777777777")]},
    }
    without_inventory = org_from(tmp_path, bundle)
    assert run_checks(without_inventory, only=["UNKNOWN_TARGET"]) == []

    with_inventory = org_from(
        tmp_path,
        {**bundle, "Accounts": [{"Id": "222222222222", "ParentId": "r-ab12"}]},
    )
    findings = run_checks(with_inventory, only=["UNKNOWN_TARGET"])
    assert len(findings) == 1 and "777777777777" in findings[0].resource


def test_severity_floor_and_selection_compose():
    org = load(["examples/messy-org/bundle.json"])
    assert all(f.severity == "high" for f in run_checks(org, severity="high"))
    assert "OU_NO_OWN_POLICY" not in checks_of(run_checks(org, severity="medium"))
    # --only wins the set, --severity still filters inside it
    assert run_checks(org, only=["OU_NO_OWN_POLICY"], severity="medium") == []
    # a check named in both --only and --skip never runs
    assert run_checks(org, only=["OU_NO_OWN_POLICY"], skip=["OU_NO_OWN_POLICY"]) == []


def test_findings_are_sorted_high_first():
    findings = run_checks(load(["examples/messy-org/bundle.json"]))
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])


def test_unknown_check_ids():
    assert unknown_check_ids(["POLICY_NO_TARGETS", "nope"]) == ["NOPE"]
    assert unknown_check_ids(["policy_no_targets"]) == []
