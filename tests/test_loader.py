from __future__ import annotations

import json

import pytest

from scp_audit.loader import OrgInputError, load

from .helpers import FULL_ACCESS, org_from, policy, target


def test_separate_files_join_into_one_model(tmp_path):
    (tmp_path / "policies.json").write_text(
        json.dumps({"Policies": [FULL_ACCESS, {"Id": "p-abc1", "Name": "DenyLeave"}]}),
        encoding="utf-8",
    )
    (tmp_path / "describe-p-abc1.json").write_text(
        json.dumps(
            {
                "Policy": {
                    "PolicySummary": {"Id": "p-abc1", "Name": "DenyLeave"},
                    "Content": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}
                            ],
                        }
                    ),
                }
            }
        ),
        encoding="utf-8",
    )
    # policy id comes from the file name for a bare list-targets-for-policy result
    (tmp_path / "targets-p-abc1.json").write_text(
        json.dumps({"Targets": [target("ou-ab12-cdef3456", "ORGANIZATIONAL_UNIT", "Workloads")]}),
        encoding="utf-8",
    )

    org = load([str(tmp_path)])

    assert set(org.policies) == {"p-FullAWSAccess", "p-abc1"}
    assert org.policies["p-FullAWSAccess"].aws_managed is True
    assert org.policies["p-abc1"].statements()[0]["Effect"] == "Deny"
    assert org.targets["ou-ab12-cdef3456"].policy_ids == ["p-abc1"]
    assert org.policies["p-abc1"].has_targets_data is True
    assert org.attachments_known is True


def test_concatenated_objects_and_top_level_list(tmp_path):
    (tmp_path / "stream.json").write_text(
        json.dumps({"Policies": [FULL_ACCESS]}) + "\n" + json.dumps({"Roots": [{"Id": "r-ab12", "Name": "Root"}]}),
        encoding="utf-8",
    )
    (tmp_path / "list.json").write_text(
        json.dumps([{"Accounts": [{"Id": "111111111111", "Name": "mgmt", "ParentId": "r-ab12"}]}]),
        encoding="utf-8",
    )

    org = load([str(tmp_path)])

    assert org.roots["r-ab12"].name == "Root"
    assert org.accounts["111111111111"].parent_id == "r-ab12"


def test_targets_map_and_documents_map(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [{"Id": "p-abc1", "Name": "DenyLeave"}],
            "Documents": {
                "p-abc1": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*"}]}
            },
            "Targets": {"p-abc1": [target("222222222222")]},
        },
    )

    assert org.policies["p-abc1"].document["Statement"][0]["Effect"] == "Deny"
    assert org.targets["222222222222"].policy_ids == ["p-abc1"]


def test_children_output_builds_parent_links(tmp_path):
    org = org_from(
        tmp_path,
        {
            "ParentId": "ou-ab12-cdef3456",
            "Children": [
                {"Id": "333333333333", "Type": "ACCOUNT"},
                {"Id": "ou-ab12-99999999", "Type": "ORGANIZATIONAL_UNIT"},
            ],
        },
    )

    assert org.accounts["333333333333"].parent_id == "ou-ab12-cdef3456"
    assert org.ous["ou-ab12-99999999"].parent_id == "ou-ab12-cdef3456"


def test_management_account_is_picked_up(tmp_path):
    org = org_from(
        tmp_path,
        {"Organization": {"Id": "o-abc", "MasterAccountId": "111111111111"}},
    )
    assert org.management_account_id == "111111111111"


def test_broken_document_is_kept_as_parse_error(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Policies": [
                {"Id": "p-broken", "Name": "Broken", "Content": '{"Statement":['},
                policy("p-fine", "Fine", [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]),
            ],
            "Targets": {"p-broken": [target("222222222222")], "p-fine": [target("222222222222")]},
        },
    )

    assert org.policies["p-broken"].parse_error is not None
    assert org.policies["p-broken"].document is None
    # the healthy policy next to it is still fully parsed
    assert org.policies["p-fine"].statements()[0]["Action"] == "iam:*"


def test_parent_chain_walks_up(tmp_path):
    org = org_from(
        tmp_path,
        {
            "Roots": [{"Id": "r-ab12"}],
            "OrganizationalUnits": [
                {"Id": "ou-ab12-top00000", "ParentId": "r-ab12"},
                {"Id": "ou-ab12-leaf0000", "ParentId": "ou-ab12-top00000"},
            ],
            "Accounts": [{"Id": "444444444444", "ParentId": "ou-ab12-leaf0000"}],
        },
    )

    assert org.ancestors("444444444444") == ["ou-ab12-leaf0000", "ou-ab12-top00000", "r-ab12"]


@pytest.mark.parametrize(
    "payload, fragment",
    [
        ('{"Policies": [', "invalid JSON"),
        ('{"totally": "unrelated"}', "no AWS Organizations data"),
        ("   ", "empty input"),
    ],
)
def test_unusable_input_raises(tmp_path, payload, fragment):
    path = tmp_path / "input.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(OrgInputError) as excinfo:
        load([str(path)])
    assert fragment in str(excinfo.value)


def test_missing_path_and_empty_directory_raise(tmp_path):
    with pytest.raises(OrgInputError):
        load([str(tmp_path / "nope.json")])
    (tmp_path / "empty").mkdir()
    with pytest.raises(OrgInputError):
        load([str(tmp_path / "empty")])


def test_targets_without_a_policy_id_raises(tmp_path):
    path = tmp_path / "anonymous.json"
    path.write_text(json.dumps({"Targets": [target("222222222222")]}), encoding="utf-8")
    with pytest.raises(OrgInputError) as excinfo:
        load([str(path)])
    assert "needs a policy id" in str(excinfo.value)
