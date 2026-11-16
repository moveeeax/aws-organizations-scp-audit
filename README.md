# aws-organizations-scp-audit

[![ci](https://github.com/moveeeax/aws-organizations-scp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-organizations-scp-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit AWS Organizations service control policies **offline**, from the JSON the `aws organizations list-*`
calls already give you. No AWS API calls at audit time, no credentials, no network — so it runs in CI next
to the Terraform that manages the org.

A policy that is attached to nothing is still a policy: it shows up in `list-policies`, it has a readable
document, and it restricts exactly nothing. An account whose only attachment is `FullAWSAccess` is
unguarded, which is easy to miss because its attachment list is not empty. A `Deny` conditioned on a key
the request never carries never fires. This tool reads the static structure and tells you which of your
guardrails are load-bearing.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-organizations-scp-audit
```

Python 3.11+, standard library only.

## Usage

```bash
# collect what the tool reads (one policy dump, its documents, its attachments, the org tree)
aws organizations list-policies --filter SERVICE_CONTROL_POLICY > dump/policies.json
aws organizations describe-organization > dump/organization.json
aws organizations list-roots > dump/roots.json
aws organizations list-accounts > dump/accounts.json
for pid in $(jq -r '.Policies[].Id' dump/policies.json); do
  aws organizations describe-policy --policy-id "$pid" > "dump/describe-$pid.json"
  aws organizations list-targets-for-policy --policy-id "$pid" > "dump/targets-$pid.json"
done

aws-organizations-scp-audit --input dump/
```

```text
Scanned 7 policies, 8 attached targets, 4 accounts, 3 OUs

SEVERITY  CHECK                    RESOURCE                                      DETAIL
---------------------------------------------------------------------------------------
HIGH      MALFORMED_DOCUMENT       p-broken00005 (ImportedGuardrail)             not valid JSON (Expecting property name enclosed in double quotes: line 1 column 73 (char 72))
HIGH      TARGET_ONLY_FULL_ACCESS  account 555555555555 (legacy-billing)         only FullAWSAccess is attached here and no ancestor attaches a restricting SCP - the target runs wide open
HIGH      WILDCARD_DENY_ALL        p-denyall0004 (EmergencyLockdown) / Lockdown  Deny on Action "*" with no NotAction and no Condition - every attached target loses all access
MEDIUM    POLICY_NO_TARGETS        p-noattach001 (DenyLeaveOrganization)         list-targets-for-policy returned no targets - the policy restricts nothing

12 finding(s): high 4, medium 5, low 3
```

More:

```bash
aws-organizations-scp-audit --input bundle.json --format json --fail-on high
aws-organizations-scp-audit --input dump/ --only POLICY_NO_TARGETS,TARGET_ONLY_FULL_ACCESS --severity medium
cat bundle.json | aws-organizations-scp-audit --input -
```

Two runnable examples live in [`examples/`](examples): `healthy-org/` is a clean org split across the
real per-call files and exits 0, `messy-org/bundle.json` is one bundle that trips every check and exits 1.

## Checks

| id | severity | what it means |
| --- | --- | --- |
| `TARGET_ONLY_FULL_ACCESS` | high | nothing in the target's chain restricts anything — `FullAWSAccess` all the way up |
| `WILDCARD_DENY_ALL` | high | `Deny` on `*` with no `NotAction` and no `Condition`; every attached target loses all access |
| `MALFORMED_DOCUMENT` | high | the document does not parse, has no `Statement`, or a statement has no `Effect` |
| `POLICY_NO_TARGETS` | medium | the SCP is attached to no root, OU or account |
| `ALLOW_ONLY_POLICY` | medium | only `Allow` statements and no `NotAction`; it cannot take anything away while `FullAWSAccess` is attached |
| `DENY_WITH_INERT_CONDITION` | medium | the `Deny` is conditioned on a key that is never populated for those actions |
| `TARGET_AT_POLICY_LIMIT` | medium / low | 5 SCPs attached (at the limit), or 4 (one slot left) |
| `OU_NO_OWN_POLICY` | low | the OU declares nothing of its own and inherits every guardrail |
| `DUPLICATE_STATEMENT` | low | the same effect/action/resource triple is attached twice to one target |
| `UNKNOWN_TARGET` | low | a policy is attached to a target the account/OU listing does not contain |

### How inheritance is handled

SCPs are inherited and they intersect, so an account under an OU that carries a `Deny` is guarded even
though its own attachment list is just `FullAWSAccess`. `TARGET_ONLY_FULL_ACCESS` therefore walks the
parent chain and only fires when nothing in it restricts anything. Parent links come from `ParentId` in
the account/OU listings, from `list-accounts-for-parent` / `list-organizational-units-for-parent`
(the parent is also read from the file name) or from `list-children`. Without parent links the check
falls back to direct attachments and says so in the finding.

The management account is skipped: SCPs never apply to it. Its id is read from `describe-organization`
output (`MasterAccountId`) or passed with `--management-account`.

### What counts as an inert condition

Two patterns, both derivable from the document alone:

- a condition key whose service prefix is not covered by the statement's actions — `ec2:InstanceType`
  on a `Deny` over `s3:PutObject` is never populated, so the `Deny` never fires;
- a key that is *absent* rather than false in the common case — `aws:MultiFactorAuthPresent`,
  `aws:SourceIp`, `aws:SourceVpc`, `aws:PrincipalTag/*`, `aws:RequestTag/*`, `aws:ResourceTag/*` —
  used with an operator that is not an `...IfExists` variant and with no `Null` guard on the same key
  in the statement. With the `Null` guard or `IfExists`, the statement is fine and nothing is reported.

## Input it accepts

Point `--input` at a file, a directory (walked for `*.json`) or `-` for stdin; repeat the flag as often
as you like. `--documents`, `--targets`, `--accounts` and `--ous` are aliases that read the same way, so
you can keep your dump organised. Recognised shapes:

| source | shape |
| --- | --- |
| `list-policies --filter SERVICE_CONTROL_POLICY` | `{"Policies": [...]}` (an inline `Content` is used if present) |
| `describe-policy` | `{"Policy": {"PolicySummary": {...}, "Content": "..."}}` |
| `list-targets-for-policy` | `{"Targets": [...]}` — the policy id comes from `PolicyId` in the object or from `p-...` in the file name |
| `list-accounts`, `list-accounts-for-parent` | `{"Accounts": [...]}`, optional `ParentId` |
| `list-organizational-units-for-parent` | `{"OrganizationalUnits": [...]}`, optional `ParentId` |
| `list-roots`, `list-children` | `{"Roots": [...]}`, `{"Children": [...]}` |
| `describe-organization` | `{"Organization": {"MasterAccountId": "..."}}` |
| bundle | one object mixing the above, where `Targets` and `Documents` may be maps keyed by policy id |

A file may hold several concatenated JSON objects or a top-level list. A broken *policy document* is a
`MALFORMED_DOCUMENT` finding, not a crash; only unreadable input exits 2.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | nothing at or above `--fail-on` (default `medium`) |
| 1 | at least one finding at or above `--fail-on` |
| 2 | the input could not be read as AWS Organizations output |

## In CI

```yaml
- name: Audit SCPs
  run: |
    aws organizations list-policies --filter SERVICE_CONTROL_POLICY > dump/policies.json
    # ...describe-policy / list-targets-for-policy / list-accounts into dump/
    aws-organizations-scp-audit --input dump/ --fail-on high
```

The audit step itself needs no credentials — only the collection does. Dump in one job, audit in another,
or commit the dump and audit it on every pull request that touches your Organizations Terraform.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
