"""Turn raw ``aws organizations list-*`` JSON into one :class:`~scp_audit.model.Org`.

The loader never calls an AWS API. It accepts, in any mix:

* ``list-policies --filter SERVICE_CONTROL_POLICY`` -> ``{"Policies": [...]}``
* ``describe-policy`` -> ``{"Policy": {"PolicySummary": {...}, "Content": "..."}}``
* ``list-targets-for-policy`` -> ``{"Targets": [...]}`` (policy id from ``PolicyId``
  in the object or from ``p-...`` in the file name)
* ``list-accounts`` / ``list-accounts-for-parent`` -> ``{"Accounts": [...]}``
* ``list-organizational-units-for-parent`` -> ``{"OrganizationalUnits": [...]}``
* ``list-roots`` -> ``{"Roots": [...]}``
* ``list-children`` -> ``{"Children": [...]}``
* a bundle object mixing the above, where ``Targets``/``Documents`` may be maps
  keyed by policy id.

A file may also hold several concatenated JSON objects or a top-level list.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

from .model import Account, Org, OrgUnit, Policy, Target

_POLICY_ID_RE = re.compile(r"p-[A-Za-z0-9]+")
_PARENT_ID_RE = re.compile(r"(?:ou-[a-z0-9]+-[a-z0-9]+|r-[a-z0-9]+)")

_ORG_KEYS = {
    "Organization",
    "Policies",
    "Policy",
    "Documents",
    "Targets",
    "Accounts",
    "OrganizationalUnits",
    "Roots",
    "Children",
}


class OrgInputError(Exception):
    """Raised when the input cannot be read as AWS Organizations output at all."""


def load(paths: list[str]) -> Org:
    """Load every path (file, directory or ``-`` for stdin) into one org model."""
    builder = _Builder()
    files = _expand(paths)
    if not files:
        raise OrgInputError("no input files found")
    for source, text in files:
        hint_policy = _first(_POLICY_ID_RE, os.path.basename(source))
        hint_parent = _first(_PARENT_ID_RE, os.path.basename(source))
        for obj in _read_json_documents(text, source):
            builder.ingest(obj, source, hint_policy, hint_parent)
        builder.org.sources.append(source)
    return builder.finish()


def _expand(paths: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in paths:
        if path == "-":
            out.append(("<stdin>", sys.stdin.read()))
            continue
        if os.path.isdir(path):
            found = []
            for root, _dirs, names in os.walk(path):
                for name in names:
                    if name.endswith(".json"):
                        found.append(os.path.join(root, name))
            if not found:
                raise OrgInputError(f"{path}: directory holds no .json files")
            for item in sorted(found):
                out.append((item, _read_file(item)))
            continue
        if not os.path.exists(path):
            raise OrgInputError(f"{path}: no such file or directory")
        out.append((path, _read_file(path)))
    return out


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise OrgInputError(f"{path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise OrgInputError(f"{path}: not UTF-8 text ({exc.reason})") from exc


def _read_json_documents(text: str, source: str) -> list[Any]:
    decoder = json.JSONDecoder()
    index = 0
    out: list[Any] = []
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            obj, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise OrgInputError(f"{source}: invalid JSON ({exc})") from exc
        out.append(obj)
    if not out:
        raise OrgInputError(f"{source}: empty input")
    return out


def _first(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(0) if match else ""


class _Builder:
    def __init__(self) -> None:
        self.org = Org()
        self.recognised = False
        self.unrecognised: list[str] = []

    # -- ingest ---------------------------------------------------------
    def ingest(self, obj: Any, source: str, hint_policy: str, hint_parent: str) -> None:
        if isinstance(obj, list):
            for item in obj:
                self.ingest(item, source, hint_policy, hint_parent)
            return
        if not isinstance(obj, dict):
            self.unrecognised.append(source)
            return
        if not _ORG_KEYS & set(obj):
            # A bare describe-policy body or a lone summary is still usable.
            if "PolicySummary" in obj:
                self._describe(obj, source)
                return
            self.unrecognised.append(source)
            return

        if isinstance(obj.get("Policies"), list):
            for entry in obj["Policies"]:
                self._summary(entry, source)
            self.recognised = True
        if isinstance(obj.get("Policy"), dict):
            self._describe(obj["Policy"], source)
            self.recognised = True
        if isinstance(obj.get("Documents"), dict):
            for pid, doc in obj["Documents"].items():
                self._document(str(pid), doc, source)
            self.recognised = True
        if "Targets" in obj:
            self._targets(obj, source, hint_policy)
            self.recognised = True
        if isinstance(obj.get("Accounts"), list):
            parent = str(obj.get("ParentId") or hint_parent or "")
            for entry in obj["Accounts"]:
                self._account(entry, parent)
            self.recognised = True
        if isinstance(obj.get("OrganizationalUnits"), list):
            parent = str(obj.get("ParentId") or hint_parent or "")
            for entry in obj["OrganizationalUnits"]:
                self._ou(entry, parent)
            self.recognised = True
        if isinstance(obj.get("Roots"), list):
            for entry in obj["Roots"]:
                self._root(entry)
            self.recognised = True
        if isinstance(obj.get("Organization"), dict):
            master = str(obj["Organization"].get("MasterAccountId") or "")
            if master:
                self.org.management_account_id = master
            self.recognised = True
        if isinstance(obj.get("Children"), list):
            parent = str(obj.get("ParentId") or hint_parent or "")
            for entry in obj["Children"]:
                self._child(entry, parent)
            self.recognised = True

    # -- policies -------------------------------------------------------
    def _policy(self, policy_id: str) -> Policy:
        policy = self.org.policies.get(policy_id)
        if policy is None:
            policy = Policy(id=policy_id)
            self.org.policies[policy_id] = policy
        return policy

    def _summary(self, entry: Any, source: str) -> None:
        if not isinstance(entry, dict):
            self.unrecognised.append(source)
            return
        policy_id = str(entry.get("Id") or entry.get("PolicyId") or "")
        if not policy_id:
            self.unrecognised.append(source)
            return
        policy = self._policy(policy_id)
        policy.name = str(entry.get("Name") or policy.name)
        policy.arn = str(entry.get("Arn") or policy.arn)
        policy.type = str(entry.get("Type") or policy.type)
        policy.description = str(entry.get("Description") or policy.description)
        if "AwsManaged" in entry:
            policy.aws_managed = bool(entry["AwsManaged"])
        if "Content" in entry:
            self._document(policy_id, entry["Content"], source)

    def _describe(self, body: Any, source: str) -> None:
        if not isinstance(body, dict):
            return
        summary = body.get("PolicySummary")
        if isinstance(summary, dict):
            self._summary(summary, source)
            policy_id = str(summary.get("Id") or "")
        else:
            policy_id = str(body.get("Id") or "")
        if policy_id and "Content" in body:
            self._document(policy_id, body["Content"], source)

    def _document(self, policy_id: str, doc: Any, source: str) -> None:
        policy = self._policy(policy_id)
        if isinstance(doc, dict):
            policy.document = doc
            policy.content = json.dumps(doc)
            policy.parse_error = None
            return
        if not isinstance(doc, str):
            policy.content = repr(doc)
            policy.parse_error = f"document is {type(doc).__name__}, not a JSON object or string"
            return
        policy.content = doc
        try:
            parsed = json.loads(doc)
        except ValueError as exc:
            policy.document = None
            policy.parse_error = f"not valid JSON ({exc})"
            return
        if not isinstance(parsed, dict):
            policy.document = None
            policy.parse_error = f"document is a JSON {type(parsed).__name__}, not an object"
            return
        policy.document = parsed
        policy.parse_error = None

    # -- attachments ----------------------------------------------------
    def _targets(self, obj: dict[str, Any], source: str, hint_policy: str) -> None:
        raw = obj["Targets"]
        if isinstance(raw, dict):
            for pid, entries in raw.items():
                self._attach(str(pid), entries, source)
            return
        if not isinstance(raw, list):
            self.unrecognised.append(source)
            return
        policy_id = str(obj.get("PolicyId") or obj.get("Id") or hint_policy or "")
        if not policy_id:
            raise OrgInputError(
                f"{source}: a Targets list needs a policy id - add \"PolicyId\" to the object, "
                "name the file after the policy (p-xxxx.json) or use a bundle keyed by policy id"
            )
        self._attach(policy_id, raw, source)

    def _attach(self, policy_id: str, entries: Any, source: str) -> None:
        policy = self._policy(policy_id)
        policy.has_targets_data = True
        if not isinstance(entries, list):
            self.unrecognised.append(source)
            return
        for entry in entries:
            if not isinstance(entry, dict):
                self.unrecognised.append(source)
                continue
            target_id = str(entry.get("TargetId") or entry.get("Id") or "")
            if not target_id:
                self.unrecognised.append(source)
                continue
            target = self.org.targets.get(target_id)
            if target is None:
                target = Target(id=target_id)
                self.org.targets[target_id] = target
            target.type = str(entry.get("Type") or target.type)
            target.name = str(entry.get("Name") or target.name)
            if policy_id not in target.policy_ids:
                target.policy_ids.append(policy_id)

    # -- inventory ------------------------------------------------------
    def _account(self, entry: Any, parent: str) -> None:
        if not isinstance(entry, dict):
            return
        account_id = str(entry.get("Id") or "")
        if not account_id:
            return
        parent = str(entry.get("ParentId") or parent or "")
        existing = self.org.accounts.get(account_id)
        account = existing or Account(id=account_id)
        account.name = str(entry.get("Name") or account.name)
        account.status = str(entry.get("Status") or account.status)
        account.parent_id = account.parent_id or parent
        self.org.accounts[account_id] = account
        self._name_target(account_id, "ACCOUNT", account.name)

    def _ou(self, entry: Any, parent: str) -> None:
        if not isinstance(entry, dict):
            return
        ou_id = str(entry.get("Id") or "")
        if not ou_id:
            return
        parent = str(entry.get("ParentId") or parent or "")
        existing = self.org.ous.get(ou_id)
        unit = existing or OrgUnit(id=ou_id)
        unit.name = str(entry.get("Name") or unit.name)
        unit.parent_id = unit.parent_id or parent
        self.org.ous[ou_id] = unit
        self._name_target(ou_id, "ORGANIZATIONAL_UNIT", unit.name)

    def _root(self, entry: Any) -> None:
        if not isinstance(entry, dict):
            return
        root_id = str(entry.get("Id") or "")
        if not root_id:
            return
        existing = self.org.roots.get(root_id)
        root = existing or OrgUnit(id=root_id)
        root.name = str(entry.get("Name") or root.name)
        self.org.roots[root_id] = root
        self._name_target(root_id, "ROOT", root.name)

    def _child(self, entry: Any, parent: str) -> None:
        if not isinstance(entry, dict):
            return
        child_id = str(entry.get("Id") or "")
        kind = str(entry.get("Type") or "")
        if not child_id:
            return
        if kind == "ACCOUNT":
            self._account({"Id": child_id}, parent)
        elif kind == "ORGANIZATIONAL_UNIT":
            self._ou({"Id": child_id}, parent)

    def _name_target(self, target_id: str, kind: str, name: str) -> None:
        target = self.org.targets.get(target_id)
        if target is None:
            return
        target.type = target.type or kind
        target.name = target.name or name

    # -- finish ---------------------------------------------------------
    def finish(self) -> Org:
        for target in self.org.targets.values():
            for pool, kind in (
                (self.org.accounts, "ACCOUNT"),
                (self.org.ous, "ORGANIZATIONAL_UNIT"),
                (self.org.roots, "ROOT"),
            ):
                entry = pool.get(target.id)
                if entry is None:
                    continue
                target.type = target.type or kind
                target.name = target.name or entry.name
        if not self.recognised:
            raise OrgInputError(
                "no AWS Organizations data found in input - expected list-policies, "
                "describe-policy, list-targets-for-policy, list-accounts or "
                "list-organizational-units-for-parent output"
            )
        return self.org
