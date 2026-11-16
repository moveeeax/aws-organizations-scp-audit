"""Normalised AWS Organizations model shared by the loader, the checks and the renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FULL_ACCESS_NAME = "FullAWSAccess"
FULL_ACCESS_ID = "p-FullAWSAccess"

#: AWS allows at most five SCPs attached directly to a root, OU or account.
SCP_LIMIT_PER_TARGET = 5

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Policy:
    """A service control policy as it comes out of ``list-policies``/``describe-policy``."""

    id: str
    name: str = ""
    arn: str = ""
    type: str = "SERVICE_CONTROL_POLICY"
    aws_managed: bool = False
    description: str = ""
    content: str | None = None
    document: dict[str, Any] | None = None
    parse_error: str | None = None
    #: True once a ``list-targets-for-policy`` result was supplied for this policy.
    has_targets_data: bool = False

    @property
    def is_full_access(self) -> bool:
        return self.name == FULL_ACCESS_NAME or self.id == FULL_ACCESS_ID

    @property
    def label(self) -> str:
        return f"{self.id} ({self.name})" if self.name else self.id

    @property
    def document_supplied(self) -> bool:
        return self.content is not None or self.document is not None

    def statements(self) -> list[dict[str, Any]]:
        """Statements of the parsed document, normalised to a list of dicts."""
        if not isinstance(self.document, dict):
            return []
        raw = self.document.get("Statement")
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        return [s for s in raw if isinstance(s, dict)]


@dataclass
class Target:
    """A root, OU or account that at least one policy is attached to."""

    id: str
    type: str = ""
    name: str = ""
    policy_ids: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.id} ({self.name})" if self.name else self.id

    @property
    def kind(self) -> str:
        return {
            "ACCOUNT": "account",
            "ORGANIZATIONAL_UNIT": "OU",
            "ROOT": "root",
        }.get(self.type, "target")


@dataclass
class OrgUnit:
    id: str
    name: str = ""
    parent_id: str = ""

    @property
    def label(self) -> str:
        return f"{self.id} ({self.name})" if self.name else self.id


@dataclass
class Account:
    id: str
    name: str = ""
    parent_id: str = ""
    status: str = ""

    @property
    def label(self) -> str:
        return f"{self.id} ({self.name})" if self.name else self.id


@dataclass
class Org:
    """Everything the checks are allowed to look at."""

    policies: dict[str, Policy] = field(default_factory=dict)
    targets: dict[str, Target] = field(default_factory=dict)
    ous: dict[str, OrgUnit] = field(default_factory=dict)
    accounts: dict[str, Account] = field(default_factory=dict)
    roots: dict[str, OrgUnit] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    #: SCPs never apply to the management account; checks skip it when it is known.
    management_account_id: str = ""

    @property
    def attachments_known(self) -> bool:
        """True when attachment data was supplied, so absence of a target means something."""
        return bool(self.targets) or any(p.has_targets_data for p in self.policies.values())

    @property
    def inventory_known(self) -> bool:
        """True when an account/OU/root listing was supplied."""
        return bool(self.accounts or self.ous or self.roots)

    def policy(self, policy_id: str) -> Policy | None:
        return self.policies.get(policy_id)

    def policy_label(self, policy_id: str) -> str:
        policy = self.policies.get(policy_id)
        return policy.label if policy else policy_id

    def targets_of(self, policy_id: str) -> list[Target]:
        return [t for t in self.targets.values() if policy_id in t.policy_ids]

    def target_label(self, target_id: str) -> str:
        target = self.targets.get(target_id)
        if target is not None:
            return target.label
        for pool in (self.accounts, self.ous, self.roots):
            entry = pool.get(target_id)
            if entry is not None:
                return entry.label
        return target_id

    def attached_policies(self, target_id: str) -> list[Policy]:
        target = self.targets.get(target_id)
        if target is None:
            return []
        out = []
        for pid in target.policy_ids:
            policy = self.policies.get(pid)
            out.append(policy if policy is not None else Policy(id=pid))
        return out

    def direct_policy_ids(self, target_id: str) -> list[str]:
        target = self.targets.get(target_id)
        return list(target.policy_ids) if target else []

    def parent_of(self, target_id: str) -> str:
        for pool in (self.accounts, self.ous):
            entry = pool.get(target_id)
            if entry is not None and entry.parent_id:
                return entry.parent_id
        return ""

    def ancestors(self, target_id: str) -> list[str]:
        """Parent chain of a target, nearest first. Empty when no parent links were supplied."""
        out: list[str] = []
        seen = {target_id}
        current = self.parent_of(target_id)
        while current and current not in seen:
            out.append(current)
            seen.add(current)
            current = self.parent_of(current)
        return out

    def guarding_policies(self, target_id: str) -> list[str]:
        """Ids of non-default SCPs attached to the target itself or to any ancestor."""
        out = []
        for node in [target_id, *self.ancestors(target_id)]:
            for pid in self.direct_policy_ids(node):
                policy = self.policies.get(pid)
                if policy is None or not policy.is_full_access:
                    out.append(pid)
        return out
