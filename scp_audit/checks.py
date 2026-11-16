"""The checks. Every check is a pure function over the org model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .model import SCP_LIMIT_PER_TARGET, SEVERITY_ORDER, Org, Policy

#: Condition keys whose value is *absent* rather than false in the common case, so a
#: Deny that requires them never fires unless the operator is an ``...IfExists`` variant
#: or a ``Null`` guard denies the absent case too.
ABSENT_KEY_TRAPS: dict[str, str] = {
    "aws:multifactorauthpresent": (
        "the key is absent, not false, for calls made by roles and service principals, "
        "so this Deny never fires for them"
    ),
    "aws:sourceip": (
        "the key is absent for calls AWS services make on your behalf, so those calls "
        "skip this Deny entirely"
    ),
    "aws:sourcevpc": "the key is absent outside VPC-endpoint traffic, so this Deny skips every other call",
    "aws:sourcevpce": "the key is absent outside VPC-endpoint traffic, so this Deny skips every other call",
    "aws:principaltype": "the key is absent for some call paths, so this Deny is not reliably evaluated",
    "aws:tagkeys": "the key is absent for actions that do not take tags, so this Deny skips them",
}

#: Condition key prefixes with the same problem.
ABSENT_PREFIX_TRAPS: dict[str, str] = {
    "aws:principaltag/": "the key is absent for principals without that tag, so this Deny skips them",
    "aws:requesttag/": "the key is absent for requests that do not pass that tag, so this Deny skips them",
    "aws:resourcetag/": (
        "the key is absent for actions that carry no resource tags, so this Deny skips them"
    ),
}

@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    resource: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "severity": self.severity,
            "resource": self.resource,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Check:
    id: str
    severity: str
    title: str
    run: Callable[[Org], list[Finding]]


# -- helpers ------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _strings(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value) if isinstance(item, (str, int, float))]


def _action_services(statement: dict[str, Any]) -> set[str]:
    services: set[str] = set()
    for action in _strings(statement.get("Action")) + _strings(statement.get("NotAction")):
        if action.strip() == "*":
            services.add("*")
            continue
        services.add(action.split(":", 1)[0].lower())
    return services


def _condition_keys(statement: dict[str, Any]) -> list[tuple[str, str]]:
    """``[(operator, key)]`` for every entry of the statement's Condition block."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return []
    out: list[tuple[str, str]] = []
    for operator, body in condition.items():
        if not isinstance(body, dict):
            continue
        for key in body:
            out.append((str(operator), str(key)))
    return out


def _statement_id(statement: dict[str, Any], index: int) -> str:
    sid = statement.get("Sid")
    return str(sid) if sid else f"statement #{index + 1}"


def _customer_policies(org: Org) -> list[Policy]:
    return [
        policy
        for policy in org.policies.values()
        if not policy.aws_managed and not policy.is_full_access
    ]


def _deny_statements(policy: Policy) -> Iterable[tuple[int, dict[str, Any]]]:
    for index, statement in enumerate(policy.statements()):
        if str(statement.get("Effect", "")).lower() == "deny":
            yield index, statement


def _sorted_targets(org: Org) -> list[Any]:
    return [org.targets[key] for key in sorted(org.targets)]


# -- checks -------------------------------------------------------------


def policy_no_targets(org: Org) -> list[Finding]:
    """An SCP that exists, reads well and restricts nothing because nothing points at it."""
    if not org.attachments_known:
        return []
    out = []
    for policy in sorted(_customer_policies(org), key=lambda p: p.id):
        if org.targets_of(policy.id):
            continue
        if policy.has_targets_data:
            detail = (
                "list-targets-for-policy returned no targets - the policy restricts nothing"
            )
        else:
            detail = (
                "no attachment in the input references this policy - the policy restricts "
                "nothing (run list-targets-for-policy for every policy to be sure)"
            )
        out.append(Finding("POLICY_NO_TARGETS", "medium", policy.label, detail))
    return out


def target_only_full_access(org: Org) -> list[Finding]:
    """A target that FullAWSAccess is the only policy for, inheritance included.

    SCPs are inherited, so an account under an OU that carries a Deny is guarded even
    though its own attachment list is just the default policy. This check only fires
    when nothing in the chain restricts anything - that account really does run wide
    open. OUs that merely declare nothing of their own are OU_NO_OWN_POLICY instead.
    """
    out = []
    for target in _sorted_targets(org):
        if target.type == "ROOT" or not target.policy_ids:
            continue
        if target.id and target.id == org.management_account_id:
            # SCPs do not restrict the management account at all, guardrail or not.
            continue
        if any(not p.is_full_access for p in org.attached_policies(target.id)):
            continue
        if org.guarding_policies(target.id):
            continue
        if org.ancestors(target.id):
            detail = (
                "only FullAWSAccess is attached here and no ancestor attaches a "
                "restricting SCP - the target runs wide open"
            )
        else:
            detail = (
                "only FullAWSAccess is attached - no guardrail of its own (no parent "
                "links in the input, so inheritance could not be checked)"
            )
        out.append(
            Finding(
                "TARGET_ONLY_FULL_ACCESS",
                "high",
                f"{target.kind} {target.label}",
                detail,
            )
        )
    return out


def allow_only_policy(org: Org) -> list[Finding]:
    """An SCP with no Deny and no NotAction cannot take anything away."""
    out = []
    for policy in sorted(_customer_policies(org), key=lambda p: p.id):
        statements = policy.statements()
        if not statements:
            continue
        has_deny = any(str(s.get("Effect", "")).lower() == "deny" for s in statements)
        has_not_action = any("NotAction" in s for s in statements)
        if has_deny or has_not_action:
            continue
        out.append(
            Finding(
                "ALLOW_ONLY_POLICY",
                "medium",
                policy.label,
                "only Allow statements and no NotAction - cannot restrict anything "
                "while FullAWSAccess is attached",
            )
        )
    return out


def deny_with_inert_condition(org: Org) -> list[Finding]:
    """A Deny whose Condition can never be satisfied for the actions it covers."""
    out = []
    for policy in sorted(_customer_policies(org), key=lambda p: p.id):
        for index, statement in _deny_statements(policy):
            keys = _condition_keys(statement)
            if not keys:
                continue
            services = _action_services(statement)
            guarded = {key.lower() for operator, key in keys if operator.lower().startswith("null")}
            for operator, key in keys:
                lowered = key.lower()
                operator_l = operator.lower()
                if lowered in guarded and not operator_l.startswith("null"):
                    continue
                reason = _inert_reason(lowered, operator_l, services)
                if reason is None:
                    continue
                out.append(
                    Finding(
                        "DENY_WITH_INERT_CONDITION",
                        "medium",
                        f"{policy.label} / {_statement_id(statement, index)}",
                        f"Deny conditioned on {key}: {reason}",
                    )
                )
    return out


def _inert_reason(key: str, operator: str, services: set[str]) -> str | None:
    if ":" in key and "*" not in services:
        prefix = key.split(":", 1)[0]
        if prefix != "aws" and prefix not in services:
            return (
                f"the key belongs to {prefix} but the statement only covers "
                f"{', '.join(sorted(services)) or 'no'} actions, so it is never populated"
            )
    if operator.endswith("ifexists") or operator.startswith("null"):
        return None
    if key in ABSENT_KEY_TRAPS:
        return ABSENT_KEY_TRAPS[key]
    for prefix, reason in ABSENT_PREFIX_TRAPS.items():
        if key.startswith(prefix):
            return reason
    return None


def wildcard_deny_all(org: Org) -> list[Finding]:
    """Deny on ``*`` with no exception locks a target out of AWS completely."""
    out = []
    for policy in sorted(_customer_policies(org), key=lambda p: p.id):
        for index, statement in _deny_statements(policy):
            actions = _strings(statement.get("Action"))
            resources = _strings(statement.get("Resource")) or ["*"]
            if "NotAction" in statement or statement.get("Condition"):
                continue
            if "*" not in actions or "*" not in resources:
                continue
            out.append(
                Finding(
                    "WILDCARD_DENY_ALL",
                    "high",
                    f"{policy.label} / {_statement_id(statement, index)}",
                    "Deny on Action \"*\" with no NotAction and no Condition - every "
                    "attached target loses all access",
                )
            )
    return out


def ou_no_own_policy(org: Org) -> list[Finding]:
    """An OU that inherits everything and declares nothing of its own."""
    if not org.attachments_known:
        return []
    out = []
    for ou_id in sorted(org.ous):
        unit = org.ous[ou_id]
        own = [
            pid
            for pid in org.direct_policy_ids(ou_id)
            if not (org.policy(pid) or Policy(id=pid)).is_full_access
        ]
        if own:
            continue
        out.append(
            Finding(
                "OU_NO_OWN_POLICY",
                "low",
                f"OU {unit.label}",
                "no SCP of its own - every guardrail here is inherited from above",
            )
        )
    return out


def target_at_policy_limit(org: Org) -> list[Finding]:
    """A target at (or one slot away from) the five-SCP limit cannot take another guardrail."""
    out = []
    for target in _sorted_targets(org):
        count = len(target.policy_ids)
        if count >= SCP_LIMIT_PER_TARGET:
            out.append(
                Finding(
                    "TARGET_AT_POLICY_LIMIT",
                    "medium",
                    f"{target.kind} {target.label}",
                    f"{count} SCPs attached - at the limit of {SCP_LIMIT_PER_TARGET}, "
                    "the next guardrail cannot be attached",
                )
            )
        elif count == SCP_LIMIT_PER_TARGET - 1:
            out.append(
                Finding(
                    "TARGET_AT_POLICY_LIMIT",
                    "low",
                    f"{target.kind} {target.label}",
                    f"{count} SCPs attached - one slot left before the limit of "
                    f"{SCP_LIMIT_PER_TARGET}",
                )
            )
    return out


def malformed_document(org: Org) -> list[Finding]:
    """A policy document that does not parse, or parses into something without a Statement."""
    out = []
    for policy_id in sorted(org.policies):
        policy = org.policies[policy_id]
        if not policy.document_supplied:
            continue
        if policy.parse_error:
            out.append(
                Finding("MALFORMED_DOCUMENT", "high", policy.label, policy.parse_error)
            )
            continue
        document = policy.document
        if not isinstance(document, dict):
            continue
        raw = document.get("Statement")
        if raw is None:
            out.append(
                Finding(
                    "MALFORMED_DOCUMENT",
                    "high",
                    policy.label,
                    "document has no Statement element",
                )
            )
            continue
        items = raw if isinstance(raw, list) else [raw]
        if not items:
            out.append(
                Finding("MALFORMED_DOCUMENT", "high", policy.label, "Statement is empty")
            )
            continue
        bad = [i for i, item in enumerate(items) if not isinstance(item, dict)]
        if bad:
            positions = ", ".join(f"#{i + 1}" for i in bad)
            out.append(
                Finding(
                    "MALFORMED_DOCUMENT",
                    "high",
                    policy.label,
                    f"Statement entries {positions} are not objects",
                )
            )
            continue
        missing = [
            _statement_id(item, i)
            for i, item in enumerate(items)
            if not str(item.get("Effect", "")).strip()
        ]
        if missing:
            out.append(
                Finding(
                    "MALFORMED_DOCUMENT",
                    "high",
                    policy.label,
                    f"{', '.join(missing)} has no Effect",
                )
            )
    return out


def duplicate_statement(org: Org) -> list[Finding]:
    """The same effect/action/resource triple attached twice to one target."""
    out = []
    for target in _sorted_targets(org):
        seen: dict[tuple[str, tuple[str, ...], tuple[str, ...]], list[str]] = {}
        for policy in org.attached_policies(target.id):
            if policy.is_full_access:
                continue
            for index, statement in enumerate(policy.statements()):
                effect = str(statement.get("Effect", "")).lower()
                actions = tuple(sorted(_strings(statement.get("Action")) or _strings(statement.get("NotAction"))))
                resources = tuple(sorted(_strings(statement.get("Resource")) or ["*"]))
                if not effect or not actions:
                    continue
                key = (effect, actions, resources)
                seen.setdefault(key, []).append(
                    f"{policy.id}/{_statement_id(statement, index)}"
                )
        for (effect, actions, _resources), places in sorted(seen.items()):
            if len(places) < 2:
                continue
            out.append(
                Finding(
                    "DUPLICATE_STATEMENT",
                    "low",
                    f"{target.kind} {target.label}",
                    f"{effect.title()} on {', '.join(actions)} repeated in "
                    f"{', '.join(places)}",
                )
            )
    return out


def unknown_target(org: Org) -> list[Finding]:
    """A policy attached to a target that the account/OU listing does not contain."""
    if not org.inventory_known:
        return []
    known = set(org.accounts) | set(org.ous) | set(org.roots)
    out = []
    for target in _sorted_targets(org):
        if target.id in known:
            continue
        out.append(
            Finding(
                "UNKNOWN_TARGET",
                "low",
                f"{target.kind} {target.label}",
                "policies are attached to a target that is absent from the account/OU "
                "listing - stale attachment or incomplete input",
            )
        )
    return out


CHECKS: tuple[Check, ...] = (
    Check("POLICY_NO_TARGETS", "medium", "SCP attached to nothing", policy_no_targets),
    Check("TARGET_ONLY_FULL_ACCESS", "high", "target guarded only by FullAWSAccess", target_only_full_access),
    Check("ALLOW_ONLY_POLICY", "medium", "SCP that cannot restrict anything", allow_only_policy),
    Check("DENY_WITH_INERT_CONDITION", "medium", "Deny that can never fire", deny_with_inert_condition),
    Check("WILDCARD_DENY_ALL", "high", "Deny on everything with no exception", wildcard_deny_all),
    Check("OU_NO_OWN_POLICY", "low", "OU with no policy of its own", ou_no_own_policy),
    Check("TARGET_AT_POLICY_LIMIT", "medium", "target at the five-SCP limit", target_at_policy_limit),
    Check("MALFORMED_DOCUMENT", "high", "unusable policy document", malformed_document),
    Check("DUPLICATE_STATEMENT", "low", "statement repeated across attached policies", duplicate_statement),
    Check("UNKNOWN_TARGET", "low", "attachment to an unlisted target", unknown_target),
)

CHECK_IDS = tuple(check.id for check in CHECKS)


def run_checks(
    org: Org,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
    severity: str = "low",
) -> list[Finding]:
    """Run the selected checks and return findings at or above ``severity``."""
    only_set = {item.strip().upper() for item in only or [] if item.strip()}
    skip_set = {item.strip().upper() for item in skip or [] if item.strip()}
    floor = SEVERITY_ORDER[severity]
    findings: list[Finding] = []
    for check in CHECKS:
        if only_set and check.id not in only_set:
            continue
        if check.id in skip_set:
            continue
        for finding in check.run(org):
            if SEVERITY_ORDER[finding.severity] < floor:
                continue
            findings.append(finding)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.check, f.resource, f.detail))
    return findings


def unknown_check_ids(values: Iterable[str]) -> list[str]:
    known = set(CHECK_IDS)
    return sorted({item.strip().upper() for item in values if item.strip()} - known)
