"""
Canon diff engine.
Produces RuleDiff objects from two SourceState snapshots.
No Anchor imports. Domain agnostic.
"""
from __future__ import annotations

import uuid
from typing import Any

from canon.models import ChangeType, EvidencePackage, RuleDiff, SourceState


def _severity_delta(old_sev: str, new_sev: str) -> str | None:
    if old_sev == new_sev:
        return None
    return f"{old_sev.upper()} -> {new_sev.upper()}"


def _regulatory_refs_affected(
    old_rule: dict[str, Any], new_rule: dict[str, Any]
) -> list[str]:
    old_refs = set(old_rule.get("regulatory_refs", []))
    new_refs = set(new_rule.get("regulatory_refs", []))
    return sorted(old_refs | new_refs)


def diff_states(baseline: SourceState, current: SourceState) -> EvidencePackage:
    """
    Compare two SourceState snapshots and produce an EvidencePackage.
    This is Canon's core operation.
    """
    diffs: list[RuleDiff] = []
    baseline_rules = baseline.rules
    current_rules = current.rules
    baseline_ids = set(baseline_rules.keys())
    current_ids = set(current_rules.keys())

    for rule_id in sorted(current_ids - baseline_ids):
        rule = current_rules[rule_id]
        diffs.append(RuleDiff(
            rule_id=rule_id,
            change_type=ChangeType.ADDED,
            old_value=None,
            new_value=rule,
            regulatory_mappings_affected=rule.get("regulatory_refs", []),
            description=f"New rule added: {rule.get('title', rule_id)}",
        ))

    for rule_id in sorted(baseline_ids - current_ids):
        rule = baseline_rules[rule_id]
        diffs.append(RuleDiff(
            rule_id=rule_id,
            change_type=ChangeType.REMOVED,
            old_value=rule,
            new_value=None,
            regulatory_mappings_affected=rule.get("regulatory_refs", []),
            description=f"Rule removed: {rule.get('title', rule_id)}",
        ))

    for rule_id in sorted(baseline_ids & current_ids):
        old = baseline_rules[rule_id]
        new = current_rules[rule_id]
        changed_fields: dict[str, Any] = {}
        for field in ("title", "description", "severity", "category", "regulatory_refs"):
            if old.get(field) != new.get(field):
                changed_fields[field] = {"old": old.get(field), "new": new.get(field)}
        # Full-source-text fingerprint: catches edits outside the extracted fields.
        # Compared only when both snapshots carry it (older baselines do not).
        old_ch, new_ch = old.get("content_hash"), new.get("content_hash")
        if old_ch and new_ch and old_ch != new_ch:
            changed_fields["content_hash"] = {"old": old_ch, "new": new_ch}
        if not changed_fields:
            continue

        sev_delta = None
        if "severity" in changed_fields:
            sev_delta = _severity_delta(
                changed_fields["severity"]["old"] or "info",
                changed_fields["severity"]["new"] or "info",
            )

        diffs.append(RuleDiff(
            rule_id=rule_id,
            change_type=ChangeType.MODIFIED,
            old_value={k: old.get(k) for k in changed_fields},
            new_value={k: new.get(k) for k in changed_fields},
            severity_delta=sev_delta,
            regulatory_mappings_affected=_regulatory_refs_affected(old, new),
            description=f"Modified fields: {', '.join(changed_fields.keys())}",
        ))

    package = EvidencePackage(
        evidence_id=str(uuid.uuid4()),
        source_id=current.source_id,
        source_name=current.source_name,
        baseline_hash=baseline.raw_hash,
        current_hash=current.raw_hash,
        diffs=diffs,
        requires_review=len(diffs) > 0,
    )
    package.compute_hash()
    return package