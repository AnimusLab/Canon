"""
Canon proposal generator.
Maps detected source rule changes to Anchor governance framework files
and writes structured proposal packages under .canon/proposals/.

No Anchor internals imported. Communicates only through the filesystem
as defined in Governance Sync Specification v1.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from canon.models import EvidencePackage, RuleDiff, ChangeType

# Maps Canon source IDs to Anchor governance framework files.
# These are the only files Canon may propose changes to.
SOURCE_TO_ANCHOR_FILE: dict[str, str] = {
    "finos-aigf":      "governance/frameworks/FINOS_Framework.anchor",
    "owasp-llm-top10": "governance/frameworks/OWASP_LLM.anchor",
    "nist-ai-rmf":     "governance/frameworks/NIST_AI_RMF.anchor",
}

# Maps Canon source rule IDs to Anchor rule IDs within the framework file.
RULE_ID_MAP: dict[str, str] = {
    # NIST
    "NIST-GOVERN.1.1": "NIST-GOV",
    "NIST-GOVERN.1.2": "NIST-GOV",
    "NIST-MAP.1.1":    "NIST-MAP",
    "NIST-MAP.2.2":    "NIST-MAP",
    "NIST-MEASURE.2.1":"NIST-MEAS",
    "NIST-MANAGE.1.1": "NIST-MAN",
    "NIST-MANAGE.4.1": "NIST-MAN",
    # OWASP and FINOS use direct ID matching
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _next_proposal_id(canon_dir: Path) -> str:
    """Generate next sequential proposal ID: CANON-YYYY-NNNNN."""
    year = datetime.now(timezone.utc).year
    proposals_dir = canon_dir / "proposals"
    proposals_dir.mkdir(parents=True, exist_ok=True)

    pattern = re.compile(rf"CANON-{year}-(\d{{5}})")
    max_seq = 0

    for d in proposals_dir.iterdir():
        if d.is_dir():
            m = pattern.match(d.name)
            if m:
                max_seq = max(max_seq, int(m.group(1)))

    history_dir = canon_dir / "history"
    if history_dir.exists():
        for d in history_dir.iterdir():
            if d.is_dir():
                m = pattern.match(d.name)
                if m:
                    max_seq = max(max_seq, int(m.group(1)))

    return f"CANON-{year}-{max_seq + 1:05d}"


def _load_anchor_file(anchor_path: Path) -> dict[str, Any]:
    """Load an Anchor .anchor YAML file."""
    if not anchor_path.exists():
        raise FileNotFoundError(f"Anchor file not found: {anchor_path}")
    return yaml.safe_load(anchor_path.read_text(encoding="utf-8"))


def _find_affected_anchor_rules(
    diffs: list[RuleDiff],
    anchor_data: dict[str, Any],
    source_id: str,
) -> list[str]:
    """
    Find which Anchor rule IDs are affected by the source diffs.
    Three strategies in order: RULE_ID_MAP, direct ID match, original_id match.
    """
    anchor_rules = {r["id"]: r for r in anchor_data.get("rules", [])}
    affected: set[str] = set()

    for diff in diffs:
        source_rule_id = diff.rule_id

        # Strategy 1: explicit map
        if source_rule_id in RULE_ID_MAP:
            anchor_id = RULE_ID_MAP[source_rule_id]
            if anchor_id in anchor_rules:
                affected.add(anchor_id)
            continue

        # Strategy 2: direct ID match
        if source_rule_id in anchor_rules:
            affected.add(source_rule_id)
            continue

        # Strategy 3: original_id match
        for rule in anchor_data.get("rules", []):
            orig = rule.get("original_id", "")
            orig_normalised = orig.split("_")[0] if "_" in orig else orig
            src_normalised = (
                source_rule_id
                .replace("OWASP-", "")
                .replace("FINOS-", "")
                .replace("NIST-", "")
            )
            if orig_normalised == src_normalised or orig == src_normalised:
                affected.add(rule["id"])
                break

    return sorted(affected)


def _severity_to_anchor(canon_sev: str, current_anchor_sev: str) -> str:
    """Map Canon severity levels to Anchor severity levels."""
    return {
        "critical": "blocker",
        "warning":  "warning",
        "info":     "info",
    }.get(canon_sev.lower(), current_anchor_sev)


def _apply_diff_to_anchor_rule(
    anchor_rule: dict[str, Any],
    diff: RuleDiff,
) -> dict[str, Any]:
    """
    Apply a single RuleDiff to an Anchor rule dict.
    Returns updated rule. Does not modify the original.
    """
    import copy
    updated = copy.deepcopy(anchor_rule)

    if diff.change_type == ChangeType.REMOVED:
        updated["deprecated"] = True
        updated["deprecation_note"] = (
            f"Source rule {diff.rule_id} removed from authoritative source. "
            "Review and confirm removal or replacement."
        )
        return updated

    new_vals = diff.new_value or {}

    if "description" in new_vals:
        updated["description"] = new_vals["description"]

    if "severity" in new_vals:
        updated["severity"] = _severity_to_anchor(
            new_vals["severity"],
            updated.get("severity", "warning"),
        )

    if "regulatory_refs" in new_vals:
        updated["regulatory_refs"] = new_vals["regulatory_refs"]

    return updated


def _build_proposed_anchor_content(
    anchor_data: dict[str, Any],
    affected_rule_ids: list[str],
    diffs: list[RuleDiff],
    proposal_id: str,
) -> str:
    """
    Build the full content of proposal.anchor.
    Complete copy of original with proposed changes applied.
    Anchor can load it without modification.
    """
    import copy
    proposed = copy.deepcopy(anchor_data)

    # Bump patch version
    current_version = str(proposed.get("version", "1.0"))
    try:
        parts = current_version.split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        proposed["version"] = ".".join(parts)
    except (ValueError, IndexError):
        proposed["version"] = f"{current_version}-proposed"

    proposed["canon_proposal"] = proposal_id
    proposed["canon_proposed_at"] = _now()
    proposed["seal"] = "sha256:PENDING"

    updated_rules = []
    for rule in proposed.get("rules", []):
        rule_id = rule["id"]
        if rule_id not in affected_rule_ids:
            updated_rules.append(rule)
            continue

        applied = False
        for diff in diffs:
            maps_to = RULE_ID_MAP.get(diff.rule_id, diff.rule_id)
            if maps_to == rule_id or diff.rule_id == rule_id:
                updated_rules.append(_apply_diff_to_anchor_rule(rule, diff))
                applied = True
                break

        if not applied:
            updated_rules.append(rule)

    proposed["rules"] = updated_rules

    return yaml.dump(
        proposed,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=100,
    )


def _build_diff_md(
    proposal_id: str,
    source_name: str,
    anchor_file: str,
    diffs: list[RuleDiff],
    affected_anchor_rules: list[str],
    anchor_data: dict[str, Any],
    is_unmapped: bool,
) -> str:
    """Build human-readable diff.md for the reviewer."""
    lines = [
        f"# Proposal {proposal_id}",
        "",
        f"**Source:** {source_name}",
        f"**Date:** {_now()[:10]}",
        f"**Affected file:** {anchor_file}",
    ]

    if is_unmapped:
        lines += [
            "",
            "> ⚠️ **UNMAPPED** — Canon could not automatically map these source changes",
            "> to Anchor rules. The current Anchor file is copied unchanged.",
            "> The reviewer must manually edit `proposal.anchor` before approving.",
            "",
        ]

    lines += [
        "",
        "---",
        "",
        "## Source Changes Detected",
        "",
    ]

    for diff in diffs:
        lines.append(f"### {diff.rule_id}")
        lines.append(f"**Change type:** {diff.change_type.value}")
        if diff.severity_delta:
            lines.append(f"**Severity change:** `{diff.severity_delta}`")
        if diff.description:
            lines.append(f"**Summary:** {diff.description}")
        if diff.old_value and isinstance(diff.old_value, dict):
            lines.append("**Previous:**")
            for k, v in diff.old_value.items():
                lines.append(f"  - {k}: {v}")
        if diff.new_value and isinstance(diff.new_value, dict):
            lines.append("**Proposed:**")
            for k, v in diff.new_value.items():
                lines.append(f"  - {k}: {v}")
        lines.append("")

    if not is_unmapped:
        lines += [
            "---",
            "",
            "## Proposed Anchor Rule Changes",
            "",
        ]
        anchor_rules = {r["id"]: r for r in anchor_data.get("rules", [])}
        for rule_id in affected_anchor_rules:
            rule = anchor_rules.get(rule_id, {})
            lines.append(f"### {rule_id} — {rule.get('name', '')}")
            lines.append(f"**Current severity:** `{rule.get('severity', 'unknown')}`")
            lines.append(f"**Maps to:** `{rule.get('maps_to', 'unknown')}`")
            lines.append("")

    lines += [
        "---",
        "",
        "## Regulatory Impact",
        "",
        f"Framework: **{anchor_data.get('namespace', 'unknown')} "
        f"v{anchor_data.get('version', '')}**",
        "",
        "---",
        "",
        "## Reviewer Instructions",
        "",
        "1. Review the source changes above.",
        "2. Open `proposal.anchor` and verify the proposed rule updates.",
        "3. Modify `proposal.anchor` if the auto-generated proposal needs adjustment.",
        "4. Run `canon review` to approve, reject, or defer this proposal.",
        "",
        "> ⚠️ Do not edit `evidence.json` or `metadata.json` — they are tamper-evident.",
    ]

    return "\n".join(lines)


def _build_change_summary(diffs: list[RuleDiff]) -> str:
    added    = sum(1 for d in diffs if d.change_type == ChangeType.ADDED)
    modified = sum(1 for d in diffs if d.change_type == ChangeType.MODIFIED)
    removed  = sum(1 for d in diffs if d.change_type == ChangeType.REMOVED)
    sev_up   = sum(
        1 for d in diffs
        if d.severity_delta and
        _severity_rank(d.severity_delta.split("->")[-1].strip()) >
        _severity_rank(d.severity_delta.split("->")[0].strip())
    )
    parts = []
    if added:    parts.append(f"{added} rule(s) added")
    if modified: parts.append(f"{modified} rule(s) modified")
    if removed:  parts.append(f"{removed} rule(s) removed")
    if sev_up:   parts.append(f"{sev_up} severity escalation(s)")
    return "; ".join(parts) if parts else "no changes"


def _severity_rank(sev: str) -> int:
    return {"INFO": 0, "WARNING": 1, "CRITICAL": 2}.get(sev.upper(), 0)


def generate_proposal(
    evidence_package: EvidencePackage,
    anchor_repo_root: Path,
    canon_dir: Path | None = None,
) -> Path | None:
    """
    Generate a proposal package for an evidence package.

    Returns the proposal directory path, or None if the source
    has no Anchor file mapping.

    Writes:
        .canon/proposals/CANON-YYYY-NNNNN/
            metadata.json
            proposal.anchor
            diff.md
            evidence.json
    """
    canon_dir = canon_dir or (anchor_repo_root / ".canon")

    anchor_file_rel = SOURCE_TO_ANCHOR_FILE.get(evidence_package.source_id)
    if not anchor_file_rel:
        print(f"  [UNMAPPED] No Anchor file mapped for: {evidence_package.source_id}")
        return None

    anchor_file_abs = anchor_repo_root / anchor_file_rel
    try:
        anchor_data = _load_anchor_file(anchor_file_abs)
    except FileNotFoundError as e:
        print(f"  [ERROR] {e}")
        return None

    # Find affected Anchor rules
    affected_rules = _find_affected_anchor_rules(
        evidence_package.diffs,
        anchor_data,
        evidence_package.source_id,
    )
    is_unmapped = len(affected_rules) == 0

    if is_unmapped:
        print(
            f"  [UNMAPPED] No Anchor rules matched for "
            f"{len(evidence_package.diffs)} diff(s) in "
            f"{evidence_package.source_id}. "
            f"Proposal created for manual review."
        )

    # Create proposal directory
    proposal_id = _next_proposal_id(canon_dir)
    proposal_dir = canon_dir / "proposals" / proposal_id
    proposal_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Creating proposal {proposal_id} for {evidence_package.source_name}")

    # 1. Write evidence.json
    evidence_path = proposal_dir / "evidence.json"
    evidence_path.write_text(
        evidence_package.model_dump_json(indent=2),
        encoding="utf-8",
    )

    # 2. Build and write proposal.anchor
    if not is_unmapped:
        proposed_content = _build_proposed_anchor_content(
            anchor_data,
            affected_rules,
            evidence_package.diffs,
            proposal_id,
        )
    else:
        # Copy current file unchanged for human to edit
        proposed_content = anchor_file_abs.read_text(encoding="utf-8")

    proposal_anchor_path = proposal_dir / "proposal.anchor"
    proposal_anchor_path.write_text(proposed_content, encoding="utf-8")

    # 3. Write diff.md
    diff_md_path = proposal_dir / "diff.md"
    diff_md_path.write_text(
        _build_diff_md(
            proposal_id=proposal_id,
            source_name=evidence_package.source_name,
            anchor_file=anchor_file_rel,
            diffs=evidence_package.diffs,
            affected_anchor_rules=affected_rules,
            anchor_data=anchor_data,
            is_unmapped=is_unmapped,
        ),
        encoding="utf-8",
    )

    # 4. Write metadata.json (hashed after all other files are finalised)
    proposal_anchor_hash = _sha256_file(proposal_anchor_path)
    metadata: dict[str, Any] = {
        "proposal_id": proposal_id,
        "spec_version": 1,
        "created_at": _now(),
        "source_id": evidence_package.source_id,
        "source_name": evidence_package.source_name,
        "affected_anchor_file": anchor_file_rel,
        "affected_rules": affected_rules,
        "unmapped": is_unmapped,
        "change_summary": _build_change_summary(evidence_package.diffs),
        "proposal_anchor_hash": proposal_anchor_hash,
        "evidence_id": evidence_package.evidence_id,
        "metadata_hash": "",
    }
    meta_for_hash = {k: v for k, v in metadata.items() if k != "metadata_hash"}
    metadata["metadata_hash"] = _sha256(
        json.dumps(meta_for_hash, sort_keys=True, default=str)
    )
    (proposal_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, default=str),
        encoding="utf-8",
    )

    print(f"  Written: {proposal_dir}")
    if not is_unmapped:
        print(f"  Affected rules: {', '.join(affected_rules)}")
    print(f"  Changes: {evidence_package.change_count}")
    if evidence_package.critical_changes:
        print(f"  ⚠ Critical: {len(evidence_package.critical_changes)} severity escalation(s)")

    return proposal_dir