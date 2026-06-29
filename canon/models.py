"""
Canon core models.
Domain-agnostic. No Anchor imports. No framework-specific types.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DEPRECATED = "deprecated"
    REMOVED = "removed"


class SeverityLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class SourceState(BaseModel):
    """Snapshot of an external governance source at a point in time."""
    source_id: str
    source_name: str
    source_url: str
    commit_sha: str | None = None
    version_tag: str | None = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rules: dict[str, Any] = Field(default_factory=dict)
    raw_hash: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps(self.rules, sort_keys=True).encode()
        self.raw_hash = hashlib.sha256(payload).hexdigest()
        return self.raw_hash


class RuleDiff(BaseModel):
    """A single rule-level change between two SourceState snapshots."""
    rule_id: str
    change_type: ChangeType
    old_value: Any | None = None
    new_value: Any | None = None
    severity_delta: str | None = None
    regulatory_mappings_affected: list[str] = Field(default_factory=list)
    description: str = ""


class EvidencePackage(BaseModel):
    """
    Structured evidence produced by Canon when an external source changes.
    Human approval is required before any constitution update.
    """
    evidence_id: str
    source_id: str
    source_name: str
    produced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    baseline_hash: str
    current_hash: str
    diffs: list[RuleDiff] = Field(default_factory=list)
    staleness_days: int = 0
    requires_review: bool = True
    evidence_hash: str = ""

    def compute_hash(self) -> str:
        payload = self.model_dump_json(exclude={"evidence_hash"})
        self.evidence_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.evidence_hash

    @property
    def change_count(self) -> int:
        return len(self.diffs)

    @property
    def critical_changes(self) -> list[RuleDiff]:
        return [d for d in self.diffs if d.severity_delta and "CRITICAL" in d.severity_delta]


class ApprovalRecord(BaseModel):
    """
    Tamper-evident record of a human approval decision on an EvidencePackage.
    Individually attributed. Written to the Canon ledger.
    """
    approval_id: str
    evidence_id: str
    approved_by: str
    decision: str
    justification: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_hash: str
    record_hash: str = ""

    def compute_hash(self) -> str:
        payload = self.model_dump_json(exclude={"record_hash"})
        self.record_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.record_hash


class CanonLedgerEntry(BaseModel):
    """Single entry in the Canon append-only ledger."""
    entry_id: str
    entry_type: str
    payload_hash: str
    prev_entry_hash: str
    chain_hash: str = ""
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def compute_chain_hash(self) -> str:
        payload = f"{self.prev_entry_hash}:{self.payload_hash}"
        self.chain_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.chain_hash