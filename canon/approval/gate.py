"""
Canon approval gate.
Human review and approval of EvidencePackages.
No automated policy changes. Ever.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from canon.ledger import Ledger
from canon.models import ApprovalRecord, EvidencePackage


class ApprovalGate:
    def __init__(self, canon_dir: Path | None = None):
        self.canon_dir = canon_dir or Path(".canon")
        self.approval_dir = self.canon_dir / "approvals"
        self.approval_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(self.canon_dir / "ledger.jsonl")

    def record_decision(
        self,
        package: EvidencePackage,
        approved_by: str,
        decision: str,
        justification: str,
    ) -> ApprovalRecord:
        # Explicit exceptions, not asserts: asserts vanish under `python -O`,
        # and this is an audit control.
        if decision not in ("approved", "rejected", "deferred"):
            raise ValueError(f"invalid decision: {decision!r}")
        if not approved_by.strip():
            raise ValueError("approved_by must be non-empty")
        if not justification.strip():
            raise ValueError("justification required for audit trail")

        record = ApprovalRecord(
            approval_id=str(uuid.uuid4()),
            evidence_id=package.evidence_id,
            approved_by=approved_by,
            decision=decision,
            justification=justification,
            evidence_hash=package.evidence_hash,
        )
        record.compute_hash()

        path = self.approval_dir / f"{record.approval_id}.json"
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
        self.ledger.append("approval", record.record_hash)
        return record

    def is_approved(self, evidence_id: str) -> bool:
        for f in self.approval_dir.glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            if data["evidence_id"] == evidence_id and data["decision"] == "approved":
                return True
        return False

    def verify_integrity(self) -> list[str]:
        tampered = []
        for f in self.approval_dir.glob("*.json"):
            try:
                record = ApprovalRecord.model_validate_json(f.read_text(encoding="utf-8"))
                stored_hash = record.record_hash
                recomputed = record.compute_hash()
                if stored_hash != recomputed:
                    tampered.append(record.approval_id)
            except Exception:
                tampered.append(str(f))
        return tampered

    def verify_ledger_binding(self) -> list[str]:
        """
        Cross-check approval files against ledger "approval" entries, both ways:
        - every ledger approval entry must have a matching record file
          (catches deleted approval files)
        - every record file must have a ledger entry
          (catches records written outside the gate, or ledger entries removed)
        Records created before approvals were ledgered will be reported here.
        """
        problems: list[str] = []
        ledgered = {
            e.payload_hash for e in self.ledger.entries() if e.entry_type == "approval"
        }
        on_disk: dict[str, str] = {}
        for f in self.approval_dir.glob("*.json"):
            try:
                rec = ApprovalRecord.model_validate_json(f.read_text(encoding="utf-8"))
                on_disk[rec.record_hash] = rec.approval_id
            except Exception:
                continue  # reported by verify_integrity()
        for h in sorted(ledgered - on_disk.keys()):
            problems.append(f"ledger approval entry {h[:12]}... has no record file")
        for h, approval_id in sorted(on_disk.items(), key=lambda kv: kv[1]):
            if h not in ledgered:
                problems.append(f"approval {approval_id} is not in the ledger")
        return problems
