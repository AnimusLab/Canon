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

from canon.models import ApprovalRecord, EvidencePackage


class ApprovalGate:
    def __init__(self, canon_dir: Path | None = None):
        self.canon_dir = canon_dir or Path(".canon")
        self.approval_dir = self.canon_dir / "approvals"
        self.approval_dir.mkdir(parents=True, exist_ok=True)

    def record_decision(
        self,
        package: EvidencePackage,
        approved_by: str,
        decision: str,
        justification: str,
    ) -> ApprovalRecord:
        assert decision in ("approved", "rejected", "deferred")
        assert approved_by.strip(), "approved_by must be non-empty"
        assert justification.strip(), "justification required for audit trail"

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
        path.write_text(record.model_dump_json(indent=2))
        return record

    def is_approved(self, evidence_id: str) -> bool:
        for f in self.approval_dir.glob("*.json"):
            data = json.loads(f.read_text())
            if data["evidence_id"] == evidence_id and data["decision"] == "approved":
                return True
        return False

    def verify_integrity(self) -> list[str]:
        tampered = []
        for f in self.approval_dir.glob("*.json"):
            try:
                record = ApprovalRecord.model_validate_json(f.read_text())
                stored_hash = record.record_hash
                recomputed = record.compute_hash()
                if stored_hash != recomputed:
                    tampered.append(record.approval_id)
            except Exception:
                tampered.append(str(f))
        return tampered