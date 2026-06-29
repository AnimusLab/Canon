import pytest
import json
from pathlib import Path
from canon.models import EvidencePackage
from canon.approval.gate import ApprovalGate

def test_approval_gate_lifecycle(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)
    
    pkg = EvidencePackage(
        evidence_id="ev-123",
        source_id="test",
        source_name="Test",
        baseline_hash="base",
        current_hash="curr"
    )
    pkg.compute_hash()
    
    # Assert not approved initially
    assert not gate.is_approved("ev-123")
    
    # Record approval decision
    record = gate.record_decision(
        package=pkg,
        approved_by="Auditor Alice",
        decision="approved",
        justification="Verified regulatory compliance."
    )
    
    assert record.decision == "approved"
    assert record.approved_by == "Auditor Alice"
    
    # Check if now approved
    assert gate.is_approved("ev-123")
    
    # Verify integrity (should be clean)
    assert len(gate.verify_integrity()) == 0

def test_approval_gate_tamper_detection(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)
    
    pkg = EvidencePackage(
        evidence_id="ev-123",
        source_id="test",
        source_name="Test",
        baseline_hash="base",
        current_hash="curr"
    )
    pkg.compute_hash()
    
    record = gate.record_decision(
        package=pkg,
        approved_by="Auditor Alice",
        decision="approved",
        justification="Verified regulatory compliance."
    )
    
    # Corrupt the written file
    path = tmp_path / "approvals" / f"{record.approval_id}.json"
    data = json.loads(path.read_text())
    data["justification"] = "Tampered justification!"
    path.write_text(json.dumps(data, indent=2))
    
    # Verify integrity detects the change
    tampered = gate.verify_integrity()
    assert len(tampered) == 1
    assert tampered[0] == record.approval_id
