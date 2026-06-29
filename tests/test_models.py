import pytest
from datetime import datetime, timezone
from canon.models import SourceState, RuleDiff, EvidencePackage, ApprovalRecord, CanonLedgerEntry, ChangeType

def test_source_state_hash():
    state = SourceState(
        source_id="test-source",
        source_name="Test Source",
        source_url="https://test.com",
        rules={
            "RULE-01": {"title": "Test Rule", "severity": "warning"}
        }
    )
    old_hash = state.compute_hash()
    assert len(old_hash) == 64
    
    # Check that sorting keys produces deterministic hash
    state2 = SourceState(
        source_id="test-source",
        source_name="Test Source",
        source_url="https://test.com",
        rules={
            "RULE-01": {"severity": "warning", "title": "Test Rule"}
        }
    )
    new_hash = state2.compute_hash()
    assert old_hash == new_hash

def test_evidence_package_properties():
    diff1 = RuleDiff(
        rule_id="RULE-01",
        change_type=ChangeType.ADDED,
        new_value={"title": "A"},
        description="Added RULE-01"
    )
    diff2 = RuleDiff(
        rule_id="RULE-02",
        change_type=ChangeType.MODIFIED,
        severity_delta="INFO -> CRITICAL",
        description="Modified RULE-02"
    )
    
    pkg = EvidencePackage(
        evidence_id="ev-123",
        source_id="test-source",
        source_name="Test Source",
        baseline_hash="baseline",
        current_hash="current",
        diffs=[diff1, diff2]
    )
    
    assert pkg.change_count == 2
    assert len(pkg.critical_changes) == 1
    assert pkg.critical_changes[0].rule_id == "RULE-02"
    
    # Test hash computation
    pkg_hash = pkg.compute_hash()
    assert len(pkg_hash) == 64

def test_approval_record_hash():
    record = ApprovalRecord(
        approval_id="app-123",
        evidence_id="ev-123",
        approved_by="Auditor",
        decision="approved",
        justification="Verified compliance.",
        evidence_hash="ev-hash"
    )
    rec_hash = record.compute_hash()
    assert len(rec_hash) == 64
    assert record.record_hash == rec_hash

def test_ledger_entry_chain_hash():
    entry = CanonLedgerEntry(
        entry_id="entry-123",
        entry_type="evidence",
        payload_hash="payload-hash",
        prev_entry_hash="prev-hash"
    )
    chain_hash = entry.compute_chain_hash()
    assert len(chain_hash) == 64
    assert entry.chain_hash == chain_hash
