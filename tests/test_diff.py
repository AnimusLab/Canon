import pytest
from canon.models import SourceState, ChangeType
from canon.diff.engine import diff_states

def test_diff_states_no_changes():
    baseline = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R1": {"title": "R1", "severity": "info"}}
    )
    baseline.compute_hash()
    
    current = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R1": {"title": "R1", "severity": "info"}}
    )
    current.compute_hash()
    
    pkg = diff_states(baseline, current)
    assert pkg.change_count == 0
    assert not pkg.requires_review

def test_diff_states_added_and_removed():
    baseline = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R1": {"title": "R1", "severity": "info"}}
    )
    baseline.compute_hash()
    
    current = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R2": {"title": "R2", "severity": "warning"}}
    )
    current.compute_hash()
    
    pkg = diff_states(baseline, current)
    assert pkg.change_count == 2
    assert pkg.requires_review
    
    diffs_by_type = {d.change_type: d for d in pkg.diffs}
    assert ChangeType.ADDED in diffs_by_type
    assert ChangeType.REMOVED in diffs_by_type
    
    assert diffs_by_type[ChangeType.ADDED].rule_id == "R2"
    assert diffs_by_type[ChangeType.REMOVED].rule_id == "R1"

def test_diff_states_modified():
    baseline = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R1": {"title": "R1", "severity": "info", "description": "old"}}
    )
    baseline.compute_hash()
    
    current = SourceState(
        source_id="test",
        source_name="Test",
        source_url="http://test",
        rules={"R1": {"title": "R1", "severity": "critical", "description": "new"}}
    )
    current.compute_hash()
    
    pkg = diff_states(baseline, current)
    assert pkg.change_count == 1
    diff = pkg.diffs[0]
    assert diff.change_type == ChangeType.MODIFIED
    assert diff.rule_id == "R1"
    assert diff.severity_delta == "INFO -> CRITICAL"
    assert diff.old_value["description"] == "old"
    assert diff.new_value["description"] == "new"
