import pytest
from pathlib import Path
from canon.models import SourceState, EvidencePackage
from canon.monitor.monitor import CanonMonitor
from canon.sources.base import BaseSourceAdapter

class DummyAdapter(BaseSourceAdapter):
    source_id = "dummy-source"
    source_name = "Dummy Source"
    source_url = "https://dummy.com"
    
    def __init__(self, rules):
        self.rules_to_return = rules
        
    async def fetch_state(self, client) -> SourceState:
        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            rules=self.rules_to_return
        )
        state.compute_hash()
        return state
        
    def normalise_rules(self, raw):
        return raw

@pytest.mark.anyio
async def test_monitor_run_initial_state(tmp_path):
    adapter = DummyAdapter({"R1": {"title": "R1"}})
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[adapter])
    
    # Run the monitor
    packages = await monitor.run()
    
    # First run establishes baseline, so no package is returned
    assert len(packages) == 0
    
    # Check baseline was saved
    baseline_file = tmp_path / "states" / "dummy-source.json"
    assert baseline_file.exists()
    
    # Check ledger contains the initial state entry
    ledger_lines = (tmp_path / "ledger.jsonl").read_text().strip().splitlines()
    assert len(ledger_lines) == 1
    assert "initial_state" in ledger_lines[0]

@pytest.mark.anyio
async def test_monitor_run_with_changes(tmp_path):
    # Setup initial state
    adapter1 = DummyAdapter({"R1": {"title": "R1"}})
    monitor1 = CanonMonitor(canon_dir=tmp_path, sources=[adapter1])
    await monitor1.run()
    
    # Change rule set and run again
    adapter2 = DummyAdapter({"R1": {"title": "R1 (updated)"}})
    monitor2 = CanonMonitor(canon_dir=tmp_path, sources=[adapter2])
    packages = await monitor2.run()
    
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.change_count == 1
    assert pkg.diffs[0].rule_id == "R1"
    
    # Verify evidence file exists
    evidence_file = tmp_path / "evidence" / f"{pkg.evidence_id}.json"
    assert evidence_file.exists()
    
    # Check ledger has two entries now (initial_state and evidence)
    ledger_lines = (tmp_path / "ledger.jsonl").read_text().strip().splitlines()
    assert len(ledger_lines) == 2
    assert "evidence" in ledger_lines[1]
