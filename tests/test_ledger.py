
import json

import pytest

from canon.approval.gate import ApprovalGate
from canon.ledger import GENESIS_HASH, Ledger
from canon.models import ChangeType, EvidencePackage, RuleDiff, SourceState
from canon.monitor.monitor import CanonMonitor
from canon.sources.base import BaseSourceAdapter


def test_ledger_append_chains_entries(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    e1 = ledger.append("initial_state", "a" * 64)
    e2 = ledger.append("evidence", "b" * 64)

    assert e1.prev_entry_hash == GENESIS_HASH
    assert e2.prev_entry_hash == e1.chain_hash
    assert ledger.verify() == []


def test_ledger_detects_payload_tampering(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("evidence", "a" * 64)
    ledger.append("evidence", "b" * 64)

    lines = ledger.path.read_text().splitlines()
    first = json.loads(lines[0])
    first["payload_hash"] = "f" * 64
    lines[0] = json.dumps(first)
    ledger.path.write_text("\n".join(lines) + "\n")

    assert any("line 1" in p for p in ledger.verify())


def test_ledger_detects_deleted_entry(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")

    for h in ("a", "b", "c"):
        ledger.append("evidence", h * 64)

    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text(lines[0] + "\n" + lines[2] + "\n")

    assert any("broken link" in p for p in ledger.verify())


def test_missing_ledger_is_valid(tmp_path):
    assert Ledger(tmp_path / "nope.jsonl").verify() == []


class _Adapter(BaseSourceAdapter):
    source_id = "dummy"
    source_name = "Dummy"
    source_url = "https://dummy.test"

    def __init__(self, rules):
        self.rules = rules

    async def fetch_state(self, client):
        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            rules=self.rules,
        )
        state.compute_hash()
        return state

    def normalise_rules(self, raw):
        return raw


@pytest.mark.anyio
async def test_same_change_is_reported_once(tmp_path):
    await CanonMonitor(
        canon_dir=tmp_path,
        sources=[_Adapter({"R1": {"title": "a"}})],
    ).run()

    changed = _Adapter({"R1": {"title": "b"}})

    first = await CanonMonitor(
        canon_dir=tmp_path,
        sources=[changed],
    ).run()

    second = await CanonMonitor(
        canon_dir=tmp_path,
        sources=[changed],
    ).run()

    assert len(first) == 1
    assert second == []
    assert Ledger(tmp_path / "ledger.jsonl").verify() == []
    assert len(list((tmp_path / "evidence").glob("*.json"))) == 1


def _pkg(eid="ev-1"):
    package = EvidencePackage(
        evidence_id=eid,
        source_id="t",
        source_name="T",
        baseline_hash="b",
        current_hash="c",
    )
    package.compute_hash()
    return package


def test_decision_is_written_to_ledger(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)
    record = gate.record_decision(_pkg(), "alice", "approved", "ok")

    entries = gate.ledger.entries()

    assert [entry.entry_type for entry in entries] == ["approval"]
    assert entries[0].payload_hash == record.record_hash
    assert gate.ledger.verify() == []
    assert gate.verify_ledger_binding() == []


def test_deleted_approval_file_is_detected(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)
    record = gate.record_decision(_pkg(), "alice", "approved", "ok")

    (tmp_path / "approvals" / f"{record.approval_id}.json").unlink()

    assert any("no record file" in p for p in gate.verify_ledger_binding())


def test_unledgered_approval_file_is_detected(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)
    gate.record_decision(_pkg(), "alice", "approved", "ok")
    gate.ledger.path.unlink()

    assert any("not in the ledger" in p for p in gate.verify_ledger_binding())


def test_invalid_input_raises_value_error(tmp_path):
    gate = ApprovalGate(canon_dir=tmp_path)

    with pytest.raises(ValueError):
        gate.record_decision(_pkg(), "alice", "maybe", "x")

    with pytest.raises(ValueError):
        gate.record_decision(_pkg(), "  ", "approved", "x")

    with pytest.raises(ValueError):
        gate.record_decision(_pkg(), "alice", "approved", "")


def test_deferred_stays_pending_rejected_does_not(tmp_path):
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[])
    gate = ApprovalGate(canon_dir=tmp_path)

    for eid in ("ev-defer", "ev-reject"):
        package = _pkg(eid)
        (tmp_path / "evidence" / f"{eid}.json").write_text(
            package.model_dump_json(),
            encoding="utf-8",
        )

    gate.record_decision(_pkg("ev-defer"), "alice", "deferred", "later")
    gate.record_decision(_pkg("ev-reject"), "alice", "rejected", "no")

    assert [
        package.evidence_id
        for package in monitor.load_pending_evidence()
    ] == ["ev-defer"]


def test_cli_verify_exit_codes(tmp_path):
    from typer.testing import CliRunner

    from canon.cli import app

    gate = ApprovalGate(canon_dir=tmp_path)
    gate.record_decision(_pkg(), "alice", "approved", "ok")

    runner = CliRunner()

    assert runner.invoke(
        app,
        ["verify", "--canon-dir", str(tmp_path)],
    ).exit_code == 0

    gate.ledger.path.write_text("garbage\n")

    assert runner.invoke(
        app,
        ["verify", "--canon-dir", str(tmp_path)],
    ).exit_code == 1


# ---- fetch CLI exit codes for source failures --------------------------------

def test_cli_fetch_exits_nonzero_when_source_fails(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from canon.cli import app

    async def fake_run(self, **kwargs):
        self.errors = {"broken-source": "connection failed"}
        self.warnings = []
        return []

    monkeypatch.setattr(CanonMonitor, "run", fake_run)

    result = CliRunner().invoke(
        app,
        ["fetch", "--canon-dir", str(tmp_path)],
    )

    assert result.exit_code == 1
    assert "broken-source" in result.output


def test_cli_fetch_exits_nonzero_when_other_source_produces_evidence(
    tmp_path,
    monkeypatch,
):
    from typer.testing import CliRunner

    from canon.cli import app

    async def fake_run_with_evidence(self, **kwargs):
        self.errors = {"broken-source": "connection failed"}
        self.warnings = []

        return [
            EvidencePackage(
                evidence_id="ev-test",
                source_id="healthy-source",
                source_name="Healthy Source",
                baseline_hash="a" * 64,
                current_hash="b" * 64,
                diffs=[
                    RuleDiff(
                        rule_id="R1",
                        change_type=ChangeType.MODIFIED,
                        description="Rule changed",
                    )
                ],
            )
        ]

    monkeypatch.setattr(
        CanonMonitor,
        "run",
        fake_run_with_evidence,
    )

    result = CliRunner().invoke(
        app,
        ["fetch", "--canon-dir", str(tmp_path)],
    )

    assert result.exit_code == 1
    assert "FAILED broken-source" in result.output
    assert "Healthy Source" in result.output
    assert "pending review" in result.output


def test_cli_fetch_clean_run_exits_zero(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from canon.cli import app

    async def fake_run(self, **kwargs):
        self.errors = {}
        self.warnings = []
        return []

    monkeypatch.setattr(CanonMonitor, "run", fake_run)

    result = CliRunner().invoke(
        app,
        ["fetch", "--canon-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "No changes detected" in result.output
