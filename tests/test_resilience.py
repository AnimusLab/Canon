import httpx
import pytest

from canon.models import SourceState
from canon.monitor.monitor import CanonMonitor
from canon.sources.base import BaseSourceAdapter
from canon.sources.nist import NISTAdapter


class ResilienceAdapter(BaseSourceAdapter):
    source_id = "resilience-test"
    source_name = "Resilience Test"
    source_url = "https://example.test"

    def __init__(self, rules=None, *, degraded=False, error=None, fetch_note=None):
        self.rules = rules or {"R1": {"title": "Rule 1"}}
        self.degraded = degraded
        self.error = error
        self.fetch_note = fetch_note

    async def fetch_state(self, client):
        if self.error:
            raise self.error

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            rules=self.rules,
            fetch_method="test",
            degraded=self.degraded,
            fetch_note=self.fetch_note,
        )
        state.compute_hash()
        return state

    def normalise_rules(self, raw):
        return raw


@pytest.mark.anyio
async def test_one_source_failure_does_not_stop_other_sources(tmp_path):
    failing = ResilienceAdapter(error=httpx.ConnectError("offline"))
    failing.source_id = "failing-source"

    healthy = ResilienceAdapter()
    healthy.source_id = "healthy-source"

    monitor = CanonMonitor(canon_dir=tmp_path, sources=[failing, healthy])
    packages = await monitor.run()

    assert "failing-source" in monitor.errors
    assert "healthy-source" not in monitor.errors
    assert (tmp_path / "states" / "healthy-source.json").exists()
    assert packages == []


@pytest.mark.anyio
async def test_monitor_clears_old_errors_on_next_run(tmp_path):
    adapter = ResilienceAdapter(error=RuntimeError("temporary failure"))
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[adapter])

    await monitor.run()
    assert "resilience-test" in monitor.errors

    adapter.error = None
    await monitor.run()

    assert monitor.errors == {}


@pytest.mark.anyio
async def test_degraded_fetch_does_not_overwrite_healthy_baseline(tmp_path):
    healthy = ResilienceAdapter(rules={"R1": {"title": "Healthy"}})
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[healthy])
    await monitor.run()

    baseline_path = tmp_path / "states" / "resilience-test.json"
    original = SourceState.model_validate_json(
        baseline_path.read_text(encoding="utf-8")
    )
    assert original.degraded is False

    degraded = ResilienceAdapter(
        rules={"R1": {"title": "Fallback"}},
        degraded=True,
        fetch_note="Using bundled fallback",
    )
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[degraded])
    packages = await monitor.run()

    saved = SourceState.model_validate_json(
        baseline_path.read_text(encoding="utf-8")
    )
    assert packages == []
    assert saved.raw_hash == original.raw_hash
    assert saved.rules == original.rules
    assert any("degraded" in warning.lower() for warning in monitor.warnings)


@pytest.mark.anyio
async def test_healthy_fetch_recovers_from_degraded_baseline(tmp_path):
    degraded = ResilienceAdapter(
        rules={"R1": {"title": "Fallback"}},
        degraded=True,
    )
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[degraded])
    await monitor.run()

    healthy = ResilienceAdapter(
        rules={"R1": {"title": "Live source"}},
        degraded=False,
    )
    monitor = CanonMonitor(canon_dir=tmp_path, sources=[healthy])
    packages = await monitor.run()

    assert len(packages) == 1
    assert packages[0].change_count == 1

    saved = SourceState.model_validate_json(
        (tmp_path / "states" / "resilience-test.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved.degraded is False
    assert saved.rules["R1"]["title"] == "Live source"


@pytest.mark.anyio
async def test_nist_failure_marks_bundled_fallback_as_degraded(monkeypatch):
    async def fail_fetch(self, client):
        raise httpx.ConnectError("NIST unavailable")

    monkeypatch.setattr(NISTAdapter, "_fetch_from_cprt", fail_fetch)

    adapter = NISTAdapter()
    async with httpx.AsyncClient() as client:
        state = await adapter.fetch_state(client)

    assert state.degraded is True
    assert state.fetch_method == "bundled-fallback"
    assert state.rules
    assert state.fetch_note
    assert "not live NIST data" in state.fetch_note
