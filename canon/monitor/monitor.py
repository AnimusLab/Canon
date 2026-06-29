"""
Canon monitor.
Orchestrates fetching, diffing, and ledger recording across all sources.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import httpx

from canon.diff.engine import diff_states
from canon.models import CanonLedgerEntry, EvidencePackage, SourceState
from canon.sources.base import BaseSourceAdapter
from canon.sources.finos import FINOSAdapter
from canon.sources.nist import NISTAdapter
from canon.sources.owasp import OWASPAdapter

_DEFAULT_SOURCES: list[BaseSourceAdapter] = [
    FINOSAdapter(),
    OWASPAdapter(),
    NISTAdapter(),
]

_GENESIS_HASH = "0" * 64


class CanonMonitor:
    def __init__(
        self,
        canon_dir: Path | None = None,
        sources: list[BaseSourceAdapter] | None = None,
    ):
        self.canon_dir = canon_dir or Path(".canon")
        self.canon_dir.mkdir(parents=True, exist_ok=True)
        self.sources = sources or _DEFAULT_SOURCES
        self.ledger_path = self.canon_dir / "ledger.jsonl"
        self.states_dir = self.canon_dir / "states"
        self.states_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.canon_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, github_token: str | None = None) -> list[EvidencePackage]:
        headers = {}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        packages: list[EvidencePackage] = []
        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            for adapter in self.sources:
                pkg = await self._process_source(adapter, client)
                if pkg:
                    packages.append(pkg)
        return packages

    async def _process_source(
        self, adapter: BaseSourceAdapter, client: httpx.AsyncClient
    ) -> EvidencePackage | None:
        start = time.perf_counter()
        current = await adapter.fetch_state(client)
        fetch_ms = (time.perf_counter() - start) * 1000

        baseline_path = self.states_dir / f"{adapter.source_id}.json"
        if not baseline_path.exists():
            baseline_path.write_text(current.model_dump_json(indent=2))
            self._write_ledger_entry("initial_state", current.raw_hash)
            return None

        baseline = SourceState.model_validate_json(baseline_path.read_text())

        diff_start = time.perf_counter()
        package = diff_states(baseline, current)
        diff_ms = (time.perf_counter() - diff_start) * 1000

        object.__setattr__(package, "_fetch_ms", round(fetch_ms, 2))
        object.__setattr__(package, "_diff_ms", round(diff_ms, 2))

        if package.change_count > 0:
            ep_path = self.evidence_dir / f"{package.evidence_id}.json"
            ep_path.write_text(package.model_dump_json(indent=2))
            baseline_path.write_text(current.model_dump_json(indent=2))
            self._write_ledger_entry("evidence", package.evidence_hash)

        return package

    def _write_ledger_entry(self, entry_type: str, payload_hash: str) -> None:
        prev_hash = self._get_last_chain_hash()
        entry = CanonLedgerEntry(
            entry_id=str(uuid.uuid4()),
            entry_type=entry_type,
            payload_hash=payload_hash,
            prev_entry_hash=prev_hash,
        )
        entry.compute_chain_hash()
        with self.ledger_path.open("a") as f:
            f.write(entry.model_dump_json() + "\n")

    def _get_last_chain_hash(self) -> str:
        if not self.ledger_path.exists():
            return _GENESIS_HASH
        lines = self.ledger_path.read_text().strip().splitlines()
        if not lines:
            return _GENESIS_HASH
        last = CanonLedgerEntry.model_validate_json(lines[-1])
        return last.chain_hash

    def load_pending_evidence(self) -> list[EvidencePackage]:
        approved = self._load_approved_ids()
        packages = []
        for ep_file in sorted(self.evidence_dir.glob("*.json")):
            pkg = EvidencePackage.model_validate_json(ep_file.read_text())
            if pkg.evidence_id not in approved:
                packages.append(pkg)
        return packages

    def _load_approved_ids(self) -> set[str]:
        approval_dir = self.canon_dir / "approvals"
        if not approval_dir.exists():
            return set()
        ids = set()
        for f in approval_dir.glob("*.json"):
            data = json.loads(f.read_text())
            ids.add(data.get("evidence_id", ""))
        return ids