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
from canon.ledger import GENESIS_HASH, Ledger
from canon.models import EvidencePackage, SourceState
from canon.sources.base import BaseSourceAdapter
from canon.sources.github_fetch import describe_error
from canon.sources.finos import FINOSAdapter
from canon.sources.nist import NISTAdapter
from canon.sources.owasp import OWASPAdapter

_DEFAULT_SOURCES: list[BaseSourceAdapter] = [
    FINOSAdapter(),
    OWASPAdapter(),
    NISTAdapter(),
]

_GENESIS_HASH = GENESIS_HASH  # kept for backwards compatibility


class CanonMonitor:
    """
    Canon's central monitor.
    Fetches all configured sources, diffs against stored baselines,
    produces EvidencePackages, generates proposals, writes to ledger.
    """

    def __init__(
        self,
        canon_dir: Path | None = None,
        sources: list[BaseSourceAdapter] | None = None,
        anchor_repo_root: Path | None = None,
    ):
        self.canon_dir = canon_dir or Path(".canon")
        self.canon_dir.mkdir(parents=True, exist_ok=True)
        self.sources = sources or _DEFAULT_SOURCES
        self.ledger_path = self.canon_dir / "ledger.jsonl"
        self.ledger = Ledger(self.ledger_path)
        self.states_dir = self.canon_dir / "states"
        self.states_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.canon_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # If set, proposals are written to anchor_repo_root/.canon/proposals/
        self.anchor_repo_root = anchor_repo_root
        self.errors: dict[str, str] = {}
        self.warnings: list[str] = []

    async def run(
        self,
        github_token: str | None = None,
        generate_proposals: bool = True,
    ) -> list[EvidencePackage]:
        """
        Fetch all sources independently, diff against baselines, and return
        evidence packages. Errors from one adapter do not stop other sources.
        """
        self.errors = {}
        self.warnings = []

        async def _auth_hook(request: httpx.Request) -> None:
            if github_token and request.url.host == "api.github.com":
                request.headers["Authorization"] = f"Bearer {github_token}"

        packages: list[EvidencePackage] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            event_hooks={"request": [_auth_hook]},
        ) as client:
            for adapter in self.sources:
                try:
                    pkg = await self._process_source(adapter, client)
                except Exception as exc:
                    self.errors[adapter.source_id] = describe_error(exc)
                    continue
                if pkg:
                    packages.append(pkg)

        if generate_proposals and self.anchor_repo_root:
            from canon.proposals.generator import generate_proposal

            for pkg in packages:
                if pkg.change_count > 0:
                    generate_proposal(
                        evidence_package=pkg,
                        anchor_repo_root=self.anchor_repo_root,
                        canon_dir=self.canon_dir,
                    )

        return packages

    async def _process_source(
        self,
        adapter: BaseSourceAdapter,
        client: httpx.AsyncClient,
    ) -> EvidencePackage | None:
        """
        Process a single source adapter.

        - First run for a source: store the baseline, ledger "initial_state", return None.
        - Hash unchanged: return None.
        - Hash changed and rules differ: write the EvidencePackage, ledger "evidence",
          advance the stored baseline to the fetched state, return the package.
        - Hash changed but no diffed field differs (e.g. only version/source_path
          changed): advance the baseline and ledger "state_refresh", return None.

        The baseline advances as soon as evidence is recorded, so the same upstream
        change is not re-reported on every fetch. The change stays in
        .canon/evidence/ until a human approves or rejects it.
        """
        current = await adapter.fetch_state(client)
        if not current.raw_hash:
            current.compute_hash()
        if current.fetch_note:
            self.warnings.append(f"{adapter.source_name}: {current.fetch_note}")

        state_path = self.states_dir / f"{adapter.source_id}.json"

        if not state_path.exists():
            self._save_state(state_path, current)
            self._write_ledger_entry("initial_state", current.raw_hash)
            return None

        baseline = SourceState.model_validate_json(
            state_path.read_text(encoding="utf-8")
        )
        if current.degraded and not baseline.degraded:
            self.warnings.append(
                f"{adapter.source_name}: degraded fetch ignored; kept the existing baseline"
            )
            return None

        if baseline.raw_hash == current.raw_hash:
            return None

        package = diff_states(baseline, current)
        if package.change_count == 0:
            self._save_state(state_path, current)
            self._write_ledger_entry("state_refresh", current.raw_hash)
            return None

        # Order matters: evidence and ledger first, baseline last, so a crash
        # mid-way leads to re-detection rather than a silently lost change.
        evidence_path = self.evidence_dir / f"{package.evidence_id}.json"
        evidence_path.write_text(package.model_dump_json(indent=2), encoding="utf-8")
        self._write_ledger_entry("evidence", package.evidence_hash)
        self._save_state(state_path, current)
        return package

    def _save_state(self, path: Path, state: SourceState) -> None:
        path.write_text(state.model_dump_json(indent=2), encoding="utf-8")

    def _write_ledger_entry(self, entry_type: str, payload_hash: str) -> None:
        self.ledger.append(entry_type, payload_hash)

    def _get_last_chain_hash(self) -> str:
        return self.ledger.last_hash()

    def load_pending_evidence(self) -> list[EvidencePackage]:
        resolved = self._load_resolved_ids()
        packages = []
        for ep_file in sorted(self.evidence_dir.glob("*.json")):
            pkg = EvidencePackage.model_validate_json(
                ep_file.read_text(encoding="utf-8")
            )
            if pkg.evidence_id not in resolved:
                packages.append(pkg)
        return packages

    def _load_resolved_ids(self) -> set[str]:
        """Evidence ids with a final decision. 'deferred' is NOT final."""
        approval_dir = self.canon_dir / "approvals"
        if not approval_dir.exists():
            return set()
        ids = set()
        for f in approval_dir.glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("decision") in ("approved", "rejected"):
                ids.add(data.get("evidence_id", ""))
        return ids
