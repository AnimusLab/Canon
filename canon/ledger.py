"""
Canon ledger.
Append-only, hash-chained log shared by the monitor and the approval gate.

chain_hash = SHA256(prev_entry_hash + ":" + payload_hash)

Note: the chain binds each entry to its predecessor and to its payload hash.
It does not cover entry_id / entry_type / recorded_at (that would change the
on-disk format of existing ledgers).
"""
from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from canon.models import CanonLedgerEntry

GENESIS_HASH = "0" * 64


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)

    def entries(self) -> list[CanonLedgerEntry]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [CanonLedgerEntry.model_validate_json(l) for l in lines if l.strip()]

    def last_hash(self) -> str:
        entries = self.entries()
        return entries[-1].chain_hash if entries else GENESIS_HASH

    def append(self, entry_type: str, payload_hash: str) -> CanonLedgerEntry:
        entry = CanonLedgerEntry(
            entry_id=str(uuid.uuid4()),
            entry_type=entry_type,
            payload_hash=payload_hash,
            prev_entry_hash=self.last_hash(),
        )
        entry.compute_chain_hash()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(entry.model_dump_json() + "\n")
        return entry

    def verify(self) -> list[str]:
        """Return a list of human-readable problems. Empty list = chain intact."""
        problems: list[str] = []
        if not self.path.exists():
            return problems
        expected_prev = GENESIS_HASH
        lines = self.path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                entry = CanonLedgerEntry.model_validate_json(line)
            except Exception:
                problems.append(f"line {n}: unparseable entry")
                return problems  # chain cannot be followed past this point
            if entry.prev_entry_hash != expected_prev:
                problems.append(f"line {n}: broken link (prev_entry_hash mismatch)")
            recomputed = hashlib.sha256(
                f"{entry.prev_entry_hash}:{entry.payload_hash}".encode()
            ).hexdigest()
            if recomputed != entry.chain_hash:
                problems.append(f"line {n}: chain_hash does not match entry contents")
            expected_prev = entry.chain_hash
        return problems
