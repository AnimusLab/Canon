"""
Canon benchmark suite.
Produces empirical results for the ICAIF paper.
"""
from __future__ import annotations

import json
import statistics
import time
import uuid
from pathlib import Path

from canon.diff.engine import diff_states
from canon.models import (
    ApprovalRecord, CanonLedgerEntry,
    EvidencePackage, SourceState,
)


def _make_source_state(n_rules: int, source_id: str = "bench") -> SourceState:
    rules = {
        f"RULE-{i:04d}": {
            "title": f"Rule {i}",
            "description": f"Description for rule {i}",
            "severity": ["info", "warning", "critical"][i % 3],
            "category": "benchmark",
            "regulatory_refs": ["BENCH-001"],
            "version": "1.0",
        }
        for i in range(n_rules)
    }
    state = SourceState(
        source_id=source_id, source_name="Benchmark Source",
        source_url="https://example.com", rules=rules,
    )
    state.compute_hash()
    return state


def _make_modified_state(baseline: SourceState, n_changes: int) -> SourceState:
    rules = dict(baseline.rules)
    for k in list(rules.keys())[:n_changes]:
        rules[k] = dict(rules[k])
        rules[k]["severity"] = "critical"
        rules[k]["description"] += " [UPDATED]"
    rules[f"RULE-NEW-{uuid.uuid4().hex[:8]}"] = {
        "title": "New Rule", "description": "Newly added governance rule",
        "severity": "critical", "category": "benchmark",
        "regulatory_refs": ["BENCH-002"], "version": "1.1",
    }
    state = SourceState(
        source_id=baseline.source_id, source_name=baseline.source_name,
        source_url=baseline.source_url, rules=rules,
    )
    state.compute_hash()
    return state


def bench(label: str, fn, iterations: int = 1000) -> dict:
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1_000_000)
    s = sorted(times)
    return {
        "label": label, "iterations": iterations,
        "mean_us": round(statistics.mean(times), 2),
        "median_us": round(statistics.median(times), 2),
        "p95_us": round(s[int(0.95 * len(times))], 2),
        "p99_us": round(s[int(0.99 * len(times))], 2),
        "throughput_per_sec": round(1_000_000 / statistics.mean(times), 1),
    }


def run_benchmarks(iterations: int = 1000) -> list[dict]:
    results = []
    baseline = _make_source_state(100)
    current = _make_modified_state(baseline, n_changes=5)
    baseline_lg = _make_source_state(500)
    current_lg = _make_modified_state(baseline_lg, n_changes=20)
    pkg = diff_states(baseline, current)

    results.append(bench("SHA-256 source state hash (100 rules)", lambda: baseline.compute_hash(), iterations))
    results.append(bench("Diff engine - 100 rules, 5 changes", lambda: diff_states(baseline, current), iterations))
    results.append(bench("Diff engine - 500 rules, 20 changes", lambda: diff_states(baseline_lg, current_lg), iterations))
    results.append(bench("Evidence package hash generation", lambda: pkg.compute_hash(), iterations))

    entry = CanonLedgerEntry(
        entry_id=str(uuid.uuid4()), entry_type="evidence",
        payload_hash=pkg.evidence_hash, prev_entry_hash="0" * 64,
    )
    results.append(bench("Ledger chain hash computation", lambda: entry.compute_chain_hash(), iterations))

    record = ApprovalRecord(
        approval_id=str(uuid.uuid4()), evidence_id=pkg.evidence_id,
        approved_by="benchmark-user", decision="approved",
        justification="Benchmark run", evidence_hash=pkg.evidence_hash,
    )
    results.append(bench("Approval record hash (tamper-evident)", lambda: record.compute_hash(), iterations))

    def e2e():
        s1 = _make_source_state(100)
        s2 = _make_modified_state(s1, 3)
        p = diff_states(s1, s2)
        p.compute_hash()
        e = CanonLedgerEntry(
            entry_id=str(uuid.uuid4()), entry_type="evidence",
            payload_hash=p.evidence_hash, prev_entry_hash="0" * 64,
        )
        e.compute_chain_hash()

    results.append(bench("End-to-end: diff + evidence hash + ledger entry", e2e, iterations=200))
    return results


def print_results(results: list[dict]) -> None:
    col_w = [50, 10, 10, 10, 10, 16]
    header = (
        f"{'Operation':<{col_w[0]}}"
        f"{'Mean(µs)':>{col_w[1]}}"
        f"{'P95(µs)':>{col_w[2]}}"
        f"{'P99(µs)':>{col_w[3]}}"
        f"{'Iter':>{col_w[4]}}"
        f"{'Throughput/s':>{col_w[5]}}"
    )
    sep = "-" * sum(col_w)
    print(f"\n{sep}\n{header}\n{sep}")
    for r in results:
        print(
            f"{r['label']:<{col_w[0]}}"
            f"{r['mean_us']:>{col_w[1]}.2f}"
            f"{r['p95_us']:>{col_w[2]}.2f}"
            f"{r['p99_us']:>{col_w[3]}.2f}"
            f"{r['iterations']:>{col_w[4]}}"
            f"{r['throughput_per_sec']:>{col_w[5]}.1f}"
        )
    print(sep)


if __name__ == "__main__":
    results = run_benchmarks(iterations=1000)
    print_results(results)
    out = Path("benchmarks/results.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")