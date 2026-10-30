# Canon 🏛️

> **Deterministic governance knowledge integrity engine for AI systems.**

Canon is a lightweight, tamper-evident governance synchronization engine designed to fetch, verify, diff, and audit external regulatory and organizational policies. It acts as the structured source-of-truth pipeline for AI constitutional guardrails.

---

## Key Features

- **Source Adapters**: Extensible adapters for crawling structured authorities (e.g., OWASP LLM Top 10, NIST AI Risk Management Framework, FINOS AI Governance).
- **Deterministic State Hashing**: Cryptographically hashes governance rulesets to detect changes instantly and reliably.
- **Evidence Packages**: Generates comprehensive diff packages detailing added, modified, deprecated, or removed rules, including severity deltas.
- **Tamper-Evident Ledger**: Logs all transitions to an append-only, hash-chained ledger (`ledger.jsonl`) to ensure auditability.
- **Human-in-the-Loop Approvals**: Approval gate that records each decision (approver, decision, justification) in a hash-chained approval record. Records are tamper-evident, not digitally signed.
- **Fast Core Operations**: Hashing, diffing and ledger operations on in-memory data run in microseconds (see [Microbenchmarks](#microbenchmarks); network fetching is separate and not included).

---

## Installation & Setup

```bash
pip install canon-governance
canon --help
```

A GitHub token is **optional**. Canon fetches public GitHub-hosted sources without the GitHub REST API wherever possible (see [How sources are fetched](#how-sources-are-fetched)). A token only raises the API rate limit and lets Canon discover new OWASP entries automatically:

```bash
export GITHUB_TOKEN=ghp_your_token_here      # macOS / Linux
$env:GITHUB_TOKEN = "ghp_your_token_here"    # Windows PowerShell
```

<details>
<summary>Development install (from source)</summary>

```bash
git clone https://github.com/AnimusLab/Canon.git
cd Canon
pip install -e .
pytest
```
</details>

---

## CLI Usage

### 1. Fetch Latest Policies
Fetch state from all tracked governance sources, compute hashes, and compare them against local baselines.
```bash
canon fetch
```
A failure in one source does not stop the others. Failed sources are listed, warnings are shown for reduced-fidelity fetches, and the command exits non-zero if any source failed.

### 2. Review Pending Decisions
Interactively inspect and approve/reject/defer pending evidence packages. Each decision is written to `.canon/approvals/` and appended to the ledger. Deferred packages stay in the pending queue; approved and rejected ones leave it.
```bash
canon review
```

### 3. Verify Ledger Integrity
Verify the ledger's hash chain, every approval record's hash, and that approval records and ledger `approval` entries match one another. Exits non-zero on any violation.
```bash
canon verify
```

### 4. Check Governance Status
Display the active version, rule count, last fetch time, and state hashes of all tracked sources.
```bash
canon status
```

---

## How sources are fetched

| Source | Method | Needs token? |
| :--- | :--- | :--- |
| FINOS AI Governance Framework | One repository archive download (`codeload.github.com`), commit SHA read from the archive | No |
| OWASP LLM Top 10 | GitHub API for file discovery, raw files at a pinned commit. If the API is rate-limited: commit SHA via git smart-HTTP and a bundled file list (`raw-manifest`) | No (token enables discovery of new entries) |
| NIST AI RMF | NIST CPRT API. If unreachable: a bundled snapshot of the core framework, marked `degraded` | No |

Each stored snapshot records how it was fetched (`canon status`, "Fetched via"). A `degraded` snapshot is never compared against, and never replaces, a baseline obtained from a live fetch, so an outage cannot create false "changes". Every rule also stores a hash of its full source text, so any edit to a source document is detected, not only edits to the extracted title, description or severity.

---

## Microbenchmarks

These measure Canon's in-memory operations (hashing, diffing, ledger chaining) on synthetic data. They do **not** include network fetching, file I/O or proposal generation. Results are from a single machine on Python 3.14 and are provided for reference only; they are not peer-reviewed.

| Operation | Mean Latency | Median Latency | P95 Latency | P99 Latency | Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Source State Hash (100 rules)** | 135.36 µs | 129.00 µs | 155.10 µs | 253.40 µs | 7,387.9 /s |
| **Diff Engine (100 rules, 5 changes)** | 88.12 µs | 83.30 µs | 104.10 µs | 176.00 µs | 11,347.8 /s |
| **Diff Engine (500 rules, 20 changes)** | 398.27 µs | 366.70 µs | 548.10 µs | 834.10 µs | 2,510.8 /s |
| **Evidence Hash Generation** | 12.27 µs | 11.20 µs | 11.50 µs | 18.70 µs | 81,496.9 /s |
| **Ledger Chain Hashing** | 1.34 µs | 1.20 µs | 1.20 µs | 1.40 µs | 744,990.0 /s |
| **Approval Record Hashing** | 3.34 µs | 3.30 µs | 3.40 µs | 3.70 µs | 299,043.3 /s |
| **End-to-End Pipeline (Diff + Hash + Ledger)** | **490.10 µs** | **450.05 µs** | **734.20 µs** | **1,112.60 µs** | **2,040.4 /s** |

---

## Next Steps & Integrations

For a deep dive into how Canon integrates with the broader ecosystem, please read the [Architecture Document](https://github.com/AnimusLab/Canon/blob/main/ARCHITECTURE.md).
