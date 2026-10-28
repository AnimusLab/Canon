# Canon 🏛️

> **Deterministic governance knowledge integrity engine for AI systems.**

Canon is a lightweight, tamper-evident governance synchronization engine designed to fetch, verify, diff, and audit external regulatory and organizational policies. It acts as the structured source-of-truth pipeline for AI constitutional guardrails.

---

## Key Features

- **Source Adapters**: Extensible adapters for crawling structured authorities (e.g., OWASP LLM Top 10, NIST AI Risk Management Framework, FINOS AI Governance).
- **Deterministic State Hashing**: Cryptographically hashes governance rulesets to detect changes instantly and reliably.
- **Evidence Packages**: Generates comprehensive diff packages detailing added, modified, deprecated, or removed rules, including severity deltas.
- **Tamper-Evident Ledger**: Logs all transitions to an append-only, hash-chained ledger (`ledger.jsonl`) to ensure auditability.
- **Human-in-the-Loop Approvals**: Approval gate that secures state transitions behind individually-attributed cryptographic approval records.
- **Microsecond Latency**: Built for high-frequency runtime checks with execution overhead under a millisecond.

---

## Installation & Setup

1. Activate your environment and install dependencies:
   ```bash
   conda activate canon
   pip install -e .
   ```
2. Configure your GitHub token (optional, but recommended to avoid rate limits):
   ```bash
   set GITHUB_TOKEN=ghp_your_token_here
   ```

---

## CLI Usage

### 1. Fetch Latest Policies
Fetch state from all tracked governance sources, compute hashes, and compare them against local baselines.
```bash
canon fetch
```

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

## Empirical Performance (ICAIF Benchmarks)

Under benchmark conditions (compiled on Python 3.14), Canon operates at microsecond scales, presenting negligible overhead for enterprise deployment.

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

For a deep dive into how Canon integrates with the broader ecosystem, please read the [Architecture Document](ARCHITECTURE.md).
