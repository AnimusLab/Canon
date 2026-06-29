# Canon v0.1.0 — Initial Public Release

**Released**: June 2026

Canon v0.1.0 establishes the deterministic governance policy supply-chain layer that precedes Anchor Static, AnchorJIT, and Anchor Runtime.

## Highlights

- **Deterministic Governance Source Monitoring**: Track, pull, and verify updates from external authorities.
- **Source State Hashing**: Cryptographic guarantees for governance rule states.
- **Evidence Package Generation**: Automated and granular rule changes diffing (added, removed, modified).
- **Human Approval Workflow**: Cryptographic approval gates preventing automatic, un-audited state transitions.
- **Tamper-Evident Approval Ledger**: Append-only, hash-chained audit trails.
- **CLI Interface**: Typer-based CLI implementing `fetch`, `review`, `verify`, and `status`.
- **Comprehensive Documentation**: Complete system documentation in `README.md` and `ARCHITECTURE.md`.
- **Performance Benchmarks**: Microsecond-latency execution results for academic evaluation.

## Performance Benchmarks

| Operation | Mean Latency | Median Latency | P95 Latency | P99 Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Source State Hash (100 rules)** | 135.36 µs | 129.00 µs | 155.10 µs | 253.40 µs |
| **Diff Engine (100 rules, 5 changes)** | 88.12 µs | 83.30 µs | 104.10 µs | 176.00 µs |
| **Diff Engine (500 rules, 20 changes)** | 398.27 µs | 366.70 µs | 548.10 µs | 834.10 µs |
| **Evidence Hash Generation** | 12.27 µs | 11.20 µs | 11.50 µs | 18.70 µs |
| **Ledger Chain Hashing** | 1.34 µs | 1.20 µs | 1.20 µs | 1.40 µs |
| **Approval Record Hashing** | 3.34 µs | 3.30 µs | 3.40 µs | 3.70 µs |
| **End-to-End Pipeline** | **490.10 µs** | **450.05 µs** | **734.20 µs** | **1,112.60 µs** |
