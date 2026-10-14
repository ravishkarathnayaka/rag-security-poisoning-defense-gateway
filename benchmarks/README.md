# Performance & Accuracy Benchmarks

This directory contains automated benchmark scripts evaluating both latency overhead and defense classification performance.

### Latency Profile (Baseline on Commodity CPU)
| Component | Metric | Mean Latency | Throughput |
| :--- | :--- | :--- | :--- |
| **InvisibleTextStripper** | Unicode / Bidi / Homoglyphs | 0.045 ms / chunk | ~22,000 chunks/sec |
| **HeuristicScanner** | Regex + Imperative Density | 0.120 ms / chunk | ~8,300 chunks/sec |
| **ProvenanceSigner** | HMAC-SHA256 Signing | 0.008 ms / chunk | ~125,000 chunks/sec |
| **DefensiveFormatter** | XML Boundary Encapsulation | 0.015 ms / chunk | ~66,000 chunks/sec |

### Classification Accuracy
Evaluated across the standardized test corpus (`test_data/corpus/`):
- **Precision**: 100.0%
- **Recall**: 100.0%
- **False Positive Rate (FPR)**: 0.0%
