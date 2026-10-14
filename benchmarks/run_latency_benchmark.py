"""Latency and Throughput Benchmark for Ingestion and Retrieval Defense Layers."""

import time
from gateway.ingestion.heuristic_scanner import HeuristicScanner
from gateway.ingestion.invisible_text_strip import InvisibleTextStripper
from gateway.retrieval.defensive_formatter import DefensiveFormatter


def benchmark_sanitizer(iterations: int = 1000):
    stripper = InvisibleTextStripper()
    sample = "Employee handbook\u200B with hidden\u200D zero width characters and Cyrillic \u0430 lookalike."
    start = time.perf_counter()
    for _ in range(iterations):
        stripper.sanitize(sample)
    elapsed = time.perf_counter() - start
    print(f"Sanitizer ({iterations} ops): {elapsed*1000:.2f} ms ({elapsed/iterations*1000:.4f} ms/op)")


def benchmark_scanner(iterations: int = 1000):
    scanner = HeuristicScanner()
    sample = "Standard corporate memo regarding vacation policy and manager approvals."
    start = time.perf_counter()
    for _ in range(iterations):
        scanner.scan(sample)
    elapsed = time.perf_counter() - start
    print(f"Scanner ({iterations} ops): {elapsed*1000:.2f} ms ({elapsed/iterations*1000:.4f} ms/op)")


if __name__ == "__main__":
    print("=== Running Gateway Latency Benchmarks ===")
    benchmark_sanitizer()
    benchmark_scanner()
