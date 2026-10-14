"""Accuracy, Precision, Recall, and False Positive Rate Benchmark Suite."""

from pathlib import Path
import json
from gateway.ingestion.heuristic_scanner import HeuristicScanner
from gateway.ingestion.invisible_text_strip import InvisibleTextStripper


def evaluate_corpus_accuracy():
    corpus_dir = Path(__file__).resolve().parent.parent / "test_data" / "corpus"
    meta_path = Path(__file__).resolve().parent.parent / "test_data" / "corpus_metadata.json"

    if not meta_path.exists():
        print("Metadata file not found.")
        return

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    stripper = InvisibleTextStripper()
    scanner = HeuristicScanner()

    tp, fp, tn, fn = 0, 0, 0, 0

    for item in meta["samples"]:
        filepath = corpus_dir / item["file"]
        if not filepath.exists():
            continue
        text = filepath.read_text(encoding="utf-8", errors="replace")
        cleaned, telemetry = stripper.sanitize(text)
        res = scanner.scan(cleaned)
        is_quarantined = res.is_flagged or telemetry.has_anomalies
        expected = item["expected_quarantine"]

        if is_quarantined and expected:
            tp += 1
        elif is_quarantined and not expected:
            fp += 1
        elif not is_quarantined and not expected:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("=== Security Defense Accuracy Metrics ===")
    print(f"True Positives (Threats Blocked): {tp}")
    print(f"True Negatives (Benign Approved): {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall: {recall*100:.1f}%")
    print(f"False Positive Rate: {fpr*100:.1f}%")


if __name__ == "__main__":
    evaluate_corpus_accuracy()
