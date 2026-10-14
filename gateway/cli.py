"""Command Line Interface (CLI) for RAG Security Gateway Operations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from gateway.ingestion.heuristic_scanner import HeuristicScanner
from gateway.ingestion.invisible_text_strip import InvisibleTextStripper


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rag-gateway",
        description="RAG Security Gateway: Heuristic Scanning, Steganography Stripping & Provenance Verification.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a document or text string for injection threats.")
    scan_parser.add_argument("--file", "-f", type=str, help="Path to text/markdown document to scan.")
    scan_parser.add_argument("--text", "-t", type=str, help="Direct text string to scan.")
    scan_parser.add_argument("--sanitize", action="store_true", help="Perform unicode sanitization before scan.")

    # verify-hash command
    verify_parser = subparsers.add_parser("verify-hash", help="Compute SHA-256 fingerprint for document content.")
    verify_parser.add_argument("--file", "-f", type=str, required=True, help="Path to file to fingerprint.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.command == "scan":
        content = ""
        if args.file:
            path = Path(args.file)
            if not path.exists():
                print(f"Error: file '{args.file}' not found", file=sys.stderr)
                return 1
            content = path.read_text(encoding="utf-8", errors="replace")
        elif args.text:
            content = args.text
        else:
            print("Error: must provide either --file or --text", file=sys.stderr)
            return 1

        scanner = HeuristicScanner()
        stripper = InvisibleTextStripper()

        if args.sanitize:
            cleaned, tele = stripper.strip_invisible_characters(content)
            print(f"[Sanitization Telemetry] zero_width={tele.zero_width_chars_removed}, homoglyphs={tele.homoglyphs_normalized}")
            content = cleaned

        res = scanner.scan(content)
        print(f"[Scan Result] flagged={res.is_flagged}, risk_score={res.risk_score:.2f}, category={res.threat_category}")
        if res.matched_patterns:
            print(f"Matched Patterns: {', '.join(res.matched_patterns)}")
        return 0 if not res.is_flagged else 2

    elif args.command == "verify-hash":
        import hashlib
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file '{args.file}' not found", file=sys.stderr)
            return 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"SHA-256 ({path.name}): {digest}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
