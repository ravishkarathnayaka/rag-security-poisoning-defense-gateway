"""Retrieval-Time Injection Detector: Distinguishes Passive Reference Data from Active System Commands."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import List

from gateway.ingestion.heuristic_scanner import HeuristicScanner


class ChunkInspectionStatus(str, enum.Enum):
    APPROVED = "APPROVED"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"


@dataclass
class InspectionResult:
    """Security classification result for a retrieved context chunk."""

    chunk_id: str
    status: ChunkInspectionStatus
    risk_score: float
    is_safe: bool
    threat_indicators: List[str] = field(default_factory=list)
    action_taken: str = "PASS"


class InjectionDetector:
    """Detects indirect prompt injection payloads embedded in retrieved chunks prior to LLM compilation."""

    # Explicit attack signifiers attempting conversation hijack or command execution
    COMMAND_EXECUTION_PATTERNS = [
        re.compile(
            r"\b(?:now\s+execute|run\s+the\s+following|evaluate\s+this\s+command|run\s+code\b)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:you\s+must\s+say|answer\s+with\s+only|disclose\s+the\s+hidden|print\s+verbatim)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:attention\s*:\s*new\s+instructions?|system\s+update\s*:\s*override)\b",
            re.IGNORECASE,
        ),
        # Conversation role hijacking
        re.compile(
            r"(?:(?:\n|\A)(?:human|user|assistant|system)\s*:\s*|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\])",
            re.IGNORECASE,
        ),
        # Delimiter escape markers
        re.compile(
            r"(?:<\/untrusted_retrieved_context>|```\s*(?:system|override)|---+\s*END\s+CONTEXT\s*---+)",
            re.IGNORECASE,
        ),
    ]

    def __init__(
        self,
        risk_threshold: float = 0.50,
        heuristic_scanner: HeuristicScanner | None = None,
    ):
        self.risk_threshold = risk_threshold
        self.scanner = heuristic_scanner or HeuristicScanner(risk_threshold=risk_threshold)

    def inspect_chunk(self, chunk_id: str, content: str) -> InspectionResult:
        """Evaluates whether the chunk functions as passive evidence vs. an imperative prompt injection."""
        threat_indicators: List[str] = []
        max_risk = 0.0

        # 1. Check for command execution & conversation boundary hijacking
        for pattern in self.COMMAND_EXECUTION_PATTERNS:
            hits = pattern.findall(content)
            if hits:
                threat_indicators.append(
                    f"Detected hijacking pattern '{pattern.pattern}' ({len(hits)} hit[s])"
                )
                max_risk = max(max_risk, 0.85)

        # 2. Leverage heuristic scanner for instruction density and override keywords
        scan_res = self.scanner.scan(content)
        if scan_res.is_flagged:
            threat_indicators.extend(scan_res.reasons)
            max_risk = max(max_risk, scan_res.risk_score)
        else:
            max_risk = max(max_risk, scan_res.risk_score)

        # 3. Assess status
        if max_risk >= self.risk_threshold or len(threat_indicators) >= 2:
            status = ChunkInspectionStatus.QUARANTINED
            is_safe = False
            action = "QUARANTINE"
        elif max_risk >= (self.risk_threshold * 0.6):
            status = ChunkInspectionStatus.SUSPICIOUS
            is_safe = False
            action = "QUARANTINE"
        else:
            status = ChunkInspectionStatus.APPROVED
            is_safe = True
            action = "PASS"

        return InspectionResult(
            chunk_id=chunk_id,
            status=status,
            risk_score=round(max_risk, 3),
            is_safe=is_safe,
            threat_indicators=threat_indicators,
            action_taken=action,
        )

    def filter_chunks(
        self, chunks: List[dict]
    ) -> tuple[List[dict], List[InspectionResult]]:
        """Filters retrieved chunk list, quarantining malicious items."""
        approved = []
        reports = []

        for c in chunks:
            cid = c.get("id", "unknown")
            text = c.get("content", "")
            report = self.inspect_chunk(cid, text)
            reports.append(report)

            if report.is_safe:
                approved.append(c)

        return approved, reports
