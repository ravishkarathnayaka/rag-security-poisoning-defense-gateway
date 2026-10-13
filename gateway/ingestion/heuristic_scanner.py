"""Ingestion & Pre-Filtering Heuristic Scanner: Instruction Density & Imperative Override Detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple


@dataclass
class HeuristicScanResult:
    """Security analysis result evaluating document risk and instruction density."""

    is_flagged: bool = False
    risk_score: float = 0.0  # 0.0 (benign) to 1.0 (malicious)
    instruction_density: float = 0.0  # Proportion of imperative clauses
    matched_patterns: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    threat_category: str = "BENIGN"


class HeuristicScanner:
    """Evaluates text chunks for prompt injection overrides and high instruction density."""

    # High-confidence prompt override and jailbreak patterns
    INJECTION_PATTERNS: List[Tuple[str, Pattern, float]] = [
        (
            "OVERRIDE_INSTRUCTIONS",
            re.compile(
                r"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|former|system)\s+(?:instructions|prompts|rules|directives|commands)\b",
                re.IGNORECASE,
            ),
            0.95,
        ),
        (
            "SYSTEM_PROMPT_HIJACK",
            re.compile(
                r"\b(?:new\s+system\s+instruction|system\s+prompt\s+override|from\s+now\s+on\s+you\s+are|you\s+are\s+now\s+a\s+DAN|jailbroken\s+mode)\b",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            "ROLE_IMPERSONATION",
            re.compile(
                r"\b(?:act\s+as\s+(?:an?\s+)?(?:unrestricted|evil|rogue|developer|administrator)\s+AI|pretend\s+you\s+have\s+no\s+(?:filters|rules|ethics))\b",
                re.IGNORECASE,
            ),
            0.85,
        ),
        (
            "DELIMITER_ESCAPE_ATTEMPT",
            re.compile(
                r"(?:<\/untrusted_retrieved_context>|<\/system>|\[\/INST\]|<<SYS>>|```\s*markdown\s*end|===+\s*END\s+(?:SYSTEM|CONTEXT)\s*===+)",
                re.IGNORECASE,
            ),
            0.90,
        ),
        (
            "DATA_EXFILTRATION_COMMAND",
            re.compile(
                r"\b(?:exfiltrate|send\s+(?:all|the)\s+(?:passwords|secrets|keys|tokens|context|history)\s+to|curl\s+https?:\/\/|fetch\(['\"]https?:\/\/)\b",
                re.IGNORECASE,
            ),
            0.85,
        ),
        (
            "OUTPUT_REDIRECTION",
            re.compile(
                r"\b(?:do\s+not\s+(?:summarize|answer|follow\s+the\s+user)|instead\s+output\s+only|your\s+only\s+response\s+must\s+be)\b",
                re.IGNORECASE,
            ),
            0.75,
        ),
        (
            "PROMPT_LEAK_INSPECTION",
            re.compile(
                r"\b(?:repeat\s+(?:everything|your\s+system\s+prompt)|print\s+the\s+initial\s+prompt|reveal\s+hidden\s+instructions)\b",
                re.IGNORECASE,
            ),
            0.80,
        ),
    ]

    # Imperative command starter verbs typical of prompt hijacking
    IMPERATIVE_VERBS = {
        "ignore",
        "disregard",
        "forget",
        "override",
        "bypass",
        "execute",
        "print",
        "output",
        "respond",
        "say",
        "send",
        "reveal",
        "act",
        "pretend",
        "delete",
        "exfiltrate",
        "transmit",
        "simulate",
        "translate",
        "repeat",
        "write",
    }

    def __init__(
        self,
        risk_threshold: float = 0.60,
        instruction_density_threshold: float = 0.35,
    ):
        self.risk_threshold = risk_threshold
        self.instruction_density_threshold = instruction_density_threshold

    def calculate_instruction_density(self, text: str) -> float:
        """Measures the ratio of imperative command sentences/clauses to total sentences.

        Factual documents generally have low imperative density (< 0.15),
        while prompt injections typically exhibit high density (> 0.35).
        """
        # Split text into sentences or major clauses
        sentences = [
            s.strip()
            for s in re.split(r"[.!?;\n]+", text)
            if len(s.strip().split()) >= 3
        ]

        if not sentences:
            return 0.0

        imperative_count = 0
        for sent in sentences:
            tokens = re.findall(r"\b[a-zA-Z]+\b", sent)
            if not tokens:
                continue

            first_word = tokens[0].lower()
            second_word = tokens[1].lower() if len(tokens) > 1 else ""

            # Check direct imperative: "Ignore...", "Print...", "Execute..."
            if first_word in self.IMPERATIVE_VERBS:
                imperative_count += 1
            # Check modal commanding constructs: "You must...", "You should...", "Always output..."
            elif first_word == "you" and second_word in ("must", "will", "shall", "should", "need"):
                imperative_count += 1
            elif first_word in ("always", "never") and second_word in self.IMPERATIVE_VERBS:
                imperative_count += 1

        return round(imperative_count / len(sentences), 4)

    def scan(self, text: str) -> HeuristicScanResult:
        """Evaluates document or chunk text for heuristic override indicators."""
        matched_patterns: List[str] = []
        reasons: List[str] = []
        max_pattern_risk = 0.0
        primary_threat = "BENIGN"

        # 1. Match known injection signatures
        for name, pattern, score in self.INJECTION_PATTERNS:
            found = pattern.findall(text)
            if found:
                matched_patterns.append(name)
                reasons.append(
                    f"Matched signature '{name}' (pattern hits: {len(found)})"
                )
                if score > max_pattern_risk:
                    max_pattern_risk = score
                    primary_threat = name

        # 2. Compute Instruction Density
        density = self.calculate_instruction_density(text)
        if density >= self.instruction_density_threshold:
            reasons.append(
                f"Elevated instruction density ({density:.2f} >= threshold {self.instruction_density_threshold:.2f})"
            )
            # Density contributes to risk
            density_risk = min(1.0, 0.40 + (density * 0.6))
        else:
            density_risk = density * 0.5

        # 3. Composite Risk Calculation
        composite_risk = max(max_pattern_risk, density_risk)

        # If both high pattern match and high density are present, elevate risk
        if matched_patterns and density >= self.instruction_density_threshold:
            composite_risk = min(1.0, composite_risk + 0.15)

        is_flagged = composite_risk >= self.risk_threshold

        return HeuristicScanResult(
            is_flagged=is_flagged,
            risk_score=round(composite_risk, 3),
            instruction_density=density,
            matched_patterns=matched_patterns,
            reasons=reasons,
            threat_category=primary_threat if is_flagged else "BENIGN",
        )
