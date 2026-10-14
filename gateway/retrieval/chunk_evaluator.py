"""Semantic Alignment & Drift Evaluator for Retrieved RAG Context Chunks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from gateway.storage.vector_store import DeterministicLocalEmbedding


@dataclass
class EvaluationResult:
    """Evaluation of semantic alignment between user query and retrieved chunk."""

    chunk_id: str
    semantic_similarity: float
    lexical_overlap: float
    alignment_score: float
    is_aligned: bool
    is_semantic_drift: bool
    instruction_penalty: float = 0.0
    drift_reasons: List[str] = field(default_factory=list)


class ChunkEvaluator:
    """Measures semantic relevance and flags out-of-distribution or drifting retrieved chunks."""

    def __init__(
        self,
        min_semantic_similarity: float = 0.20,
        min_alignment_score: float = 0.15,
        embedding_model: Optional[DeterministicLocalEmbedding] = None,
    ):
        self.min_semantic_similarity = min_semantic_similarity
        self.min_alignment_score = min_alignment_score
        self.embedding = embedding_model or DeterministicLocalEmbedding()

    def _calculate_cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Computes cosine similarity between two unit-normalized vectors."""
        dot = sum(a * b for a, b in zip(vec_a, vec_b, strict=False))
        return max(-1.0, min(1.0, dot))

    def _calculate_lexical_overlap(self, query: str, chunk: str) -> float:
        """Calculates token overlap (Jaccard coefficient on significant terms)."""
        stop_words = {
            "a", "an", "the", "in", "on", "at", "to", "for", "of", "and", "or",
            "is", "are", "was", "were", "what", "how", "when", "where", "why",
            "this", "that", "these", "those", "it", "its", "with", "from",
        }
        q_tokens = {
            t.lower()
            for t in re.findall(r"\b\w{2,}\b", query)
            if t.lower() not in stop_words
        }
        c_tokens = {
            t.lower()
            for t in re.findall(r"\b\w{2,}\b", chunk)
            if t.lower() not in stop_words
        }

        if not q_tokens:
            return 0.5  # Neutral overlap if query has no content words

        intersection = q_tokens.intersection(c_tokens)
        return len(intersection) / len(q_tokens)

    def evaluate(
        self,
        query: str,
        chunk_content: str,
        chunk_id: str = "chunk_0",
        precomputed_similarity: Optional[float] = None,
    ) -> EvaluationResult:
        """Evaluates whether retrieved chunk aligns with query intent or exhibits semantic drift."""
        drift_reasons: List[str] = []

        # 1. Semantic Similarity
        if precomputed_similarity is not None:
            sim = precomputed_similarity
        else:
            q_vec = self.embedding.embed_query(query)
            c_vec = self.embedding.embed_query(chunk_content)
            sim = self._calculate_cosine_similarity(q_vec, c_vec)
            # Map [-1, 1] to [0, 1]
            sim = max(0.0, (sim + 1.0) / 2.0)

        # 2. Lexical Overlap
        lexical = self._calculate_lexical_overlap(query, chunk_content)

        # 3. Instruction Penalty Check
        imperative_markers = ["ignore", "disregard", "override", "execute", "bypass", "system"]
        words = chunk_content.lower().split()
        match_count = sum(1 for w in words if any(m in w for m in imperative_markers))
        instruction_penalty = min(0.40, match_count * 0.10)

        # Composite Alignment Score (70% semantic, 30% lexical - penalty)
        alignment_score = max(0.0, (sim * 0.70) + (lexical * 0.30) - instruction_penalty)

        # 4. Check for Semantic Drift
        is_semantic_drift = False
        if sim < self.min_semantic_similarity:
            is_semantic_drift = True
            drift_reasons.append(
                f"Low semantic similarity ({sim:.3f} < threshold {self.min_semantic_similarity:.3f})"
            )

        if alignment_score < self.min_alignment_score:
            is_semantic_drift = True
            drift_reasons.append(
                f"Low composite alignment ({alignment_score:.3f} < threshold {self.min_alignment_score:.3f})"
            )

        is_aligned = not is_semantic_drift

        return EvaluationResult(
            chunk_id=chunk_id,
            semantic_similarity=round(sim, 4),
            lexical_overlap=round(lexical, 4),
            alignment_score=round(alignment_score, 4),
            is_aligned=is_aligned,
            is_semantic_drift=is_semantic_drift,
            instruction_penalty=round(instruction_penalty, 4),
            drift_reasons=drift_reasons,
        )
