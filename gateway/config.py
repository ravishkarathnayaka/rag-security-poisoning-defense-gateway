"""Centralized configuration and security thresholds for the RAG Security Gateway."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class GatewayConfig:
    """Enterprise security thresholds, model parameters, and gateway configuration."""

    def validate(self) -> None:
        """Validates configuration bounds to ensure defensive integrity."""
        if not (0.0 <= self.heuristic_risk_threshold <= 1.0):
            raise ValueError(f"heuristic_risk_threshold must be in [0.0, 1.0], got {self.heuristic_risk_threshold}")
        if not (0.0 <= self.instruction_density_threshold <= 1.0):
            raise ValueError(f"instruction_density_threshold must be in [0.0, 1.0], got {self.instruction_density_threshold}")
        if not (0.0 <= self.injection_risk_threshold <= 1.0):
            raise ValueError(f"injection_risk_threshold must be in [0.0, 1.0], got {self.injection_risk_threshold}")
        if self.chunk_overlap >= self.chunk_size:
            raise ValueError(f"chunk_overlap ({self.chunk_overlap}) must be strictly less than chunk_size ({self.chunk_size})")

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        """Builds configuration with environment variable overrides."""
        cfg = cls()
        if "GATEWAY_RISK_THRESHOLD" in os.environ:
            cfg.heuristic_risk_threshold = float(os.environ["GATEWAY_RISK_THRESHOLD"])
        if "GATEWAY_CHUNK_SIZE" in os.environ:
            cfg.chunk_size = int(os.environ["GATEWAY_CHUNK_SIZE"])
        cfg.validate()
        return cfg

    # ---------------------------------------------------------
    # Ingestion Constraints & Sanitization Thresholds
    # ---------------------------------------------------------
    allowed_mime_types: List[str] = field(
        default_factory=lambda: [
            "text/plain",
            "text/markdown",
            "text/html",
            "application/pdf",
        ]
    )
    max_doc_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    chunk_size: int = 500  # Characters per chunk
    chunk_overlap: int = 60  # Overlap between consecutive chunks

    # Zero-width / hidden characters tolerance (0 means any discovered character is stripped & logged)
    max_zero_width_chars: int = 0
    normalize_homoglyphs: bool = True

    # Ingestion Heuristic Thresholds
    # Instruction density: ratio of imperative sentence commands to total sentences
    instruction_density_threshold: float = 0.35
    # Composite heuristic risk score [0.0 - 1.0] above which document/chunk is quarantined at ingestion
    heuristic_risk_threshold: float = 0.60

    # ---------------------------------------------------------
    # Provenance & Cryptographic Signing
    # ---------------------------------------------------------
    provenance_secret_key: str = field(
        default_factory=lambda: os.getenv(
            "GATEWAY_PROVENANCE_KEY", "rag-security-gateway-hmac-master-key-prod-001"
        )
    )
    enforce_signature_verification: bool = True

    # ---------------------------------------------------------
    # Vector Storage & Namespace Isolation
    # ---------------------------------------------------------
    chroma_persist_dir: str = field(
        default_factory=lambda: os.getenv(
            "CHROMA_PERSIST_DIR",
            "/tmp/chroma_data"  # nosec B108
            if (os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
            else str(Path.cwd() / "chroma_data"),
        )
    )
    default_collection: str = "enterprise_knowledge"
    enable_tenant_isolation: bool = True

    # ---------------------------------------------------------
    # Retrieval-Time Verification & Boundary Hardening
    # ---------------------------------------------------------
    # Minimum cosine similarity between user query and retrieved chunk
    semantic_alignment_min_similarity: float = 0.20
    # Runtime prompt injection risk score threshold [0.0 - 1.0]
    injection_risk_threshold: float = 0.50
    # When True, quarantined chunks are completely excluded from the LLM prompt
    strict_quarantine: bool = True
    # Delimiter encapsulation style: XML tags with strict attribute signing
    xml_context_tag: str = "untrusted_retrieved_context"
    escape_delimiters: bool = True

    # ---------------------------------------------------------
    # Embedding & Local Execution
    # ---------------------------------------------------------
    embedding_model_name: str = "all-MiniLM-L6-v2"
    # When True or when sentence-transformers is offline, uses deterministic local hasher
    use_deterministic_fallback: bool = True

    # ---------------------------------------------------------
    # API & Telemetry
    # ---------------------------------------------------------
    api_host: str = "0.0.0.0"  # nosec B104
    api_port: int = 8000
    telemetry_retention_max: int = 500


# Singleton default configuration instance
default_config = GatewayConfig()
