"""End-to-End RAG Security Defense Gateway Pipeline.

Coordinates ingestion sanitization, cryptographic provenance, vector isolation,
retrieval verification, semantic drift detection, and hardened prompt generation.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from gateway.config import GatewayConfig, default_config
from gateway.ingestion.document_parser import DocumentParser, ParsedDocument
from gateway.ingestion.heuristic_scanner import HeuristicScanner, HeuristicScanResult
from gateway.ingestion.invisible_text_strip import (
    InvisibleTextStripper,
    SanitizationTelemetry,
)
from gateway.ingestion.provenance_signer import ProvenanceSigner
from gateway.retrieval.chunk_evaluator import ChunkEvaluator, EvaluationResult
from gateway.retrieval.defensive_formatter import DefensiveFormatter, FormattedPrompt
from gateway.retrieval.injection_detector import (
    InjectionDetector,
    InspectionResult,
)
from gateway.storage.vector_store import SecureVectorStore, VectorStoreRecord


@dataclass
class DocumentIngestionResult:
    """Security audit log and status of an ingested document."""

    doc_id: str
    filename: str
    status: str  # "INDEXED", "QUARANTINED", "REJECTED"
    chunks_indexed: int
    sanitization: SanitizationTelemetry
    heuristic_scan: HeuristicScanResult
    quarantine_reason: Optional[str] = None
    processing_time_ms: float = 0.0


@dataclass
class GuardedQueryResult:
    """Defensive RAG response with runtime telemetry, quarantined chunks, and hardened prompt."""

    query: str
    response_text: str
    total_retrieved_chunks: int
    approved_chunks_count: int
    quarantined_chunks_count: int
    quarantined_details: List[Dict[str, Any]]
    surviving_chunk_ids: List[str]
    hardened_prompt: str
    execution_time_ms: float
    tampered_chunks_detected: int = 0
    semantic_drift_detected: int = 0


class RAGDefenseGateway:
    """Enterprise Gateway protecting RAG architectures from document poisoning and indirect prompt injection."""

    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config or default_config

        # Ingestion components
        self.parser = DocumentParser(
            chunk_size=self.config.chunk_size,
            chunk_overlap=self.config.chunk_overlap,
        )
        self.stripper = InvisibleTextStripper()
        self.scanner = HeuristicScanner(
            risk_threshold=self.config.heuristic_risk_threshold,
            instruction_density_threshold=self.config.instruction_density_threshold,
        )
        self.signer = ProvenanceSigner(secret_key=self.config.provenance_secret_key)

        # Storage component
        self.vector_store = SecureVectorStore(
            persist_dir=self.config.chroma_persist_dir,
            base_collection=self.config.default_collection,
            provenance_signer=self.signer,
        )

        # Retrieval components
        self.evaluator = ChunkEvaluator(
            min_semantic_similarity=self.config.semantic_alignment_min_similarity,
            embedding_model=self.vector_store.embedding_fn,
        )
        self.detector = InjectionDetector(
            risk_threshold=self.config.injection_risk_threshold,
            heuristic_scanner=self.scanner,
        )
        self.formatter = DefensiveFormatter(
            tag_name=self.config.xml_context_tag,
            escape_inner_tags=self.config.escape_delimiters,
        )

        # In-memory security audit log
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit_event(self, event_type: str, details: Dict[str, Any]):
        """Records security event into gateway telemetry buffer."""
        record = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details,
        }
        self.audit_log.append(record)
        if len(self.audit_log) > self.config.telemetry_retention_max:
            self.audit_log.pop(0)

    def ingest_document(
        self,
        content: str | bytes,
        filename: str = "document.txt",
        mime_type: Optional[str] = None,
        author: str = "security-admin",
        tenant_id: str = "default",
        source_uri: str = "direct_upload",
    ) -> DocumentIngestionResult:
        """Executes multi-stage ingestion pre-filtering, signing, and vector indexing."""
        start_time = time.perf_counter()
        doc_id = str(uuid.uuid4())

        # Stage 1: Document Parsing
        parsed: ParsedDocument = self.parser.parse(
            content=content,
            filename=filename,
            mime_type=mime_type,
            doc_id=doc_id,
        )

        # Stage 2: Ingestion Text Sanitization (Zero-Width, Homoglyphs, Hidden CSS)
        is_html = parsed.mime_type == "text/html" or filename.lower().endswith(".html")
        sanitized_text, telemetry = self.stripper.sanitize(
            parsed.raw_text, is_html=is_html
        )

        # Stage 3: Ingestion Heuristic Scanning & Instruction Density Analysis
        heuristic_res = self.scanner.scan(sanitized_text)

        # Quarantine check at ingestion: if document exhibits blatant prompt injection override
        if heuristic_res.is_flagged:
            reason = f"Ingestion Quarantined: {', '.join(heuristic_res.reasons)} (Risk: {heuristic_res.risk_score})"
            self.log_audit_event(
                "INGESTION_QUARANTINE",
                {
                    "doc_id": doc_id,
                    "filename": filename,
                    "risk_score": heuristic_res.risk_score,
                    "reasons": heuristic_res.reasons,
                },
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DocumentIngestionResult(
                doc_id=doc_id,
                filename=filename,
                status="QUARANTINED",
                chunks_indexed=0,
                sanitization=telemetry,
                heuristic_scan=heuristic_res,
                quarantine_reason=reason,
                processing_time_ms=round(elapsed_ms, 2),
            )

        # Stage 4: Re-chunk sanitized text
        chunks = self.parser.chunk_text(sanitized_text)

        # Check individual chunks for elevated imperative risk
        valid_chunks: List[str] = []
        for ch in chunks:
            chunk_scan = self.scanner.scan(ch)
            if not chunk_scan.is_flagged:
                valid_chunks.append(ch)

        if not valid_chunks and chunks:
            # All individual chunks flagged
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DocumentIngestionResult(
                doc_id=doc_id,
                filename=filename,
                status="QUARANTINED",
                chunks_indexed=0,
                sanitization=telemetry,
                heuristic_scan=heuristic_res,
                quarantine_reason="All chunks failed imperative density / injection checks",
                processing_time_ms=round(elapsed_ms, 2),
            )

        # Stage 5: Cryptographic Signing & Vector Storage
        self.vector_store.add_documents(
            chunks=valid_chunks,
            doc_id=doc_id,
            author=author,
            tenant_id=tenant_id,
            source_uri=source_uri,
            extra_metadata={
                "filename": filename,
                "mime_type": parsed.mime_type,
            },
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.log_audit_event(
            "INGESTION_SUCCESS",
            {
                "doc_id": doc_id,
                "filename": filename,
                "chunks_indexed": len(valid_chunks),
            },
        )

        return DocumentIngestionResult(
            doc_id=doc_id,
            filename=filename,
            status="INDEXED",
            chunks_indexed=len(valid_chunks),
            sanitization=telemetry,
            heuristic_scan=heuristic_res,
            processing_time_ms=round(elapsed_ms, 2),
        )

    def query(
        self,
        query_text: str,
        tenant_id: str = "default",
        top_k: int = 4,
        llm_caller: Optional[Callable[[str], str]] = None,
    ) -> GuardedQueryResult:
        """Executes guarded RAG retrieval, runs multi-stage context verification, and forms hardened prompt."""
        start_time = time.perf_counter()

        # Step 1: Retrieve candidate chunks from vector database
        candidates: List[VectorStoreRecord] = self.vector_store.search(
            query_text=query_text,
            top_k=top_k,
            tenant_id=tenant_id,
            enforce_provenance=self.config.enforce_signature_verification,
        )

        approved_chunks: List[Dict[str, Any]] = []
        quarantined_details: List[Dict[str, Any]] = []
        tampered_count = 0
        drift_count = 0

        # Step 2: Multi-Stage Retrieval Verification on each candidate chunk
        for record in candidates:
            # 2a. Provenance & Cryptographic Signature Check (Anti-Tampering)
            if self.config.enforce_signature_verification and not record.provenance_verified:
                tampered_count += 1
                quarantined_details.append(
                    {
                        "chunk_id": record.id,
                        "reason": "Cryptographic signature mismatch / direct database tampering detected",
                        "status": "TAMPERED",
                        "risk_score": 1.0,
                    }
                )
                self.log_audit_event(
                    "VECTOR_TAMPERING_DETECTED",
                    {"chunk_id": record.id, "tenant_id": tenant_id},
                )
                continue

            # 2b. Runtime Injection Detector (Imperative Instruction vs. Reference Data)
            inspect_res: InspectionResult = self.detector.inspect_chunk(
                chunk_id=record.id,
                content=record.content,
            )

            if not inspect_res.is_safe:
                quarantined_details.append(
                    {
                        "chunk_id": record.id,
                        "reason": f"Indirect prompt injection detected: {', '.join(inspect_res.threat_indicators)}",
                        "status": inspect_res.status.value,
                        "risk_score": inspect_res.risk_score,
                    }
                )
                self.log_audit_event(
                    "INDIRECT_INJECTION_QUARANTINED",
                    {
                        "chunk_id": record.id,
                        "indicators": inspect_res.threat_indicators,
                        "risk": inspect_res.risk_score,
                    },
                )
                continue

            # 2c. Semantic Drift & Relevance Alignment Check
            eval_res: EvaluationResult = self.evaluator.evaluate(
                query=query_text,
                chunk_content=record.content,
                chunk_id=record.id,
                precomputed_similarity=record.similarity,
            )

            if eval_res.is_semantic_drift:
                drift_count += 1
                quarantined_details.append(
                    {
                        "chunk_id": record.id,
                        "reason": f"Semantic drift: {', '.join(eval_res.drift_reasons)}",
                        "status": "SEMANTIC_DRIFT",
                        "risk_score": 0.65,
                    }
                )
                self.log_audit_event(
                    "SEMANTIC_DRIFT_EXCLUDED",
                    {"chunk_id": record.id, "reasons": eval_res.drift_reasons},
                )
                continue

            # Chunk successfully passed all verification gates
            approved_chunks.append(
                {
                    "id": record.id,
                    "content": record.content,
                    "metadata": record.metadata,
                    "similarity": record.similarity,
                }
            )

        # Step 3: Hardened Context Encapsulation with Defensive Boundary Delimiters
        formatted_prompt: FormattedPrompt = self.formatter.build_hardened_prompt(
            query=query_text,
            approved_chunks=approved_chunks,
        )

        # Step 4: LLM Generation (Deterministic Mock or User-Supplied Function)
        if llm_caller is not None:
            response_text = llm_caller(formatted_prompt.full_prompt)
        else:
            response_text = self._simulate_safe_llm_inference(
                query=query_text,
                approved_chunks=approved_chunks,
                quarantined_count=len(quarantined_details),
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return GuardedQueryResult(
            query=query_text,
            response_text=response_text,
            total_retrieved_chunks=len(candidates),
            approved_chunks_count=len(approved_chunks),
            quarantined_chunks_count=len(quarantined_details),
            quarantined_details=quarantined_details,
            surviving_chunk_ids=formatted_prompt.encapsulated_chunk_ids,
            hardened_prompt=formatted_prompt.full_prompt,
            execution_time_ms=round(elapsed_ms, 2),
            tampered_chunks_detected=tampered_count,
            semantic_drift_detected=drift_count,
        )

    def _simulate_safe_llm_inference(
        self,
        query: str,
        approved_chunks: List[Dict[str, Any]],
        quarantined_count: int,
    ) -> str:
        """Deterministic, zero-cost mock LLM inference demonstrating safe response generation and immunity to injection."""
        if not approved_chunks:
            if quarantined_count > 0:
                return (
                    "I am unable to answer based on the retrieved documents because potential prompt injection "
                    "or malicious override payloads were detected and quarantined by the security gateway."
                )
            return "No relevant verified documentation was found matching your query."

        # Synthesize answer using top approved chunk
        top_chunk = approved_chunks[0]
        snippet = top_chunk["content"][:200].strip()
        source = top_chunk.get("metadata", {}).get("filename", "knowledge base")

        return (
            f"Based on verified enterprise documentation ({source}):\n\n"
            f'"{snippet}..."\n\n'
            f"[Security Gateway Notice: {len(approved_chunks)} chunk(s) verified safe; "
            f"{quarantined_count} quarantined]."
        )
