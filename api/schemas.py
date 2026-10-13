"""Pydantic schemas for document ingestion, query verification, and security telemetry."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class IngestTextRequest(BaseModel):
    """Payload for ingesting raw document text."""

    text: str = Field(..., description="Document content to ingest")
    filename: str = Field("document.txt", description="Origin filename or title")
    mime_type: Optional[str] = Field("text/plain", description="MIME type of document")
    author: str = Field("security-admin", description="Author or identity signing document")
    tenant_id: str = Field("default", description="Namespace / tenant isolation key")
    source_uri: str = Field("api_upload", description="Source location URI")


class SanitizationDetail(BaseModel):
    """Metrics regarding stripped anomalies and hidden characters."""

    zero_width_chars_removed: int
    homoglyphs_normalized: int
    hidden_elements_stripped: int
    bidi_overrides_removed: int
    ascii_smuggling_tags_removed: int
    anomalies: List[str]


class IngestResponse(BaseModel):
    """Response payload after document ingestion."""

    doc_id: str
    filename: str
    status: str  # INDEXED, QUARANTINED, REJECTED
    chunks_indexed: int
    sanitization: SanitizationDetail
    risk_score: float
    instruction_density: float
    quarantine_reason: Optional[str] = None
    processing_time_ms: float


class QueryRequest(BaseModel):
    """RAG query request with tenant filtering."""

    query: str = Field(..., description="User query to search against secured knowledge base")
    tenant_id: str = Field("default", description="Tenant isolation boundary")
    top_k: int = Field(4, ge=1, le=20, description="Maximum chunks to retrieve")


class QuarantinedChunkDetail(BaseModel):
    """Security explanation for a quarantined chunk."""

    chunk_id: str
    reason: str
    status: str
    risk_score: float


class QueryResponse(BaseModel):
    """Guarded RAG answer and security telemetry."""

    query: str
    answer: str
    total_retrieved_chunks: int
    approved_chunks_count: int
    quarantined_chunks_count: int
    quarantined_details: List[QuarantinedChunkDetail]
    hardened_prompt: str
    execution_time_ms: float
    tampered_chunks_detected: int
    semantic_drift_detected: int


class SanitizePreviewRequest(BaseModel):
    """Request to test and preview text sanitization without vector storage."""

    text: str
    is_html: bool = False


class SanitizePreviewResponse(BaseModel):
    """Preview of stripped text and security risk flags."""

    original_length: int
    cleaned_length: int
    cleaned_text: str
    zero_width_removed: int
    homoglyphs_normalized: int
    hidden_elements_stripped: int
    heuristic_risk_score: float
    instruction_density: float
    threat_category: str
    is_flagged: bool
    reasons: List[str]


class TelemetryStatsResponse(BaseModel):
    """Aggregated security gateway telemetry statistics."""

    total_audit_events: int
    quarantined_events_count: int
    tamper_events_count: int
    indexed_documents_estimate: int
