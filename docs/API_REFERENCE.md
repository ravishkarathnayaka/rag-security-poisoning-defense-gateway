# REST API Reference Specification

The gateway exposes a production-ready FastAPI interface for document ingestion, query retrieval, sanitization preview, and security telemetry.

### 1. Ingest Document
`POST /api/ingest`
- **Request Body**:
```json
{
  "content": "Corporate policy details...",
  "filename": "policy.md",
  "metadata": {"author": "secops", "tenant_id": "finance"}
}
```
- **Responses**:
  - `200 OK`: `{"status": "approved", "doc_id": "...", "chunks_stored": 4}`
  - `400 Bad Request`: Document format invalid or size exceeds limits.

### 2. Query Knowledge Base
`POST /api/query`
- **Request Body**:
```json
{
  "query": "What is our data retention policy?",
  "top_k": 5,
  "tenant_id": "finance"
}
```
- **Response**:
```json
{
  "query": "What is our data retention policy?",
  "approved_chunks": [...],
  "quarantined_chunks": [...],
  "hardened_prompt": "<untrusted_retrieved_context id=\"...\">...</untrusted_retrieved_context>"
}
```

### 3. Sanitize Preview
`POST /api/sanitize-preview`
Inspects raw text for zero-width characters, homoglyphs, and hidden CSS without persisting to vector store.

### 4. Telemetry Statistics
`GET /api/telemetry/stats`
Returns aggregated ingestion counts, quarantined items, and stripped anomaly totals.

### 5. Health Check
`GET /api/health`
Returns service readiness and database connectivity status.
