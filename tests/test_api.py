"""Integration tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient

from api.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    """Verifies that health probe returns healthy status."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "gateway_version" in data


def test_api_ingest_and_query_flow(client):
    """Tests end-to-end HTTP document ingestion and guarded query flow."""
    # 1. Ingest benign document via API
    ingest_payload = {
        "text": "Enterprise Cloud Architecture: All microservices must be deployed on Kubernetes clusters with Istio service mesh mTLS enabled.",
        "filename": "cloud_architecture.md",
        "author": "devops-lead",
        "tenant_id": "infra_team",
    }
    ingest_res = client.post("/api/v1/ingest/text", json=ingest_payload)
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert data["status"] == "INDEXED"
    assert data["chunks_indexed"] >= 1

    # 2. Query guarded endpoint
    query_payload = {
        "query": "How should microservices be deployed?",
        "tenant_id": "infra_team",
        "top_k": 3,
    }
    query_res = client.post("/api/v1/query", json=query_payload)
    assert query_res.status_code == 200
    qdata = query_res.json()
    assert qdata["approved_chunks_count"] >= 1
    assert "Kubernetes" in qdata["answer"]
    assert "<untrusted_retrieved_context" in qdata["hardened_prompt"]


def test_api_sanitize_preview(client):
    """Verifies interactive preview scanner endpoint."""
    payload = {
        "text": "Hello world.\u200B\uFEFF<div style='display:none'>hidden</div>",
        "is_html": True,
    }
    res = client.post("/api/v1/sanitize/preview", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["zero_width_removed"] == 2
    assert data["hidden_elements_stripped"] == 1
    assert "hidden" not in data["cleaned_text"]


def test_api_telemetry_stats(client):
    """Verifies telemetry metrics retrieval."""
    res = client.get("/api/v1/telemetry/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_audit_events" in data
    assert "quarantined_events_count" in data


def test_ui_index_serving(client):
    """Verifies that root URL serves the Web UI dashboard HTML."""
    res = client.get("/")
    assert res.status_code == 200
    assert "RAG Security Defense Gateway" in res.text or "text/html" in res.headers.get("content-type", "")
