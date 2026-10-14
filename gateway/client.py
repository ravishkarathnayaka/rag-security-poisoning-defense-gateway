"""Lightweight Python Client SDK for RAG Security Gateway."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import urllib.request
import json


class RAGDefenseClient:
    """Client wrapper for integrating external RAG applications with the Security Gateway."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")

    def health(self) -> Dict[str, Any]:
        """Queries gateway health and status."""
        req = urllib.request.Request(f"{self.base_url}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def ingest_document(
        self,
        content: str,
        filename: str = "document.txt",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Ingests and screens a document through the gateway pipeline."""
        payload = json.dumps({"content": content, "filename": filename, "metadata": metadata or {}}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/ingest",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def query(
        self,
        query: str,
        top_k: int = 5,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Queries the vector store with retrieval-time boundary hardening."""
        payload = json.dumps({"query": query, "top_k": top_k, "tenant_id": tenant_id}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/query",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
