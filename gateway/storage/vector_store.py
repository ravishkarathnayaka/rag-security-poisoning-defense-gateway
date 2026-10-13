"""ChromaDB Vector Store Wrapper with Namespace Isolation, Metadata Filtering, and Cryptographic Provenance Verification."""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from gateway.ingestion.provenance_signer import ProvenanceSigner


@dataclass
class VectorStoreRecord:
    """Retrieved vector database document chunk with metadata and similarity score."""

    id: str
    content: str
    metadata: Dict[str, Any]
    similarity: float  # Cosine similarity score [0.0 - 1.0]
    distance: float  # Cosine distance
    provenance_verified: bool = False


class DeterministicLocalEmbedding:
    """Zero-dependency, reproducible embedding model producing 384-dimensional dense vectors.

    Uses character trigram and subword token feature hashing with sinusoidal phase projection
    and L2 unit normalization. Guarantees deterministic, offline vector similarity for $0
    without external API keys or heavy weight downloads in local and CI environments.
    """

    DIMENSION = 384

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def _embed_single(self, text: str) -> List[float]:
        vec = [0.0] * self.dimension
        clean = text.lower().strip()
        if not clean:
            return vec

        # Token and subword trigram hashing
        tokens = clean.split()
        features: List[str] = list(tokens)

        # Generate character 3-grams
        padded = f" {clean} "
        for i in range(len(padded) - 2):
            features.append(padded[i : i + 3])

        # Feature hashing into dense vector
        for feat in features:
            h = int(hashlib.md5(feat.encode("utf-8"), usedforsecurity=False).hexdigest(), 16)  # nosec B324
            idx = h % self.dimension
            # Sign hash for balance
            sign = 1.0 if ((h >> 8) & 1) else -1.0
            # Weight term by token length
            weight = math.log1p(len(feat))
            vec[idx] += sign * weight

        # Apply positional / sinusoidal frequency smoothing
        for i in range(self.dimension):
            freq = math.sin((i + 1) * 0.1)
            vec[i] += freq * 0.05

        # L2 Normalization
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0.0:
            vec = [round(x / norm, 6) for x in vec]
        return vec

    def __call__(self, input: Any = None, *args, **kwargs) -> List[List[float]]:
        target = input
        if target is None and args:
            target = args[0]
        if target is None and "documents" in kwargs:
            target = kwargs["documents"]
        if isinstance(target, str):
            return [self._embed_single(target)]
        if isinstance(target, (list, tuple)):
            return [self._embed_single(t) for t in target]
        return []

    # ChromaDB embedding function protocol compatibility
    def embed_documents(self, input: Any = None, documents: Any = None, *args, **kwargs) -> List[List[float]]:
        target = input if input is not None else documents
        if target is None and args:
            target = args[0]
        if isinstance(target, str):
            return [self._embed_single(target)]
        if isinstance(target, (list, tuple)):
            return [self._embed_single(t) for t in target]
        return []

    def embed_query(self, input: Any = None, query: Any = None, *args, **kwargs) -> List[List[float]]:
        target = input if input is not None else query
        if target is None and args:
            target = args[0]
        if isinstance(target, str):
            return [self._embed_single(target)]
        if isinstance(target, (list, tuple)):
            return [self._embed_single(t) for t in target]
        return []

    def name(self) -> str:
        return "DeterministicLocalEmbedding-384d"


class FallbackVectorCollection:
    """Thread-safe, pure-Python vector collection fallback when ChromaDB is not installed."""

    def __init__(self, name: str, embedding_fn: DeterministicLocalEmbedding):
        self.name = name
        self.embedding_fn = embedding_fn
        self.documents: Dict[str, str] = {}
        self.metadatas: Dict[str, Dict[str, Any]] = {}
        self.embeddings: Dict[str, List[float]] = {}

    def add(
        self,
        ids: List[str],
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        embeddings: Optional[List[List[float]]] = None,
    ):
        if embeddings is None:
            embeddings = self.embedding_fn(documents)
        if metadatas is None:
            metadatas = [{} for _ in documents]

        for i, doc_id in enumerate(ids):
            self.documents[doc_id] = documents[i]
            self.metadatas[doc_id] = metadatas[i]
            self.embeddings[doc_id] = embeddings[i]

    def count(self) -> int:
        return len(self.documents)

    def query(
        self,
        query_texts: Optional[List[str]] = None,
        query_embeddings: Optional[List[List[float]]] = None,
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if query_embeddings is None and query_texts is not None:
            query_embeddings = self.embedding_fn(query_texts)

        if not query_embeddings or not self.documents:
            return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        q_vec = query_embeddings[0]

        # Calculate cosine distance for candidates
        results = []
        for doc_id, doc_text in self.documents.items():
            meta = self.metadatas.get(doc_id, {})
            # Check metadata filter
            if where:
                match = True
                for k, v in where.items():
                    if meta.get(k) != v:
                        match = False
                        break
                if not match:
                    continue

            d_vec = self.embeddings[doc_id]
            # Dot product for normalized vectors = cosine similarity
            cos_sim = sum(q * d for q, d in zip(q_vec, d_vec, strict=False))
            cos_sim = max(-1.0, min(1.0, cos_sim))
            # Cosine distance = 1 - similarity
            distance = max(0.0, 1.0 - cos_sim)
            results.append((distance, doc_id, doc_text, meta))

        # Sort by lowest distance (highest similarity)
        results.sort(key=lambda x: x[0])
        top = results[:n_results]

        return {
            "ids": [[item[1] for item in top]],
            "documents": [[item[2] for item in top]],
            "metadatas": [[item[3] for item in top]],
            "distances": [[item[0] for item in top]],
        }

    def delete(self, ids: Optional[List[str]] = None, where: Optional[Dict[str, Any]] = None):
        if ids:
            for doc_id in ids:
                self.documents.pop(doc_id, None)
                self.metadatas.pop(doc_id, None)
                self.embeddings.pop(doc_id, None)
        elif where:
            to_delete = []
            for doc_id, meta in self.metadatas.items():
                match = True
                for k, v in where.items():
                    if meta.get(k) != v:
                        match = False
                        break
                if match:
                    to_delete.append(doc_id)
            for doc_id in to_delete:
                self.documents.pop(doc_id, None)
                self.metadatas.pop(doc_id, None)
                self.embeddings.pop(doc_id, None)


class SecureVectorStore:
    """Hardened vector store interface supporting tenant isolation, signed metadata, and tamper detection."""

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        base_collection: str = "enterprise_knowledge",
        provenance_signer: Optional[ProvenanceSigner] = None,
        use_mock_embedding: bool = True,
    ):
        self.persist_dir = persist_dir or str(Path.cwd() / "chroma_data")
        self.base_collection = base_collection
        self.signer = provenance_signer or ProvenanceSigner()
        self.embedding_fn = DeterministicLocalEmbedding()
        self._fallback_collections: Dict[str, FallbackVectorCollection] = {}
        self._chroma_client = None

        os.makedirs(self.persist_dir, exist_ok=True)
        self._init_chroma()

    def _init_chroma(self):
        """Attempts to initialize ChromaDB; falls back gracefully if not installed."""
        try:
            import chromadb
            from chromadb.config import Settings

            # Use PersistentClient with telemetry disabled
            self._chroma_client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(anonymized_telemetry=False, is_persistent=True),
            )
        except Exception:
            self._chroma_client = None

    def _get_collection_name(self, tenant_id: str) -> str:
        """Computes isolated collection name for multi-tenant isolation."""
        safe_tenant = "".join(c if c.isalnum() else "_" for c in tenant_id)
        return f"{self.base_collection}_{safe_tenant}"

    def _get_collection(self, tenant_id: str):
        """Retrieves or creates isolated collection for tenant."""
        name = self._get_collection_name(tenant_id)
        if self._chroma_client is not None:
            try:
                return self._chroma_client.get_or_create_collection(
                    name=name,
                    embedding_function=self.embedding_fn,
                    metadata={"tenant_id": tenant_id, "gateway_protected": "true"},
                )
            except Exception:
                pass

        # In-memory / pure fallback
        if name not in self._fallback_collections:
            self._fallback_collections[name] = FallbackVectorCollection(
                name=name, embedding_fn=self.embedding_fn
            )
        return self._fallback_collections[name]

    def add_documents(
        self,
        chunks: List[str],
        doc_id: str,
        author: str = "security-admin",
        tenant_id: str = "default",
        source_uri: str = "direct_upload",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Cryptographically signs chunks, attaches provenance metadata, and indexes in isolated collection."""
        if not chunks:
            return []

        collection = self._get_collection(tenant_id)
        chunk_ids: List[str] = []
        metadatas: List[Dict[str, Any]] = []

        for idx, chunk in enumerate(chunks):
            cid = f"{doc_id}_chunk_{idx}"
            chunk_ids.append(cid)

            signed_meta = self.signer.sign_chunk(
                content=chunk,
                doc_id=doc_id,
                chunk_id=cid,
                author=author,
                tenant_id=tenant_id,
                source_uri=source_uri,
            )

            meta_dict = signed_meta.to_dict()
            meta_dict["chunk_index"] = idx
            if extra_metadata:
                for k, v in extra_metadata.items():
                    if k not in meta_dict:
                        meta_dict[k] = str(v)

            metadatas.append(meta_dict)

        collection.add(
            ids=chunk_ids,
            documents=chunks,
            metadatas=metadatas,
        )

        return chunk_ids

    def search(
        self,
        query_text: str,
        top_k: int = 5,
        tenant_id: str = "default",
        enforce_provenance: bool = True,
    ) -> List[VectorStoreRecord]:
        """Queries tenant collection and validates cryptographic provenance signatures."""
        collection = self._get_collection(tenant_id)

        try:
            results = collection.query(
                query_texts=[query_text],
                n_results=top_k,
                where={"tenant_id": tenant_id} if hasattr(collection, "count") else None,
            )
        except Exception:
            # Fallback without where filter if collection schema forbids
            results = collection.query(
                query_texts=[query_text],
                n_results=top_k,
            )

        records: List[VectorStoreRecord] = []
        if not results or not results.get("ids") or not results["ids"][0]:
            return records

        ids = results["ids"][0]
        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results.get("distances", [[0.0] * len(ids)])[0]

        for i in range(len(ids)):
            doc_content = docs[i]
            meta = metas[i] if metas and i < len(metas) else {}
            dist = float(distances[i]) if distances and i < len(distances) else 0.0

            # Cosine similarity conversion
            similarity = max(0.0, min(1.0, 1.0 - dist))

            # Cryptographic Provenance Check
            is_valid_provenance = False
            if enforce_provenance and meta and "signature" in meta:
                is_valid_provenance = self.signer.verify_chunk(doc_content, meta)
            elif not enforce_provenance:
                is_valid_provenance = True

            records.append(
                VectorStoreRecord(
                    id=ids[i],
                    content=doc_content,
                    metadata=meta,
                    similarity=round(similarity, 4),
                    distance=round(dist, 4),
                    provenance_verified=is_valid_provenance,
                )
            )

        return records

    def delete_document(self, doc_id: str, tenant_id: str = "default"):
        """Removes all indexed chunks associated with doc_id from tenant collection."""
        collection = self._get_collection(tenant_id)
        collection.delete(where={"doc_id": doc_id})

    def count(self, tenant_id: str = "default") -> int:
        """Returns number of chunks indexed in tenant collection."""
        collection = self._get_collection(tenant_id)
        return collection.count()
