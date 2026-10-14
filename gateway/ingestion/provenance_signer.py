"""Document Provenance & Cryptographic Metadata Signer.

Generates SHA-256 content fingerprints and HMAC-SHA256 signatures to detect
out-of-band vector store tampering and verify document provenance.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class SignedMetadata:
    """Cryptographically signed document/chunk provenance manifest."""

    doc_id: str
    chunk_id: str
    content_sha256: str
    author: str
    tenant_id: str
    source_uri: str
    ingested_at: float
    sanitizer_version: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProvenanceSigner:
    """Computes SHA-256 digests and signs metadata with HMAC-SHA256."""

    SANITIZER_VERSION = "1.0.0-defensive-gateway"

    def __init__(
        self,
        secret_key: str = "rag-security-gateway-hmac-master-key-prod-001",
        previous_keys: Optional[List[str]] = None,
    ):
        self.secret_key = secret_key.encode("utf-8")
        self.previous_keys = [k.encode("utf-8") for k in (previous_keys or [])]

    def compute_sha256(self, content: str) -> str:
        """Computes deterministic SHA-256 hex digest of string content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _build_signing_payload(
        self,
        doc_id: str,
        chunk_id: str,
        content_sha256: str,
        author: str,
        tenant_id: str,
        source_uri: str,
        ingested_at: float,
    ) -> bytes:
        """Builds a canonical byte string for HMAC signing."""
        canonical_str = (
            f"{doc_id}:{chunk_id}:{content_sha256}:{author}:{tenant_id}:{source_uri}:{ingested_at}:{self.SANITIZER_VERSION}"
        )
        return canonical_str.encode("utf-8")

    def sign_chunk(
        self,
        content: str,
        doc_id: str,
        chunk_id: str,
        author: str = "system",
        tenant_id: str = "default",
        source_uri: str = "direct_upload",
        ingested_at: Optional[float] = None,
    ) -> SignedMetadata:
        """Generates signed provenance metadata for an individual text chunk."""
        if ingested_at is None:
            ingested_at = time.time()

        content_sha256 = self.compute_sha256(content)
        payload = self._build_signing_payload(
            doc_id=doc_id,
            chunk_id=chunk_id,
            content_sha256=content_sha256,
            author=author,
            tenant_id=tenant_id,
            source_uri=source_uri,
            ingested_at=ingested_at,
        )

        signature = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

        return SignedMetadata(
            doc_id=doc_id,
            chunk_id=chunk_id,
            content_sha256=content_sha256,
            author=author,
            tenant_id=tenant_id,
            source_uri=source_uri,
            ingested_at=ingested_at,
            sanitizer_version=self.SANITIZER_VERSION,
            signature=signature,
        )

    def verify_chunk(self, content: str, metadata: Dict[str, Any]) -> bool:
        """Verifies that chunk content matches content_sha256 and HMAC signature is valid.

        Guards against direct manipulation of stored vector chunks.
        """
        required_keys = [
            "doc_id",
            "chunk_id",
            "content_sha256",
            "author",
            "tenant_id",
            "source_uri",
            "ingested_at",
            "signature",
        ]
        for key in required_keys:
            if key not in metadata:
                return False

        # Verify hash integrity
        calculated_hash = self.compute_sha256(content)
        if not hmac.compare_digest(calculated_hash, str(metadata["content_sha256"])):
            return False

        # Verify HMAC signature
        payload = self._build_signing_payload(
            doc_id=str(metadata["doc_id"]),
            chunk_id=str(metadata["chunk_id"]),
            content_sha256=calculated_hash,
            author=str(metadata["author"]),
            tenant_id=str(metadata["tenant_id"]),
            source_uri=str(metadata["source_uri"]),
            ingested_at=float(metadata["ingested_at"]),
        )
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, str(metadata["signature"])):
            return True

        # Check previous rotated keys if primary validation failed
        for old_k in self.previous_keys:
            candidate_sig = hmac.new(old_k, payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(candidate_sig, str(metadata["signature"])):
                return True

        return False
