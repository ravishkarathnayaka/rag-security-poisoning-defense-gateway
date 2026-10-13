"""Storage layer providing vector database integration, namespace isolation, and provenance checks."""

from gateway.storage.vector_store import SecureVectorStore, VectorStoreRecord

__all__ = ["SecureVectorStore", "VectorStoreRecord"]
