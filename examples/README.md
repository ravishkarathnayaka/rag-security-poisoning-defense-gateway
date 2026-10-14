# Integration Examples

This directory provides working, production-ready patterns for integrating the **RAG Security Poisoning Defense Gateway** into popular LLM orchestration frameworks:

- [`langchain_integration.py`](langchain_integration.py): Integrating gateway retrieval boundary isolation into LangChain retrievers.
- [`llamaindex_integration.py`](llamaindex_integration.py): Using `ChunkEvaluator` as a LlamaIndex node post-processor to filter poisoned chunks.
- [`standalone_rag_pipeline.py`](standalone_rag_pipeline.py): Zero-dependency pure-Python pipeline executing ingestion, cryptographic signing, and retrieval.
