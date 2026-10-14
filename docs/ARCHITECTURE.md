# System Architecture & Defense-in-Depth Pipeline

The RAG Security Poisoning Defense Gateway operates as an inline firewall and sanitization boundary between untrusted documents, external vector stores, and downstream Large Language Models.

```mermaid
flowchart TD
    subgraph Ingestion Pipeline
        A[Untrusted Document] --> B[Invisible Text Stripper]
        B -->|Unicode / Zero-Width / CSS Cleaned| C[Heuristic Scanner]
        C -->|Risk >= 0.60| D[Ingestion Quarantine]
        C -->|Risk < 0.60| E[Document Parser & Chunker]
        E --> F[Provenance Signer: HMAC-SHA256]
        F --> G[(Secure Vector Store)]
    end

    subgraph Retrieval Pipeline
        H[User Query] --> I[Vector Store Similarity Search]
        G --> I
        I --> J[Cryptographic Signature Verification]
        J -->|Signature Invalid| K[Tamper Alert & Drop]
        J -->|Signature Valid| L[Chunk Semantic Evaluator]
        L -->|Semantic Drift / High Imperative| M[Runtime Quarantine]
        L -->|Aligned & Benign| N[Defensive Context Formatter]
        N --> O[XML Delimiter Boundary Hardening]
        O --> P[Hardened LLM Prompt Assembly]
    end
```
