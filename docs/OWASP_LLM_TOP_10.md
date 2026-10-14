# OWASP Top 10 for Large Language Models - Defense Matrix

This document provides a comprehensive mapping of the **RAG Security Poisoning Defense Gateway** defensive mechanisms against the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

| Vulnerability ID | Threat Name | Gateway Defense Mechanism | Defense Layer |
| :--- | :--- | :--- | :--- |
| **LLM01** | Prompt Injection | Boundary isolation via XML tags, delimiter escaping, and multi-pattern heuristic scanning | Ingestion & Retrieval |
| **LLM02** | Sensitive Information Disclosure | High-entropy canary token generation and egress leak verification | Retrieval Formatting |
| **LLM03** | Supply Chain Vulnerabilities | Cryptographic HMAC-SHA256 provenance manifests and key rotation | Storage & Ingestion |
| **LLM04** | Data and Model Poisoning | Pre-ingestion steganography stripping (zero-width, homoglyph normalization, hidden CSS) | Ingestion Pre-Filter |
| **LLM05** | Improper Output Handling | Defensive instruction encapsulation preventing model execution of retrieved text | Runtime Boundary |
| **LLM06** | Excessive Agency | Strict tenant isolation and quarantine gating for unauthorized payloads | Vector Store |
| **LLM07** | System Prompt Leakage | Detection of prompt extraction commands (`reveal hidden instructions`, `repeat system prompt`) | Heuristic Scanner |
| **LLM08** | Vector and Embedding Weaknesses | Cosine similarity thresholding, lexical overlap, and instruction density penalties | Semantic Evaluator |
| **LLM09** | Misinformation / Hallucination | Quarantine of drifting chunks and strict fact-only grounding directives | Context Formatter |
| **LLM10** | Unbounded Consumption | Maximum document size limits, chunk overlap validation, and rate controls | Document Parser |
