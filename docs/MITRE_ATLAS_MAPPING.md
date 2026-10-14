# MITRE ATLAS Threat Matrix Mapping

Mapping of gateway capabilities to the [MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)](https://atlas.mitre.org/) framework.

| MITRE ATLAS ID | Technique Name | Gateway Mitigation | Verification Test |
| :--- | :--- | :--- | :--- |
| **AML.T0054** | LLM Indirect Prompt Injection | Neutralizes instruction overrides embedded within retrieved context chunks | `test_runtime_injection_quarantine` |
| **AML.T0051** | LLM Prompt Injection | Flags imperative command triggers and system persona hijack patterns | `test_flag_ignore_previous_instructions` |
| **AML.T0043** | LLM Data Poisoning | Detects out-of-band manipulation using HMAC-SHA256 signature verification | `test_tampered_vector_provenance_detected` |
| **AML.T0040** | Steganography / Obfuscation | Normalizes Cyrillic lookalikes, strips zero-width BOMs and hidden CSS tags | `test_zero_width_sanitization_during_ingestion` |
| **AML.T0029** | Denial of Service | Enforces document byte limits to prevent resource exhaustion and decompression bombs | `test_document_parser_size_limit_rejection` |
