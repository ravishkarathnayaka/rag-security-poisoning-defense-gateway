# Security Policy & Vulnerability Reporting

### Threat Model
The gateway assumes an adversarial threat environment where:
1. Third-party documents submitted for ingestion may contain hidden payloads, indirect prompt injections, or steganographic markup.
2. The vector store storage layer may be accessed out-of-band by unauthorized actors. Cryptographic HMAC signatures ensure tampering is immediately detected.
3. Downstream LLMs are susceptible to prompt injection when presented with untrusted retrieved text without strict boundary framing.

### Reporting Vulnerabilities
If you discover a security vulnerability within the gateway, please report it privately via email to `security@example.com` or create a GitHub Security Advisory. Please do not report security issues via public GitHub issues.
