# Contributing to RAG Security Gateway

We welcome contributions from the community!

### Development Environment Setup
```bash
git clone https://github.com/ravishkarathnayaka/rag-security-poisoning-defense-gateway.git
cd rag-security-poisoning-defense-gateway
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Running Tests & Linting
```bash
python -m pytest
ruff check .
bandit -r gateway api
```

### Commit Message Conventions
All commit messages must adhere to Conventional Commits:
- `feat(...)`: New capability or detection heuristic
- `fix(...)`: Bug fix or security hardening
- `test(...)`: Unit, integration, or end-to-end tests
- `docs(...)`: Documentation and architectural diagrams
- `perf(...)`: Latency or throughput optimizations
