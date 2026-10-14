# Production Deployment Guide

### Standalone Docker Deployment
```bash
docker build -t rag-security-gateway:latest -f docker/Dockerfile .
docker run -d -p 8000:8000 \
  -e GATEWAY_PROVENANCE_KEY="your-secret-master-key" \
  -v $(pwd)/chroma_data:/app/chroma_data \
  rag-security-gateway:latest
```

### Docker Compose Stack
Deploy with persistent volume storage and telemetry integration:
```bash
docker compose up -d
```

### Kubernetes Deployment
Deploy using standard deployment manifests with liveness and readiness probes pointing to `/api/health`.
