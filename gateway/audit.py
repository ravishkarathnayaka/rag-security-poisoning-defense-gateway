"""Structured Security Audit Logger: CEF (Common Event Format) and JSON Security Events."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    """Standardized security event record for SIEM ingestion."""

    event_type: str  # INGESTION_QUARANTINE, RETRIEVAL_BLOCKED, TAMPER_DETECTED, ACCESS_ALLOWED
    severity: str    # INFO, LOW, MEDIUM, HIGH, CRITICAL
    doc_id: str
    tenant_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    def to_cef(self) -> str:
        """Formats the event in standard ArcSight Common Event Format (CEF)."""
        sev_map = {"INFO": "1", "LOW": "3", "MEDIUM": "5", "HIGH": "8", "CRITICAL": "10"}
        sev_num = sev_map.get(self.severity.upper(), "5")
        cef_str = (
            f"CEF:0|RAGSecurityGateway|DefenseGateway|1.0|{self.event_type}|"
            f"{self.reason}|{sev_num}|cs1={self.doc_id} cs1Label=DocId "
            f"cs2={self.tenant_id} cs2Label=TenantId msg={self.reason}"
        )
        return cef_str


class SecurityAuditLogger:
    """Manages security telemetry and SIEM audit event streams."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("rag_security_audit")
        self.events: List[AuditEvent] = []

    def record_event(
        self,
        event_type: str,
        severity: str,
        doc_id: str,
        reason: str = "",
        tenant_id: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            doc_id=doc_id,
            reason=reason,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )
        self.events.append(event)
        self.logger.info(event.to_json())
        return event

    def get_recent_events(self, limit: int = 50) -> List[AuditEvent]:
        return self.events[-limit:]
