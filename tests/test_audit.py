"""Unit tests for structured audit logger and CEF format serialization."""

from gateway.audit import SecurityAuditLogger


def test_security_audit_logger_json_and_cef():
    logger = SecurityAuditLogger()
    event = logger.record_event(
        event_type="INGESTION_QUARANTINE",
        severity="HIGH",
        doc_id="doc_malicious_1",
        reason="Matched pattern OVERRIDE_INSTRUCTIONS",
        tenant_id="tenant_alpha",
    )

    assert event.event_type == "INGESTION_QUARANTINE"
    json_repr = event.to_json()
    assert "doc_malicious_1" in json_repr
    assert "OVERRIDE_INSTRUCTIONS" in json_repr

    cef_repr = event.to_cef()
    assert cef_repr.startswith("CEF:0|RAGSecurityGateway|DefenseGateway")
    assert "cs1=doc_malicious_1" in cef_repr
    assert "cs2=tenant_alpha" in cef_repr

    recent = logger.get_recent_events(10)
    assert len(recent) == 1
