"""Unit tests for GatewayConfig validation and environment parsing."""

import pytest
from gateway.config import GatewayConfig


def test_gateway_config_validation():
    cfg = GatewayConfig()
    cfg.validate()  # default must be valid

    with pytest.raises(ValueError, match="heuristic_risk_threshold"):
        invalid_cfg = GatewayConfig(heuristic_risk_threshold=1.5)
        invalid_cfg.validate()

    with pytest.raises(ValueError, match="chunk_overlap"):
        invalid_overlap = GatewayConfig(chunk_size=100, chunk_overlap=120)
        invalid_overlap.validate()


def test_gateway_config_from_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_RISK_THRESHOLD", "0.75")
    monkeypatch.setenv("GATEWAY_CHUNK_SIZE", "800")
    cfg = GatewayConfig.from_env()
    assert cfg.heuristic_risk_threshold == 0.75
    assert cfg.chunk_size == 800
