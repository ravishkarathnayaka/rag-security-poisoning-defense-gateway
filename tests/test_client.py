"""Unit tests for RAGDefenseClient SDK."""

from unittest.mock import MagicMock, patch
from gateway.client import RAGDefenseClient


def test_client_health():
    client = RAGDefenseClient("http://mock-gateway:8000")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "healthy", "service": "rag-security-gateway"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        data = client.health()
        assert data["status"] == "healthy"
        assert data["service"] == "rag-security-gateway"


def test_client_ingest_and_query():
    client = RAGDefenseClient("http://mock-gateway:8000")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"status": "approved", "chunks_stored": 2}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = client.ingest_document("Corporate policy text", filename="policy.txt")
        assert res["status"] == "approved"
        assert res["chunks_stored"] == 2
