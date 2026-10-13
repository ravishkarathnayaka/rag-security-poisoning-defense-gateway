"""Pytest shared fixtures and test configuration."""

from __future__ import annotations

import shutil
import tempfile

import pytest

from gateway.config import GatewayConfig
from gateway.ingestion.document_parser import DocumentParser
from gateway.ingestion.heuristic_scanner import HeuristicScanner
from gateway.ingestion.invisible_text_strip import InvisibleTextStripper
from gateway.ingestion.provenance_signer import ProvenanceSigner
from gateway.pipeline import RAGDefenseGateway
from gateway.retrieval.chunk_evaluator import ChunkEvaluator
from gateway.retrieval.defensive_formatter import DefensiveFormatter
from gateway.retrieval.injection_detector import InjectionDetector
from gateway.storage.vector_store import SecureVectorStore


@pytest.fixture
def temp_chroma_dir():
    """Provides a clean temporary directory for vector database persistence."""
    temp_dir = tempfile.mkdtemp(prefix="rag_test_chroma_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def stripper():
    return InvisibleTextStripper()


@pytest.fixture
def scanner():
    return HeuristicScanner(risk_threshold=0.60, instruction_density_threshold=0.35)


@pytest.fixture
def signer():
    return ProvenanceSigner(secret_key="test-key-384819284")


@pytest.fixture
def parser():
    return DocumentParser(chunk_size=400, chunk_overlap=40)


@pytest.fixture
def formatter():
    return DefensiveFormatter(tag_name="untrusted_retrieved_context")


@pytest.fixture
def evaluator():
    return ChunkEvaluator()


@pytest.fixture
def detector(scanner):
    return InjectionDetector(risk_threshold=0.50, heuristic_scanner=scanner)


@pytest.fixture
def vector_store(temp_chroma_dir, signer):
    return SecureVectorStore(
        persist_dir=temp_chroma_dir,
        base_collection="test_collection",
        provenance_signer=signer,
    )


@pytest.fixture
def gateway(temp_chroma_dir):
    cfg = GatewayConfig(
        chroma_persist_dir=temp_chroma_dir,
        default_collection="test_rag_gateway",
        provenance_secret_key="test-secret-key-999",
        heuristic_risk_threshold=0.60,
        instruction_density_threshold=0.35,
        injection_risk_threshold=0.50,
    )
    return RAGDefenseGateway(cfg)
