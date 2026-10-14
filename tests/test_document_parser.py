"""Unit tests for document parsing, format extraction, and size limit enforcement."""

import pytest
from gateway.ingestion.document_parser import DocumentParser


def test_document_parser_markdown_and_html():
    parser = DocumentParser(chunk_size=100, chunk_overlap=20)
    md_text = "# Header 1\n\nThis is a [link](https://example.com) and an ![image](img.png)."
    doc = parser.parse(md_text, filename="test.md")
    assert "Header 1" in doc.raw_text
    assert "https://example.com" not in doc.raw_text
    assert len(doc.chunks) > 0

    html_text = "<html><body><h1>Title</h1><p>Paragraph content</p><script>alert(1)</script></body></html>"
    doc_html = parser.parse(html_text, filename="test.html")
    assert "alert(1)" not in doc_html.raw_text
    assert "Title" in doc_html.raw_text
    assert "Paragraph content" in doc_html.raw_text


def test_document_parser_size_limit_rejection():
    parser = DocumentParser(max_doc_size_bytes=100)
    large_payload = "A" * 200
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        parser.parse(large_payload, filename="large.txt")
