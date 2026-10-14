"""Document Parser & Chunker: Multi-format Extraction (PDF, Markdown, HTML, Plain Text)."""

from __future__ import annotations

import html
import io
import re
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional


class HTMLTextExtractor(HTMLParser):
    """Safe HTML parser extracting visible text while dropping scripts, styles, and headers."""

    def __init__(self):
        super().__init__()
        self.result = []
        self._skip_depth = 0
        self._skip_tags = {"script", "style", "head", "title", "meta", "noscript"}

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._skip_tags:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            cleaned = data.strip()
            if cleaned:
                self.result.append(cleaned)

    def get_text(self) -> str:
        return "\n".join(self.result)


@dataclass
class ParsedDocument:
    """Standardized representation of an ingested document."""

    doc_id: str
    filename: str
    mime_type: str
    raw_text: str
    chunks: List[str] = field(default_factory=list)


class DocumentParser:
    """Parses heterogeneous file formats into sanitized text representations and chunks."""

    def __init__(
        self,
        chunk_size: int = 500,
        chunk_overlap: int = 60,
        max_doc_size_bytes: int = 10 * 1024 * 1024,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.max_doc_size_bytes = max_doc_size_bytes

    def parse_html(self, content: str) -> str:
        """Extracts readable content from HTML while stripping non-content tags."""
        extractor = HTMLTextExtractor()
        extractor.feed(content)
        text = extractor.get_text()
        return html.unescape(text)

    def parse_markdown(self, content: str) -> str:
        """Strips markdown frontmatter, link URLs, and excess symbols for clear textual analysis."""
        # Strip YAML / TOML frontmatter (--- ... ---)
        text = re.sub(r"^---[\s\S]*?---\s*", "", content, flags=re.MULTILINE)
        # Convert links [text](url) -> text
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
        # Convert image tags ![alt](url) -> alt
        text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
        # Clean header markers
        text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
        return text.strip()

    def parse_pdf(self, content_bytes: bytes) -> str:
        """Extracts text from PDF binary.

        Tries pypdf/pypdf2 first, then falls back to pure-Python PDF stream scanner.
        """
        # Attempt standard pypdf if available
        try:
            import pypdf  # type: ignore

            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
            pages_text = [page.extract_text() or "" for page in reader.pages]
            full_text = "\n".join(pages_text).strip()
            if full_text:
                return full_text
        except Exception:
            pass

        # Fallback: Extract ASCII / UTF-8 text strings within PDF stream objects
        try:
            text_chunks = []
            # Look for PDF text objects between BT and ET
            matches = re.findall(
                rb"BT\s*(.*?)\s*ET", content_bytes, flags=re.DOTALL
            )
            for m in matches:
                # Extract Tj or TJ strings
                str_matches = re.findall(rb"\((.*?)\)\s*Tj", m)
                for sm in str_matches:
                    try:
                        text_chunks.append(sm.decode("latin1", errors="ignore"))
                    except Exception:
                        pass
            if text_chunks:
                return " ".join(text_chunks)
        except Exception:
            pass

        # Final fallback: Decode with errors ignored and extract printable text runs
        decoded = content_bytes.decode("latin1", errors="ignore")
        printable = re.findall(r"[a-zA-Z0-9\s.,!?:;'\"]{4,}", decoded)
        return "\n".join(printable)

    def chunk_text(self, text: str) -> List[str]:
        """Splits document text into overlapping segments respecting sentence and newline boundaries."""
        cleaned = re.sub(r"\r\n|\r", "\n", text).strip()
        if not cleaned:
            return []

        if len(cleaned) <= self.chunk_size:
            return [cleaned]

        chunks: List[str] = []
        start = 0
        text_len = len(cleaned)

        while start < text_len:
            end = min(start + self.chunk_size, text_len)

            if end < text_len:
                # Try to break at paragraph or newline boundary
                newline_pos = cleaned.rfind("\n", start + int(self.chunk_size * 0.5), end)
                if newline_pos != -1:
                    end = newline_pos + 1
                else:
                    # Try to break at sentence punctuation
                    punct_pos = max(
                        cleaned.rfind(". ", start + int(self.chunk_size * 0.5), end),
                        cleaned.rfind("! ", start + int(self.chunk_size * 0.5), end),
                        cleaned.rfind("? ", start + int(self.chunk_size * 0.5), end),
                    )
                    if punct_pos != -1:
                        end = punct_pos + 2
                    else:
                        # Fallback: break at space
                        space_pos = cleaned.rfind(" ", start + int(self.chunk_size * 0.5), end)
                        if space_pos != -1:
                            end = space_pos + 1

            chunk = cleaned[start:end].strip()
            if chunk:
                chunks.append(chunk)

            if end >= text_len:
                break

            # Slide forward by (end - overlap)
            start = max(start + 1, end - self.chunk_overlap)

        return chunks

    def parse(
        self,
        content: str | bytes,
        filename: str = "document.txt",
        mime_type: Optional[str] = None,
        doc_id: Optional[str] = None,
    ) -> ParsedDocument:
        """Parses document by MIME type or extension and chunks text."""
        if doc_id is None:
            doc_id = str(uuid.uuid4())

        content_len = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
        if content_len > self.max_doc_size_bytes:
            raise ValueError(f"Document {filename} ({content_len} bytes) exceeds maximum limit of {self.max_doc_size_bytes} bytes")

        fn_lower = filename.lower()
        if mime_type is None:
            if fn_lower.endswith(".pdf"):
                mime_type = "application/pdf"
            elif fn_lower.endswith(".html") or fn_lower.endswith(".htm"):
                mime_type = "text/html"
            elif fn_lower.endswith(".md") or fn_lower.endswith(".markdown"):
                mime_type = "text/markdown"
            else:
                mime_type = "text/plain"

        # Extract text based on format
        if mime_type == "application/pdf":
            raw_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            extracted_text = self.parse_pdf(raw_bytes)
        else:
            raw_str = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
            if mime_type == "text/html":
                extracted_text = self.parse_html(raw_str)
            elif mime_type == "text/markdown":
                extracted_text = self.parse_markdown(raw_str)
            else:
                extracted_text = raw_str

        chunks = self.chunk_text(extracted_text)

        return ParsedDocument(
            doc_id=doc_id,
            filename=filename,
            mime_type=mime_type,
            raw_text=extracted_text,
            chunks=chunks,
        )
