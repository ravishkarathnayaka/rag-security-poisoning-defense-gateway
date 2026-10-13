"""Ingestion-Time Text Sanitization: Zero-Width Character Stripping, Homoglyph Normalization, and Hidden CSS/Markup Removal."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class SanitizationTelemetry:
    """Detailed telemetry describing stripped anomalies during ingestion."""

    zero_width_chars_removed: int = 0
    homoglyphs_normalized: int = 0
    hidden_elements_stripped: int = 0
    bidi_overrides_removed: int = 0
    ascii_smuggling_tags_removed: int = 0
    anomalies: List[str] = field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        return (
            self.zero_width_chars_removed > 0
            or self.homoglyphs_normalized > 0
            or self.hidden_elements_stripped > 0
            or self.bidi_overrides_removed > 0
            or self.ascii_smuggling_tags_removed > 0
        )


class InvisibleTextStripper:
    """Detects, logs, and neutralizes obfuscated text, hidden CSS, and invisible characters."""

    # Zero-width spaces, joiners, non-joiners, word joiners, soft hyphens, BOM
    ZERO_WIDTH_CHARS = {
        "\u200B",  # Zero-width space
        "\u200C",  # Zero-width non-joiner
        "\u200D",  # Zero-width joiner
        "\uFEFF",  # Byte order mark / Zero-width no-break space
        "\u2060",  # Word joiner
        "\u180E",  # Mongolian vowel separator
        "\u200E",  # Left-to-right mark
        "\u200F",  # Right-to-left mark
        "\u2062",  # Invisible times
        "\u2063",  # Invisible separator
        "\u2064",  # Invisible plus
        "\u00AD",  # Soft hyphen
    }

    # Bidirectional override characters often used to spoof or reverse prompt tokens
    BIDI_OVERRIDES = {
        "\u202A",  # Left-to-Right Embedding
        "\u202B",  # Right-to-Left Embedding
        "\u202C",  # Pop Directional Formatting
        "\u202D",  # Left-to-Right Override
        "\u202E",  # Right-to-Left Override
        "\u2066",  # Left-to-Right Isolate
        "\u2067",  # Right-to-Left Isolate
        "\u2068",  # First Strong Isolate
        "\u2069",  # Pop Directional Isolate
    }

    # Common Cyrillic & Greek homoglyphs used to evade keyword filters
    # Maps visually indistinguishable Cyrillic/Greek codepoints to Latin counterparts
    HOMOGLYPH_MAP = {
        # Cyrillic lowercase
        "\u0430": "a",
        "\u0441": "c",
        "\u0435": "e",
        "\u043E": "o",
        "\u0440": "p",
        "\u0445": "x",
        "\u0443": "y",
        "\u0456": "i",
        "\u0458": "j",
        "\u0455": "s",
        # Cyrillic uppercase
        "\u0410": "A",
        "\u0412": "B",
        "\u0421": "C",
        "\u0415": "E",
        "\u041D": "H",
        "\u0406": "I",
        "\u0408": "J",
        "\u041A": "K",
        "\u041C": "M",
        "\u041E": "O",
        "\u0420": "P",
        "\u0405": "S",
        "\u0422": "T",
        "\u0425": "X",
        # Greek letters
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039A": "K",
        "\u039C": "M",
        "\u039D": "N",
        "\u039F": "O",
        "\u03A1": "P",
        "\u03A4": "T",
        "\u03A5": "Y",
        "\u03A7": "X",
        "\u03BF": "o",
        "\u03BD": "v",
    }

    # Regex detecting hidden HTML / CSS styling patterns
    HIDDEN_CSS_PATTERNS = [
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*display\s*:\s*none[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*visibility\s*:\s*hidden[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*font-size\s*:\s*0(?:px|pt|em|rem)?[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*opacity\s*:\s*0(?:\.0+)?(?:;|['"])[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*color\s*:\s*(?:transparent|rgba\([^)]*,\s*0\)|#00000000)[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        # White-on-white / matching color concealment
        re.compile(
            r"""<[^>]+style\s*=\s*['"][^'"]*color\s*:\s*(?:#ffffff|#fff|white)[^'"]*background(?:-color)?\s*:\s*(?:#ffffff|#fff|white)[^'"]*['"][^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        # Hidden HTML attribute
        re.compile(
            r"""<[^>]+\bhidden\b[^>]*>[\s\S]*?<\/[^>]+>""",
            re.IGNORECASE,
        ),
        # HTML comment block payloads (often used for prompt injection smuggling)
        re.compile(
            r"""<!--[\s\S]*?-->""",
            re.IGNORECASE,
        ),
    ]

    # Unicode tag characters (U+E0000 to U+E007F) used in ASCII smuggling
    ASCII_SMUGGLING_REGEX = re.compile(r"[\U000e0000-\U000e007f]")

    def strip_zero_width_and_bidi(self, text: str) -> Tuple[str, int, int]:
        """Strips zero-width characters and directional overrides.

        Returns (cleaned_text, zero_width_count, bidi_count).
        """
        zero_width_count = 0
        bidi_count = 0
        cleaned_chars = []

        for ch in text:
            if ch in self.ZERO_WIDTH_CHARS:
                zero_width_count += 1
            elif ch in self.BIDI_OVERRIDES:
                bidi_count += 1
            else:
                cleaned_chars.append(ch)

        return "".join(cleaned_chars), zero_width_count, bidi_count

    def strip_ascii_smuggling(self, text: str) -> Tuple[str, int]:
        """Detects and strips unicode tag codepoints used for ASCII smuggling."""
        matches = self.ASCII_SMUGGLING_REGEX.findall(text)
        count = len(matches)
        cleaned = self.ASCII_SMUGGLING_REGEX.sub("", text)
        return cleaned, count

    def normalize_homoglyphs(self, text: str) -> Tuple[str, int]:
        """Normalizes Cyrillic/Greek homoglyphs and fullwidth ASCII characters into standard Latin."""
        # Step 1: Compatibility Decomposition (NFKC) handles full-width ASCII and many ligatures
        decomposed = unicodedata.normalize("NFKC", text)

        # Step 2: Custom Homoglyph Map for Cyrillic and Greek lookalikes
        homoglyph_count = 0
        normalized_chars = []

        for ch in decomposed:
            if ch in self.HOMOGLYPH_MAP:
                normalized_chars.append(self.HOMOGLYPH_MAP[ch])
                homoglyph_count += 1
            else:
                normalized_chars.append(ch)

        return "".join(normalized_chars), homoglyph_count

    def strip_hidden_markup(self, text: str) -> Tuple[str, int, List[str]]:
        """Identifies and strips CSS-hidden blocks, transparent text, and comment payloads."""
        cleaned_text = text
        elements_stripped = 0
        descriptions: List[str] = []

        for pattern in self.HIDDEN_CSS_PATTERNS:
            matches = pattern.findall(cleaned_text)
            if matches:
                elements_stripped += len(matches)
                for m in matches:
                    snippet = m[:60].replace("\n", " ").strip()
                    descriptions.append(f"Hidden CSS/Markup stripped: {snippet}...")
                cleaned_text = pattern.sub(" ", cleaned_text)

        # Clean multiple spaces left by replacements
        cleaned_text = re.sub(r"[ \t]+", " ", cleaned_text)
        return cleaned_text, elements_stripped, descriptions

    def sanitize(
        self, text: str, is_html: bool = False
    ) -> Tuple[str, SanitizationTelemetry]:
        """Performs comprehensive multi-stage sanitization on document text.

        Returns (sanitized_text, telemetry).
        """
        telemetry = SanitizationTelemetry()
        current = text

        # Stage 1: Strip Zero-Width and Bidi override characters
        current, zw_count, bidi_count = self.strip_zero_width_and_bidi(current)
        telemetry.zero_width_chars_removed = zw_count
        telemetry.bidi_overrides_removed = bidi_count
        if zw_count > 0:
            telemetry.anomalies.append(
                f"Stripped {zw_count} zero-width unicode characters."
            )
        if bidi_count > 0:
            telemetry.anomalies.append(
                f"Stripped {bidi_count} bidirectional override characters."
            )

        # Stage 2: Strip ASCII Smuggling Tag codepoints
        current, tag_count = self.strip_ascii_smuggling(current)
        telemetry.ascii_smuggling_tags_removed = tag_count
        if tag_count > 0:
            telemetry.anomalies.append(
                f"Neutralized {tag_count} ASCII smuggling tag characters."
            )

        # Stage 3: Normalize Homoglyphs
        current, homoglyph_count = self.normalize_homoglyphs(current)
        telemetry.homoglyphs_normalized = homoglyph_count
        if homoglyph_count > 0:
            telemetry.anomalies.append(
                f"Normalized {homoglyph_count} suspicious homoglyph characters to standard Latin."
            )

        # Stage 4: Strip Hidden Markup / CSS (always executed if HTML tags or comments are detected)
        if is_html or "<" in current:
            current, hidden_count, descriptions = self.strip_hidden_markup(current)
            telemetry.hidden_elements_stripped = hidden_count
            telemetry.anomalies.extend(descriptions)

        return current, telemetry
