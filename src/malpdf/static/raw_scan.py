"""Bounded lexical diagnostics for untrusted PDF bytes.

These counters are intentionally lexical.  A literal name inside a PDF string
is not evidence of a parsed action and is reported separately by ``pdf_parser``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping


_NAME_DELIMITER = rb"(?=[\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}/%]|$)"


def _pdf_name_pattern(name: str) -> re.Pattern[bytes]:
    return re.compile(rb"/" + re.escape(name.encode("ascii")) + _NAME_DELIMITER)


def _word_pattern(word: str) -> re.Pattern[bytes]:
    return re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(word.encode("ascii")) + rb"(?![A-Za-z0-9_])")


# The existing paper-alignment dictionary documents these as lexical string
# occurrences.  Word boundaries keep obj/stream/xref distinct from endobj,
# endstream, and startxref respectively, which the published statistics imply.
RAW_FEATURE_PATTERNS: Mapping[str, re.Pattern[bytes]] = {
    "obj": _word_pattern("obj"),
    "endobj": _word_pattern("endobj"),
    "stream": _word_pattern("stream"),
    "endstream": _word_pattern("endstream"),
    "trailer": _word_pattern("trailer"),
    "xref": _word_pattern("xref"),
    "startxref": _word_pattern("startxref"),
    "page_command": _pdf_name_pattern("Page"),
    "Encrypt": _pdf_name_pattern("Encrypt"),
    # Standard PDF spelling is /ObjStm.  The paper's /ObJStm spelling is
    # retained as a documented ambiguity in schema.py rather than silently
    # normalizing the historical feature definition.
    "ObjStm": _pdf_name_pattern("ObjStm"),
    "JS": _pdf_name_pattern("JS"),
    "JavaScript": _pdf_name_pattern("JavaScript"),
    "AA": _pdf_name_pattern("AA"),
    "OpenAction": _pdf_name_pattern("OpenAction"),
    "Acroform": _pdf_name_pattern("Acroform"),
    "JBIG2Decode": _pdf_name_pattern("JBIG2Decode"),
    "RichMedia": _pdf_name_pattern("RichMedia"),
    "Launch": _pdf_name_pattern("Launch"),
    "EmbeddedFile": _pdf_name_pattern("EmbeddedFile"),
    "XFA": _pdf_name_pattern("XFA"),
    "Colors": re.compile(rb"/Colors[\x00\x09\x0a\x0c\x0d\x20]+>[\x00\x09\x0a\x0c\x0d\x20]+2\^24"),
    "URI": _pdf_name_pattern("URI"),
    "BaseEncoding": _pdf_name_pattern("BaseEncoding"),
    "Encoding": _pdf_name_pattern("Encoding"),
    "ProcSet": _pdf_name_pattern("ProcSet"),
    "Registry": _pdf_name_pattern("Registry"),
    "Resources": _pdf_name_pattern("Resources"),
    "www": _pdf_name_pattern("www"),
    "server": _pdf_name_pattern("server"),
    "Root": _pdf_name_pattern("Root"),
    "BitsPerComponent": _pdf_name_pattern("BitsPerComponent"),
}


def scan_raw_pdf_tokens(data: bytes) -> dict[str, int]:
    """Return deterministic lexical feature counts without interpreting content."""
    return {feature: len(pattern.findall(data)) for feature, pattern in RAW_FEATURE_PATTERNS.items()}
