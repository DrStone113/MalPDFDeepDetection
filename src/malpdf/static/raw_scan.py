"""Exact PDFMalExtract v0.1 raw-byte counters for untrusted PDF bytes.

The released reference implementation uses ``bytes.count`` and three explicit
subtractions for overlapping tokens.  These are canonical RIT measurements,
not parser-confirmed semantics: a literal inside a PDF string still counts.
"""

from __future__ import annotations

from collections.abc import Mapping


RAW_DIRECT_TOKENS: Mapping[str, bytes] = {
    "trailer": b"trailer", "Encrypt": b"/Encrypt", "ObjStm": b"/ObjStm",
    "JS": b"/JS", "JavaScript": b"/JavaScript", "AA": b"/AA",
    "OpenAction": b"/OpenAction", "Acroform": b"/Acroform",
    "JBIG2Decode": b"/JBIG2Decode", "RichMedia": b"/RichMedia",
    "Launch": b"/Launch", "EmbeddedFile": b"/EmbeddedFile", "XFA": b"/XFA",
    "Colors": b"/Colors > 2^24", "URI": b"/URI",
    # This apparent leading "j" is a released PDFMalExtract v0.1 quirk.
    # It is retained for dataset-contract fidelity, not corrected to /BaseEncoding.
    "BaseEncoding": b"j/BaseEncoding", "Encoding": b"/Encoding", "ProcSet": b"/ProcSet",
    "Registry": b"/Registry", "Resources": b"/Resources", "www": b"/www",
    "server": b"/server", "Root": b"/Root", "BitsPerComponent": b"/BitsPerComponent",
}


def scan_raw_pdf_tokens(data: bytes) -> dict[str, int]:
    """Return deterministic raw counts with PDFMalExtract's overlap rules."""
    endobj = data.count(b"endobj")
    endstream = data.count(b"endstream")
    startxref = data.count(b"startxref")
    counts = {
        "endobj": endobj,
        "obj": data.count(b"obj") - endobj,
        "endstream": endstream,
        "stream": data.count(b"stream") - endstream,
        "startxref": startxref,
        "xref": data.count(b"xref") - startxref,
        "page_command": data.count(b"/Page") - data.count(b"/Pages"),
    }
    counts.update({feature: data.count(token) for feature, token in RAW_DIRECT_TOKENS.items()})
    return counts
