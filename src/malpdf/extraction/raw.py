"""Bounded lexical measurements, explicitly distinct from parsed PDF facts."""

from collections import Counter
import hashlib
import math
import re

from malpdf.static.raw_scan import scan_raw_pdf_tokens

MAX_MARKERS = 256
MAX_NAMES = 4096
WINDOW_BYTES = 4096
MAX_WINDOWS = 256
_NAME = re.compile(rb"/[^\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}/%]{1,256}")
_ESCAPE = re.compile(rb"#([a-fA-F0-9]{2})")


def _entropy(data):
    if not data:
        return 0.0
    return -sum((count / len(data)) * math.log2(count / len(data))
                for count in Counter(data).values())


def _offsets(data, token, maximum=MAX_MARKERS):
    values, start = [], 0
    while maximum is None or len(values) <= maximum:
        position = data.find(token, start)
        if position < 0:
            return values, True
        values.append(position)
        start = position + len(token)
    return values[:maximum], False


def inspect_raw_layout(data, *, full_scan=False):
    """Inspect already size-verified bytes inside a resource-limited worker.

    Markers/names can occur in comments, strings and streams. No object,
    revision, exploit, or hidden-payload identity is inferred from these hints.
    """
    if not isinstance(data, bytes):
        raise ValueError("raw_snapshot_type")
    counts = Counter(data)
    header = data.find(b"%PDF-")
    last_eof = data.rfind(b"%%EOF")
    markers = {}
    for name, token in (("header", b"%PDF-"), ("eof", b"%%EOF"), ("startxref", b"startxref")):
        offsets, complete = _offsets(data, token, None if full_scan else MAX_MARKERS)
        markers[name] = {"offsets": offsets, "complete": complete}
    windows = []
    for start in range(0, len(data) if full_scan else min(len(data), WINDOW_BYTES * MAX_WINDOWS), WINDOW_BYTES):
        end = min(len(data), start + WINDOW_BYTES)
        windows.append({"start": start, "end": end, "entropy": _entropy(data[start:end])})
    name_hints, names_seen, escaped, complete = [], 0, 0, True
    for match in _NAME.finditer(data):
        if not full_scan and names_seen == MAX_NAMES:
            complete = False
            break
        raw = match.group()
        normalized = _ESCAPE.sub(lambda item: bytes([int(item[1], 16)]), raw)
        names_seen += 1
        if raw != normalized:
            escaped += 1

            name_hints.append({"start": match.start(), "end": match.end(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "normalized_sha256": hashlib.sha256(normalized).hexdigest()})
    prefix = data[:header] if header >= 0 else None
    suffix_start = last_eof + len(b"%%EOF") if last_eof >= 0 else None
    suffix = data[suffix_start:] if suffix_start is not None else None
    return {"schema_version": "pdf-raw-layout-v1", "scope": "immutable original bytes; lexical hints only",
            "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "byte_histogram": [counts.get(value, 0) for value in range(256)],
            "entropy": _entropy(data), "markers": markers,
            "header_offset": header if header >= 0 else None,
            "last_eof_offset": last_eof if last_eof >= 0 else None,
            "prefix_bytes": len(prefix) if prefix is not None else None,
            "prefix_entropy": _entropy(prefix) if prefix is not None else None,
            "suffix_start": suffix_start,
            "suffix_bytes": len(suffix) if suffix is not None else None,
            "suffix_entropy": _entropy(suffix) if suffix is not None else None,
            "entropy_windows": windows, "window_bytes": WINDOW_BYTES,
            "entropy_windows_complete": full_scan or len(data) <= WINDOW_BYTES * MAX_WINDOWS,
            "name_candidates_seen": names_seen, "escaped_name_candidates": escaped,
            "name_scan_complete": complete, "escaped_name_hints": name_hints,
            "token_counts": scan_raw_pdf_tokens(data)}
