from __future__ import annotations

from copy import copy
from functools import partial
import hashlib
import io
from itertools import islice
import json
import math
from pathlib import Path
import re
from typing import Any
import zlib

import numpy as np
import pikepdf
import pypdf
from pypdf import PdfReader
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NullObject,
    NumberObject,
    StreamObject,
    TextStringObject,
    read_object,
)

from malpdf.extraction.byte_images import ByteImageLimits, _tile_order
from malpdf.extraction.filters import DecodeBudget, FilterLimits, _parameters, _predict, _Stopped, decode_filters
from malpdf.extraction.font_containers import inspect_cff, inspect_type1, inspect_woff
from malpdf.extraction.media import (
    MediaIssue,
    inspect_flash,
    inspect_font,
    jbig2_structure,
    jpeg_structure,
    jpx_structure,
)
from malpdf.features.contract_v3 import DERIVED, FEATURES, LEXICAL, RAW, log_matrix
from malpdf.scanner.forensic import (
    _strip_diacritics,
    evaluate_javascript_semantics,
    invalidate_incomplete_javascript_verification,
    is_risky_remote_target,
    is_suspicious_uri,
    is_untrusted_http_uri,
    phishing_lure_phrases,
)
from malpdf.scanner.qr_scan import empty_qr_analysis, page_has_image_xobject, scan_pdf_qr_codes
from malpdf.scanner.signatures import match_pdf_signatures
from malpdf.scanner.static_evidence import CODEC_QUOTA_REASON_CODES, is_quota_only_codec_reasons
from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.raw_scan import count_acroform_names, scan_raw_pdf_tokens
from malpdf.static.xfa_xml import inspect_xfa_xml

NODE_TYPES: dict[str, int] = {
    "catalog": 0,
    "pages": 1,
    "page": 2,
    "action": 3,
    "annotation": 4,
    "script": 5,
    "stream": 6,
    "filespec": 7,
    "pdf_object": 8,
}

EDGE_TYPES: dict[tuple[str, str], int] = {
    ("catalog", "pages"): 0,
    ("pages", "page"): 1,
    ("catalog", "action"): 2,
    ("page", "action"): 3,
    ("action", "script"): 4,
    ("catalog", "script"): 5,
    ("page", "stream"): 6,
    ("pdf_object", "pdf_object"): 7,
}

AST_NODE_TYPES: list[str] = [
    "ArrayExpression",
    "AssignmentExpression",
    "BinaryExpression",
    "BlockStatement",
    "CallExpression",
    "ConditionalExpression",
    "ExpressionStatement",
    "FunctionDeclaration",
    "FunctionExpression",
    "Identifier",
    "IfStatement",
    "Literal",
    "MemberExpression",
    "NewExpression",
    "ObjectExpression",
    "ReturnStatement",
    "SequenceExpression",
    "UnaryExpression",
    "UpdateExpression",
    "VariableDeclaration",
    "VariableDeclarator",
    "WhileStatement",
    "ForStatement",
    "ForInStatement",
    "DoWhileStatement",
    "SwitchStatement",
    "TryStatement",
    "CatchClause",
    "ThrowStatement",
]

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCALER_PATH = REPO_ROOT / "configs" / "tabular_scaler.json"
DEFAULT_V3_CONTRACT_PATH = REPO_ROOT / "configs" / "transgraph_v3_contract.json"
DEFAULT_V4_CONTRACT_PATH = REPO_ROOT / "configs" / "transgraph_v4_contract.json"
REGIME_B_NAMES = tuple(name for name in LEXICAL if name != "lexical_AcroForm") + RAW[:3] + DERIVED[:4]
REGIME_B_INDICES = tuple(FEATURES.index(name) for name in REGIME_B_NAMES)
VERIFIED_CONTRACT_VERSION = "pdf-graph-projection-v2"
DEFAULT_MAX_PDF_BYTES = 100 * 1024 * 1024

_SCANNER_DIRECT_TOKENS: tuple[tuple[str, bytes], ...] = (
    ("Encrypt", b"/Encrypt"),
    ("ObjStm", b"/ObjStm"),
    ("JS", b"/JS"),
    ("JavaScript", b"/JavaScript"),
    ("AA", b"/AA"),
    ("OpenAction", b"/OpenAction"),
    ("Acroform", b"/Acroform"),
    ("JBIG2Decode", b"/JBIG2Decode"),
    ("RichMedia", b"/RichMedia"),
    ("Launch", b"/Launch"),
    ("EmbeddedFile", b"/EmbeddedFile"),
    ("XFA", b"/XFA"),
    ("Colors", b"/Colors > 2^24"),
    ("URI", b"/URI"),
)


def _scan_scanner_raw_tokens(data: bytes) -> dict[str, int]:
    endobj = data.count(b"endobj")
    endstream = data.count(b"endstream")
    counts = {
        "endobj": endobj,
        "obj": data.count(b"obj") - endobj,
        "endstream": endstream,
        "stream": data.count(b"stream") - endstream,
        "page_command": data.count(b"/Page") - data.count(b"/Pages"),
        "Resources": data.count(b"/Resources"),
        "Root": data.count(b"/Root"),
    }
    for feature, token in _SCANNER_DIRECT_TOKENS:
        counts[feature] = data.count(token)
    counts["AcroForm"] = count_acroform_names(data)
    return counts


_PDF_NAME = re.compile(rb"/[^\x00\s()<>\[\]{}/%]*#[0-9a-fA-F]{2}[^\x00\s()<>\[\]{}/%]*")
_HEX_ESCAPE = re.compile(rb"#([0-9a-fA-F]{2})")
_RECOVERABLE_TOKENS = {
    "JS",
    "JavaScript",
    "AA",
    "OpenAction",
    "AcroForm",
    "Acroform",
    "JBIG2Decode",
    "RichMedia",
    "Launch",
    "EmbeddedFile",
    "XFA",
    "Encrypt",
}
_STATIC_BYTE_LIMIT = 4 * 1024**2
_STATIC_FILTER_LIMITS = FilterLimits(max_input_bytes=_STATIC_BYTE_LIMIT, max_stage_bytes=_STATIC_BYTE_LIMIT)
_CODEC_DOC_BUDGET_BYTES = 96 * 1024**2
_CODEC_FILTER_LIMITS = FilterLimits(
    max_input_bytes=16 * 1024**2,
    max_stage_bytes=8 * 1024**2,
    max_total_bytes=8 * 1024**2,
    max_filters=8,
    max_expansion_ratio=500,
)
_STREAM_PREVIEW_LIMIT = 64 * 1024
_STREAM_PREVIEW_LIMITS = FilterLimits(
    max_input_bytes=_STREAM_PREVIEW_LIMIT,
    max_stage_bytes=_STREAM_PREVIEW_LIMIT,
    max_total_bytes=_STREAM_PREVIEW_LIMIT,
    max_expansion_ratio=1000,
)
_NON_JS_ACTIONS = {
    "/Launch",
    "/ImportData",
    "/GoToE",
    "/GoToR",
    "/SubmitForm",
    "/Rendition",
    "/Movie",
    "/Sound",
    "/RichMediaExecute",
}
_NON_JS_KEYS = {
    "/Launch",
    "/EmbeddedFiles",
    "/XFA",
    "/RichMedia",
    "/Movie",
    "/Sound",
    "/Rendition",
    "/3D",
    "/U3D",
    "/PRC",
}
_EXTERNAL_ANNOTATIONS = {"/FileAttachment", "/3D", "/U3D", "/PRC"}
VISUAL_LURE_SUBTYPES = {"/Link", "/Widget"}
IMAGE_LURE_MIN_AREA = 2500.0
VECTOR_LURE_MIN_AREA = 10000.0
_JBIG2_FILTERS = {"/JBIG2Decode", "/JB2"}
_JBIG2_MAGIC = b"\x97JB2\r\n\x1a\n"
_IMAGE_CODEC_FILTERS = {**dict.fromkeys(_JBIG2_FILTERS, "JBIG2"), "/JPXDecode": "JPX", "/DCTDecode": "JPEG"}
_SFNT_SIGNATURES = {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}
_SWF_SIGNATURES = (b"FWS", b"CWS", b"ZWS")
_CRITICAL_FONT_REASONS = frozenset(
    {"font_directory_truncated", "font_table_bounds_invalid", "font_table_overlap", "font_duplicate_table"}
)
_CODEC_OBJECT_LIMIT = 10_000
_ACTION_CONTAINER_LIMIT = 50_000
_PDF_CONTAINERS = (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)
_NON_ACTION_RESOURCE_KEYS = {"/Font", "/ColorSpace", "/ExtGState", "/Pattern", "/Shading", "/ProcSet", "/Properties"}
_AUDITED_STREAM_TOKENS = (
    "obj",
    "stream",
    "JS",
    "JavaScript",
    "AA",
    "OpenAction",
    "AcroForm",
    "Acroform",
    "URI",
    "XFA",
    "Launch",
    "EmbeddedFile",
)
_TYPE1_REASONS = {"type1_segment_header_invalid", "type1_segment_truncated", "type1_end_marker_missing"}
_WOFF_REASONS = {"woff_header_invalid", "woff_directory_truncated", "woff_table_bounds_invalid", "woff_table_overlap"}


def normalize_pdf_hex_names(raw_bytes: bytes) -> tuple[bytes, int]:
    decoded = 0

    def decode_escape(match: re.Match[bytes]) -> bytes:
        value = int(match[1], 16)
        return bytes([value]) if 0x21 <= value <= 0x7E else match[0]

    def decode_name(match: re.Match[bytes]) -> bytes:
        nonlocal decoded
        raw_name = match[0]
        # ASCII indicator names cannot contain raw binary bytes from a compressed stream.
        if any(byte < 0x21 or byte > 0x7E for byte in raw_name):
            return raw_name
        name = _HEX_ESCAPE.sub(decode_escape, raw_name)
        decoded += name != raw_name
        return name

    return _PDF_NAME.sub(decode_name, raw_bytes), decoded


def _stream_filters(value: Any) -> list[str]:
    if isinstance(value, IndirectObject):
        value = value.get_object()
    if isinstance(value, (pikepdf.Array, ArrayObject)):
        return [str(item.get_object() if isinstance(item, IndirectObject) else item) for item in value]
    return [str(value)] if value is not None else []


def _decode_script_bytes(data: bytes) -> str:
    return data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")


def _pypdf_script_text(value: Any) -> str | None:
    if isinstance(value, TextStringObject):
        return str(value)
    if not isinstance(value, (StreamObject, bytes)):
        return None
    try:
        if isinstance(value, bytes):
            return _decode_script_bytes(value)
        if not _JBIG2_FILTERS.intersection(_stream_filters(value.get("/Filter"))):
            return _decode_script_bytes(value.get_data())
    except (pypdf.errors.PyPdfError, ValueError, TypeError):
        pass
    return None


def _bounded_stream_bytes(
    stream: pikepdf.Stream,
    filters: list[str],
    budget: DecodeBudget,
    *,
    allow_flate_padding: bool = False,
    raw: bytes | None = None,
    limits: FilterLimits = _STATIC_FILTER_LIMITS,
) -> tuple[bytes | None, list[str]]:
    if int(stream.get("/Length") or 0) > limits.max_input_bytes or not budget.remaining:
        return None, ["decoded_byte_or_expansion_limit"]
    if raw is None:
        raw = stream.read_raw_bytes()
    if len(raw) > limits.max_input_bytes:
        return None, ["decoded_byte_or_expansion_limit"]
    result = decode_filters(
        raw,
        filters,
        decode_parms=_stream_decode_parms(stream, filters),
        limits=limits,
        budget=budget,
        recover_trailing=allow_flate_padding,
    )
    reasons = result.metadata["reason_codes"]
    if result.trailing_spans:
        if any(suffix.strip(b" \t\r\n\v\f") for _, suffix in result.trailing_spans):
            return None, ["trailing_flate_data", *reasons]
        reasons = [reason for reason in reasons if reason != "filter_trailing_data_preserved"]
    return result.data, reasons


def _stream_decode_parms(stream: Any, filters: list[str]) -> Any:
    if not filters:
        return None

    def as_dict(item: Any) -> dict | None:
        if isinstance(item, DictionaryObject):
            return {key: int(value) if isinstance(value, NumberObject) else value for key, value in item.items()}
        return dict(item) if isinstance(item, pikepdf.Dictionary) else None

    parms = _resolve_pdf_object(stream.get("/DecodeParms"))
    if isinstance(parms, (pikepdf.Array, ArrayObject)):
        return [as_dict(_resolve_pdf_object(item)) for item in islice(parms, len(filters))]
    if isinstance(parms, (pikepdf.Dictionary, DictionaryObject)):
        return as_dict(parms)
    return None if isinstance(parms, NullObject) else parms


def _flate_prefix_and_length(
    raw: bytes, budget: DecodeBudget, *, prefix_cap: int, cap: int
) -> tuple[bytes | None, int | None, list[str]]:
    decoder = zlib.decompressobj()
    prefix = bytearray()
    total = 0
    try:
        for start in range(0, len(raw), 16 * 1024):
            chunk = raw[start : start + 16 * 1024]
            decoded = decoder.decompress(chunk, cap - total + 1)
            total += len(decoded)
            budget.remaining = max(0, budget.remaining - len(decoded))
            if decoder.unconsumed_tail or total > cap:
                return None, None, ["decoded_byte_or_expansion_limit"]
            if len(prefix) < prefix_cap:
                prefix.extend(decoded[: prefix_cap - len(prefix)])
            if decoder.eof:
                whitespace = b" \t\r\n\v\f"
                if decoder.unused_data.strip(whitespace) or raw[start + len(chunk) :].strip(whitespace):
                    return None, None, ["trailing_flate_data"]
                return bytes(prefix), total, []
    except zlib.error:
        return None, None, ["invalid_flate_stream"]
    return None, None, ["truncated_flate_stream"]


def _decode_sfnt_prefix_and_length(
    raw: bytes,
    wrappers: list[str],
    budget: DecodeBudget,
    *,
    prefix_cap: int = 65536,
    stream_cap: int = 32 * 1024**2,
    max_ratio: int = 500,
) -> tuple[bytes | None, int | None, list[str]]:
    cap = min(budget.remaining, stream_cap, max(len(raw), 1) * max_ratio)
    if not wrappers:
        if len(raw) > cap:
            return None, None, ["decoded_byte_or_expansion_limit"]
        budget.remaining -= len(raw)
        return raw[:prefix_cap], len(raw), []
    if wrappers in (["/FlateDecode"], ["/Fl"]):
        return _flate_prefix_and_length(raw, budget, prefix_cap=prefix_cap, cap=cap)
    decoded = decode_filters(raw, wrappers, limits=_CODEC_FILTER_LIMITS, budget=budget)
    if decoded.data is None:
        return None, None, decoded.metadata["reason_codes"]
    return decoded.data[:prefix_cap], len(decoded.data), decoded.metadata["reason_codes"]


def _codec_reasons(inspect, body: bytes, *, include_unsupported: bool = False) -> list[str]:
    try:
        return inspect(body)["reason_codes"]
    except MediaIssue as exc:
        if exc.status == "unsupported" and not include_unsupported:
            return []
        return exc.details.get("reason_codes") or [exc.code]


def _font_anomaly_reasons(body: bytes, key: str, subtype: str, *, measured_length: int | None = None) -> list[str]:
    signature = body[:4]
    if key == "/FontFile":
        return sorted(_TYPE1_REASONS.intersection(_codec_reasons(inspect_type1, body)))
    if key == "/FontFile3" and signature in {b"wOFF", b"wOF2"}:
        inspect = partial(inspect_woff, budget=DecodeBudget(_STATIC_BYTE_LIMIT), max_expansion_ratio=20)
        return sorted(_WOFF_REASONS.intersection(_codec_reasons(inspect, body)))
    if signature in _SFNT_SIGNATURES:
        inspect = partial(inspect_font, inspect_table_data=False, measured_length=measured_length)
        return sorted(_CRITICAL_FONT_REASONS.intersection(_codec_reasons(inspect, body)))
    if key == "/FontFile2":
        if signature == b"ttcf":
            return ["font_directory_truncated"] if len(body) < 12 else []
        return ["fontfile2_signature_invalid"] if body else []
    if subtype in {"/Type1C", "/CIDFontType0C"}:
        if body.startswith(b"\x02"):
            return ["cff2_header_invalid"] if len(body) < 5 or not 5 <= body[2] <= len(body) else []
        if len(body) <= 4:
            invalid = len(body) < 4 or body[0] != 1 or body[2] != 4 or not 1 <= body[3] <= 4
            return ["cff_header_invalid"] if invalid else []
        return [
            "cff_header_invalid" if code == "cff_header_unsupported" else code
            for code in _codec_reasons(inspect_cff, body, include_unsupported=True)
        ]
    return []


def _inspect_icc_profile(body: bytes) -> list[str]:
    if len(body) < 132 or body[36:40] != b"acsp" or int.from_bytes(body[:4], "big") < 128:
        return ["icc_header_invalid"]
    tag_count = int.from_bytes(body[128:132], "big")
    table_end = 132 + tag_count * 12
    if tag_count > 2048 or table_end > len(body):
        return ["icc_tag_table_truncated"]
    for entry in range(132, table_end, 12):
        offset = int.from_bytes(body[entry + 4 : entry + 8], "big")
        size = int.from_bytes(body[entry + 8 : entry + 12], "big")
        if offset < table_end or offset + size > len(body):
            return ["icc_tag_bounds_invalid"]
    return []


def _invalid_ccitt_parameters(stream: pikepdf.Stream, index: int) -> bool:
    parms = stream.get("/DecodeParms")
    if isinstance(parms, pikepdf.Array):
        parms = parms[index] if index < len(parms) else None
    if not isinstance(parms, pikepdf.Dictionary):
        return False
    cols, rows, k = parms.get("/Columns", 1728), parms.get("/Rows", 0), parms.get("/K", 0)
    return any(type(value) is not int for value in (cols, rows, k)) or cols <= 0 or rows < 0 or not -1 <= k <= 1000000


def _inspect_swf(body: bytes) -> list[str]:
    def inspect(data: bytes) -> dict[str, Any]:
        result = inspect_flash(data, budget=DecodeBudget(_STATIC_BYTE_LIMIT), max_expansion_ratio=20)
        if result.get("script_tag_count", 0):
            result["reason_codes"].append("flash_script_embedded")
        return result

    return _codec_reasons(inspect, body, include_unsupported=True)


def _might_decode_to_swf(stream: pikepdf.Stream, raw: bytes, filters: list[str]) -> bool:
    if filters not in (["/FlateDecode"], ["/Fl"]):
        return True
    parms = stream.get("/DecodeParms")
    if isinstance(parms, pikepdf.Array):
        parms = parms[0] if len(parms) else None
    try:
        parameters = _parameters("/FlateDecode", dict(parms) if isinstance(parms, pikepdf.Dictionary) else None)
        predictor = parameters.get("/Predictor", 1)
        prefix_size = 3
        if predictor != 1:
            row_bits = (
                parameters.get("/Columns", 1) * parameters.get("/Colors", 1) * parameters.get("/BitsPerComponent", 8)
            )
            row_bytes = (row_bits + 7) // 8
            rows = (3 + row_bytes - 1) // row_bytes
            prefix_size = rows * (row_bytes + (predictor >= 10))
            if prefix_size > 64 * 1024:
                return True
        prefix = zlib.decompressobj().decompress(raw, prefix_size)
        return _predict(prefix, parameters, prefix_size).startswith(_SWF_SIGNATURES)
    except (zlib.error, _Stopped):
        return False


def inspect_pdf_codec_anomalies(
    pdf: pikepdf.Pdf,
    *,
    has_jbig2_magic: bool = False,
    uninspected_out: list[dict[str, Any]] | None = None,
    doc_budget: DecodeBudget | None = None,
) -> list[dict[str, Any]]:
    anomalies, _ = _inspect_pdf_codecs(pdf, has_jbig2_magic, uninspected_out, doc_budget)
    return anomalies


def _inspect_pdf_codecs(
    pdf: pikepdf.Pdf,
    has_jbig2_magic: bool,
    uninspected_out: list[dict[str, Any]] | None,
    doc_budget: DecodeBudget | None,
) -> tuple[list[dict[str, Any]], set[tuple[int, int]]]:
    budget = doc_budget if doc_budget is not None else DecodeBudget(_CODEC_DOC_BUDGET_BYTES)
    anomalies = []
    font_streams: dict[tuple[int, int], tuple[str, pikepdf.Stream]] = {}
    icc_streams: dict[tuple[int, int], pikepdf.Stream] = {}
    seen_streams: set[tuple[tuple[int, int], str, str, tuple[str, ...]]] = set()
    clean_streams: set[tuple[int, int]] = set()
    failed_streams: set[tuple[int, int]] = set()
    flash_candidates = []
    direct_objects = []

    def record_anomaly(stream: pikepdf.Stream, codec: str, filter_name: str, stream_size: int | None, reasons) -> None:
        if not reasons:
            return
        object_number, generation = stream.objgen
        failed_streams.add((object_number, generation))
        finding = {
            "object_number": object_number,
            "generation": generation,
            "codec": codec,
            "filter": filter_name,
            "stream_size": stream_size,
            "reason_codes": reasons,
        }
        if is_quota_only_codec_reasons(reasons):
            if uninspected_out is not None:
                uninspected_out.append(finding)
        else:
            anomalies.append({**finding, "stream": stream})

    def inspect_stream(stream: pikepdf.Stream, codec: str, codec_filter: str, wrappers: list[str]) -> None:
        identity = (stream.objgen, codec, codec_filter, tuple(wrappers))
        if identity in seen_streams:
            return
        seen_streams.add(identity)
        stream_size = None
        measured_len = None
        try:
            stream_size = int(stream.get("/Length") or 0)
            if stream_size > _CODEC_FILTER_LIMITS.max_input_bytes or not budget.remaining:
                record_anomaly(stream, codec, codec_filter, stream_size, ["decoded_byte_or_expansion_limit"])
                return
            raw = stream.read_raw_bytes()
            if codec_filter == "Uncompressed" and not raw.startswith(_JBIG2_MAGIC):
                return
            if len(raw) > _CODEC_FILTER_LIMITS.max_input_bytes:
                record_anomaly(stream, codec, codec_filter, stream_size, ["decoded_byte_or_expansion_limit"])
                return
            use_sfnt_prefix = False
            if codec_filter == "/FontFile2" and wrappers in ([], ["/FlateDecode"], ["/Fl"]):
                parms = _stream_decode_parms(stream, wrappers)
                if isinstance(parms, list) and len(parms) == 1:
                    parms = parms[0]
                use_sfnt_prefix = parms is None or isinstance(parms, dict) and "/Predictor" not in parms
                if use_sfnt_prefix and wrappers:
                    _parameters("/FlateDecode", parms)
            if use_sfnt_prefix:
                body, measured_len, reasons = _decode_sfnt_prefix_and_length(raw, wrappers, budget)
            else:
                body, reasons = _bounded_stream_bytes(
                    stream, wrappers, budget, allow_flate_padding=codec == "ICC", raw=raw, limits=_CODEC_FILTER_LIMITS
                )
        except _Stopped as exc:
            body, reasons = None, [exc.code]
        except (pikepdf.PdfError, ValueError, TypeError, OverflowError):
            if codec_filter == "Uncompressed":
                return
            body, reasons = None, ["stream_decode_failed"]
        if body is not None and not reasons:
            if codec == "JBIG2":
                reasons = _codec_reasons(jbig2_structure, body, include_unsupported=True)
            elif codec == "JPX":
                reasons = _codec_reasons(jpx_structure, body)
            elif codec == "JPEG":
                reasons = [code for code in _codec_reasons(jpeg_structure, body) if code != "image_trailing_data"]
            elif codec == "ICC":
                reasons = _inspect_icc_profile(body)
            else:
                subtype = str(stream.get("/Subtype") or "")
                reasons = _font_anomaly_reasons(body, codec_filter, subtype, measured_length=measured_len)
            if not reasons:
                clean_streams.add(stream.objgen)
        record_anomaly(stream, codec, codec_filter, stream_size, reasons)

    for obj in islice(pdf.objects, _CODEC_OBJECT_LIMIT):
        if isinstance(obj, pikepdf.Stream):
            filters = _stream_filters(obj.get("/Filter"))
            inspected_image = False
            for index, name in enumerate(filters):
                if name == "/CCITTFaxDecode":
                    if _invalid_ccitt_parameters(obj, index):
                        record_anomaly(obj, "CCITT", name, obj.get("/Length"), ["ccitt_decode_parms_invalid"])
                    inspected_image = True
                elif name in _IMAGE_CODEC_FILTERS and not inspected_image:
                    inspect_stream(obj, _IMAGE_CODEC_FILTERS[name], name, filters[:index])
                    inspected_image = True
            if not inspected_image:
                if has_jbig2_magic and not filters:
                    inspect_stream(obj, "JBIG2", "Uncompressed", [])
                flash_candidates.append((obj, filters))
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            direct_objects.extend(
                value
                for value in obj.values()
                if isinstance(value, (pikepdf.Array, pikepdf.Dictionary)) and not value.is_indirect
            )
        elif isinstance(obj, pikepdf.Array):
            direct_objects.append(obj)
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        for descriptor in (obj, obj.get("/FontDescriptor")):
            if not isinstance(descriptor, pikepdf.Dictionary):
                continue
            for key in ("/FontFile", "/FontFile2", "/FontFile3"):
                stream = descriptor.get(key)
                if isinstance(stream, pikepdf.Stream):
                    identity = stream.objgen
                    if identity not in font_streams or key == "/FontFile2":
                        font_streams[identity] = (key, stream)
    for key, stream in font_streams.values():
        inspect_stream(stream, "FONT", key, _stream_filters(stream.get("/Filter")))
    for _ in range(_CODEC_OBJECT_LIMIT):
        if not direct_objects:
            break
        value = direct_objects.pop()
        if isinstance(value, pikepdf.Array):
            if len(value) >= 2 and value[0] == pikepdf.Name.ICCBased and isinstance(value[1], pikepdf.Stream):
                icc_streams[value[1].objgen] = value[1]
            children = value
        else:
            children = value.values()
        direct_objects.extend(
            child
            for child in children
            if isinstance(child, (pikepdf.Array, pikepdf.Dictionary)) and not child.is_indirect
        )
    for stream in icc_streams.values():
        inspect_stream(stream, "ICC", "/ICCBased", _stream_filters(stream.get("/Filter")))

    flash_allowance = min(budget.remaining, _STATIC_BYTE_LIMIT)
    flash_budget = DecodeBudget(flash_allowance)
    flash_candidates.sort(key=lambda candidate: candidate[0].get("/Type") != pikepdf.Name.EmbeddedFile)
    for stream, filters in flash_candidates:
        if not flash_budget.remaining:
            break
        if stream.objgen in font_streams or stream.objgen in icc_streams:
            continue
        try:
            size = int(stream.get("/Length") or 0)
            if size < 3 or size > flash_budget.remaining:
                continue
            raw = stream.read_raw_bytes()
            if len(raw) > flash_budget.remaining:
                continue
            if raw.startswith(_SWF_SIGNATURES):
                body = raw
                flash_budget.remaining -= len(raw)
            elif filters and _might_decode_to_swf(stream, raw, filters):
                body, _ = _bounded_stream_bytes(stream, filters, flash_budget, raw=raw)
            else:
                flash_budget.remaining -= len(raw)
                continue
        except (pikepdf.PdfError, ValueError, TypeError, OverflowError):
            continue
        if body and body.startswith(_SWF_SIGNATURES):
            record_anomaly(stream, "SWF", "/SWF", size, _inspect_swf(body))
    budget.remaining -= flash_allowance - flash_budget.remaining
    return anomalies, clean_streams - failed_streams


def _recover_hidden_evasion_tokens(data: bytes, base_tokens: dict[str, int]) -> tuple[dict[str, int], dict[str, Any]]:
    audit = {
        "hex_escaped_names_decoded": 0,
        "objstm_streams_unpacked": 0,
        "objstm_decoded_bytes": 0,
        "objstm_unpack_complete": True,
        "recovered_hidden_triggers": [],
    }
    has_objstm = b"/ObjStm" in data
    if not has_objstm and not _PDF_NAME.search(data):
        return base_tokens, audit
    normalized, audit["hex_escaped_names_decoded"] = normalize_pdf_hex_names(data)
    counts = _scan_scanner_raw_tokens(normalized)
    if has_objstm or b"/ObjStm" in normalized:
        budget = DecodeBudget(_STATIC_BYTE_LIMIT)
        try:
            with pikepdf.open(io.BytesIO(data)) as pdf:
                attempted = 0
                for obj in pdf.objects:
                    if not isinstance(obj, pikepdf.Stream) or obj.get("/Type") != pikepdf.Name.ObjStm:
                        continue
                    attempted += 1
                    if attempted > 64 or not budget.remaining:
                        audit["objstm_unpack_complete"] = False
                        break
                    filters = _stream_filters(obj.get("/Filter"))
                    try:
                        raw_obj = obj.read_raw_bytes()
                        body, _ = _bounded_stream_bytes(obj, filters, budget, raw=raw_obj)
                    except (pikepdf.PdfError, ValueError, TypeError):
                        audit["objstm_unpack_complete"] = False
                        continue
                    if body is None:
                        audit["objstm_unpack_complete"] = False
                        continue
                    audit["objstm_streams_unpacked"] += 1
                    audit["objstm_decoded_bytes"] += len(body)
                    norm_raw, _ = normalize_pdf_hex_names(raw_obj)
                    already = _scan_scanner_raw_tokens(norm_raw)
                    body, decoded = normalize_pdf_hex_names(body)
                    audit["hex_escaped_names_decoded"] += decoded
                    unpacked = _scan_scanner_raw_tokens(body)
                    for key in _RECOVERABLE_TOKENS:
                        counts[key] = max(0, counts[key] + unpacked[key] - already[key])
        except pikepdf.PdfError:
            audit["objstm_unpack_complete"] = False
    merged = base_tokens.copy()
    for key in sorted(_RECOVERABLE_TOKENS):
        if counts[key] > base_tokens.get(key, 0):
            merged[key] = counts[key]
            audit["recovered_hidden_triggers"].append(key)
    return merged, audit


def annotation_rect_area(rect: Any) -> float:
    if not isinstance(rect, (ArrayObject, pikepdf.Array)) or len(rect) != 4:
        return 0.0
    try:
        x0, y0, x1, y1 = (float(value) for value in rect)
        area = abs(x1 - x0) * abs(y1 - y0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return area if math.isfinite(area) else 0.0


def page_box_area(page: Any) -> float:
    if not isinstance(page, (DictionaryObject, pikepdf.Dictionary)):
        return 0.0
    for key in ("/CropBox", "/MediaBox"):
        if key in page:
            return annotation_rect_area(_resolve_pdf_object(page.get(key)))
    for _ in range(8):
        page = _resolve_pdf_object(page.get("/Parent"))
        if not isinstance(page, (DictionaryObject, pikepdf.Dictionary)):
            break
        if "/MediaBox" in page:
            return annotation_rect_area(_resolve_pdf_object(page.get("/MediaBox")))
    return 0.0


def inspect_polyglot_and_revisions(
    data: bytes, header_pos: int | None = None, last_eof: int | None = None
) -> dict[str, Any]:
    window = 64 * 1024
    if header_pos is None:
        header_pos = data.find(b"%PDF-")
    if last_eof is None:
        last_eof = data.rfind(b"%%EOF")

    def signatures(chunk: bytes) -> list[str]:
        chunk = chunk.lstrip(b" \t\r\n\v\f\0")
        found = [
            name
            for magic, name in (
                (b"\x7fELF", "elf"),
                (b"PK\x03\x04", "zip"),
                (b"Rar!\x1a\x07", "rar"),
                (b"7z\xbc\xaf\x27\x1c", "7z"),
            )
            if chunk.startswith(magic)
        ]
        if chunk.startswith(b"MZ"):
            pe_offset = int.from_bytes(chunk[60:64], "little")
            if chunk[pe_offset : pe_offset + 4] == b"PE\0\0" or any(
                marker in chunk[:4096] for marker in (b"PE\0\0", b"This program")
            ):
                found.append("pe")
        lower = chunk.lower()
        for markers, name in (
            ((b"<!doctype html", b"<html", b"<script"), "html_script"),
            ((b"<?php",), "php"),
            ((b"#!/",), "shebang"),
        ):
            if any(marker in lower for marker in markers):
                found.append(name)
        return found

    prefix = signatures(data[: min(header_pos, window)]) if header_pos > 0 else []
    suffix = signatures(data[last_eof + 5 : last_eof + 5 + window]) if last_eof >= 0 else []
    return {
        "has_polyglot_payload": bool(prefix or suffix),
        "prefix_signatures": prefix,
        "suffix_signatures": suffix,
        "incremental_eof_count": data.count(b"%%EOF"),
        "anomalies": [
            f"polyglot_{location}_{name}"
            for location, names in (("prefix", prefix), ("suffix", suffix))
            for name in names
        ],
    }


_DISALLOWED_NAV_KEYS = ("/Next", "/JS", "/JavaScript", "/URI", "/F", "/UF", "/Launch", "/AA")
_BENIGN_NAMED_ACTIONS = frozenset({"/FirstPage", "/PrevPage", "/NextPage", "/LastPage"})


def is_navigation_destination(value: Any) -> bool:
    dictionaries = (DictionaryObject, pikepdf.Dictionary)
    arrays = (ArrayObject, pikepdf.Array)
    value = _resolve_pdf_object(value)
    if isinstance(value, dictionaries):
        if str(value.get("/S", "")) != "/GoTo" or "/D" not in value:
            return False
        if any(key in value for key in _DISALLOWED_NAV_KEYS):
            return False
        value = _resolve_pdf_object(value["/D"])
        if isinstance(value, (pikepdf.Name, pikepdf.String, NameObject, TextStringObject)):
            return True
    if not isinstance(value, arrays) or len(value) < 2:
        return False
    page = _resolve_pdf_object(value[0])
    return (
        isinstance(page, dictionaries)
        and str(page.get("/Type", "")) == "/Page"
        and isinstance(value[1], (pikepdf.Name, NameObject))
        and all(
            not isinstance(_resolve_pdf_object(item), (*dictionaries, *arrays, pikepdf.Stream))
            for item in list(value)[1:]
        )
    )


def is_benign_catalog_navigation(value: Any) -> bool:
    if is_navigation_destination(value):
        return True
    resolved = _resolve_pdf_object(value)
    return (
        isinstance(resolved, (DictionaryObject, pikepdf.Dictionary))
        and str(resolved.get("/S", "")) == "/Named"
        and str(_resolve_pdf_object(resolved.get("/N", ""))) in _BENIGN_NAMED_ACTIONS
        and not any(key in resolved for key in (*_DISALLOWED_NAV_KEYS, "/D"))
    )


def is_benign_catalog_aa(value: Any) -> bool:
    resolved = _resolve_pdf_object(value)
    return isinstance(resolved, (DictionaryObject, pikepdf.Dictionary)) and all(
        is_benign_catalog_navigation(entry) for entry in resolved.values()
    )


def _catalog_trigger_keys(root: Any) -> set[str]:
    keys = set()
    for name in ("/OpenAction", "/AA", "/Names/JavaScript", "/AcroForm/XFA"):
        value = root
        for key in name[1:].split("/"):
            if not isinstance(value, (DictionaryObject, pikepdf.Dictionary)):
                break
            value = _resolve_pdf_object(value.get("/" + key))
        else:
            if (
                value is not None
                and not isinstance(value, NullObject)
                and not (name == "/OpenAction" and is_benign_catalog_navigation(value))
                and not (name == "/AA" and is_benign_catalog_aa(value))
            ):
                keys.add(name)
    return keys


_REVISION_OBJECT = re.compile(rb"\b(\d{1,12})\s+(\d{1,8})\s+obj\b")
_REVISION_TRIGGER = re.compile(
    rb"/(?:JS|JavaScript|OpenAction|AA|Launch|GoToR|XFA|EmbeddedFiles)"
    rb"(?=[\s/<>()\[\]%]|$)(?!\s+null\b)"
)
_REVISION_OBJECT_END = re.compile(rb"(?m)^[ \t]*stream\b|(?<![^\s>])endobj\b")
_REVISION_LITERAL = re.compile(rb"\((?:\\[\s\S]|[^\\()])*\)|(?<!<)<[0-9a-fA-F\s]*>|%[^\r\n]*")
_REVISION_LIMIT = 512 * 1024
_BENIGN_SHADOWABLE = {b"/OpenAction", b"/AA"}


def _revision_trigger_updates(data: bytes, mismatch: bool) -> tuple[list[str], list[str]]:
    anomalies = []
    shadowed = []
    base_end = data.find(b"%%EOF")
    base_tokens: set[bytes] = set()
    object_tokens: dict[tuple[bytes, bytes], set[bytes]] = {}
    start = 0
    end = base_end
    for revision in range(6):
        if end < 0:
            break
        chunk = data[start : min(end, start + _REVISION_LIMIT)]
        added_tokens: set[bytes] = set()
        removed_tokens: set[bytes] = set()
        objects = list(_REVISION_OBJECT.finditer(chunk))
        for index, match in enumerate(objects):
            next_offset = objects[index + 1].start() if index + 1 < len(objects) else len(chunk)
            boundary = _REVISION_OBJECT_END.search(chunk, match.end(), next_offset)
            if boundary is None:
                continue
            header = _REVISION_LITERAL.sub(b" ", chunk[match.end() : boundary.start()])
            current = set(_REVISION_TRIGGER.findall(header))
            identity = match.groups()
            previous = object_tokens.pop(identity, set())
            if current:
                object_tokens[identity] = current
            if revision == 0:
                base_tokens.update(current)
                continue
            removed = previous - current
            if removed:
                removed_tokens.update(removed)
                if len(shadowed) < 32:
                    label = b" ".join(identity).decode("ascii")
                    shadowed.append(f"{label} R: " + ", ".join(token.decode("ascii") for token in sorted(removed)))
            added_tokens.update(current - base_tokens)
        shadowed_here = bool(removed_tokens - _BENIGN_SHADOWABLE) or (
            bool(removed_tokens) and (bool(added_tokens) or mismatch)
        )
        if shadowed_here and "incremental_shadow_trigger_update" not in anomalies:
            anomalies.append("incremental_shadow_trigger_update")
        if added_tokens and (mismatch or shadowed_here) and "incremental_hidden_trigger_revision" not in anomalies:
            anomalies.append("incremental_hidden_trigger_revision")
        start = end + len(b"%%EOF")
        end = data.find(b"%%EOF", start)
    return anomalies, shadowed


def _differential_summary() -> dict[str, Any]:
    return {
        "has_differential_evasion": False,
        "pypdf_pages": 0,
        "pikepdf_pages": 0,
        "anomalies": [],
        "shadowed_triggers": [],
    }


def inspect_parser_differential(
    data: bytes, reader: PdfReader, pdf: pikepdf.Pdf, incremental_eof_count: int
) -> dict[str, Any]:
    result = _differential_summary()
    result.update(pypdf_pages=len(reader.pages), pikepdf_pages=len(pdf.pages))
    anomalies = result["anomalies"]
    if result["pypdf_pages"] != result["pikepdf_pages"]:
        anomalies.append("parser_page_count_mismatch")
    if _catalog_trigger_keys(reader.trailer["/Root"]) != _catalog_trigger_keys(pdf.Root):
        anomalies.append("parser_trigger_visibility_mismatch")
    if incremental_eof_count >= 2:
        revision_anomalies, shadowed = _revision_trigger_updates(data, bool(anomalies))
        anomalies.extend(revision_anomalies)
        result["shadowed_triggers"] = shadowed
    result["has_differential_evasion"] = bool(anomalies)
    return result


def _uri_evidence(
    uri: str,
    evidence_id: str,
    invoker: str,
    page_index: int | None = None,
    rect_area: float = 0.0,
    page_area: float = 0.0,
) -> dict[str, Any] | None:
    if not uri.strip():
        return None
    suspicious, reasons = is_suspicious_uri(uri)
    return {
        "uri": uri,
        "evidence_id": evidence_id,
        "invoker": invoker,
        "page_index": page_index,
        "rect_area": rect_area,
        "page_area": page_area,
        "is_suspicious": suspicious,
        "reasons": reasons,
    }


_LURE_TEXT_LIMIT = 128 * 1024
_LURE_FILTER_LIMITS = FilterLimits(
    max_input_bytes=_LURE_TEXT_LIMIT,
    max_stage_bytes=_LURE_TEXT_LIMIT,
    max_total_bytes=_LURE_TEXT_LIMIT,
)


def _page_lure_text(page: Any, budget: DecodeBudget) -> str | None:
    contents = page.get("/Contents")
    if contents is None:
        return ""
    contents = contents.get_object()
    streams = contents if isinstance(contents, ArrayObject) else [contents]
    bodies = []
    for stream_ref in streams:
        stream = stream_ref.get_object()
        raw = getattr(stream, "_data", None)
        if not isinstance(raw, bytes) or len(raw) > budget.remaining:
            return None
        filters = _stream_filters(stream.get("/Filter"))
        decoded = decode_filters(raw, filters, limits=_LURE_FILTER_LIMITS, budget=budget)
        if decoded.data is None:
            return None
        bodies.append(decoded.data)
    page_snapshot = copy(page)
    decoded_contents = DecodedStreamObject()
    decoded_contents.set_data(b"\n".join(bodies))
    text_content = ContentStream(decoded_contents, page.pdf, "bytes")
    text_content.operations = [(args, op) for args, op in text_content.operations if op != b"Do"]
    page_snapshot[NameObject("/Contents")] = text_content
    return page_snapshot.extract_text()


def _resolve_pdf_object(value: Any) -> Any:
    return value.get_object() if isinstance(value, IndirectObject) else value


def page_has_vector_overlay_surface(page: Any) -> bool:
    contents = _resolve_pdf_object(page.get("/Contents"))
    streams = contents if isinstance(contents, (ArrayObject, pikepdf.Array)) else (contents,)
    budget = DecodeBudget(_LURE_TEXT_LIMIT)
    for ref in islice(iter(streams), 64):
        stream = _resolve_pdf_object(ref)
        try:
            if isinstance(stream, pikepdf.Stream):
                body, _ = _bounded_stream_bytes(stream, _stream_filters(stream.get("/Filter")), budget)
            elif isinstance(stream, StreamObject):
                body = decode_filters(
                    stream._data, _stream_filters(stream.get("/Filter")), limits=_LURE_FILTER_LIMITS, budget=budget
                ).data
            else:
                continue
        except (pikepdf.PdfError, pypdf.errors.PyPdfError, ValueError, TypeError, OverflowError):
            continue
        if body:
            return True
    return False


def visual_lure_kind(
    page: Any,
    page_text: str | None,
    *,
    pages_count: int,
    page_area: float,
    rect_area: float,
    uri: str,
) -> str | None:
    if page_text is None or rect_area < IMAGE_LURE_MIN_AREA or not is_untrusted_http_uri(uri):
        return None
    text_chars = len(page_text.strip())
    if pages_count <= 2 and text_chars < 40:
        if page_has_image_xobject(page):
            return "image"
        if rect_area >= VECTOR_LURE_MIN_AREA and page_has_vector_overlay_surface(page):
            return "vector"
    if pages_count <= 10 and page_area >= 10000.0:
        coverage = rect_area / page_area
        if coverage >= 0.35 and (text_chars < 400 or coverage >= 0.45 and page_has_image_xobject(page)):
            return "overlay"
    return None


def lure_phrases_for_pages(texts: dict[int, str]) -> tuple[set[str], set[str]]:
    phrases: set[str] = set()
    corroborated: set[str] = set()
    for text in texts.values():
        page_phrases = phishing_lure_phrases(text)
        phrases.update(page_phrases)
        # Overlapping QR phrases describe the same cue.
        normalized = {_strip_diacritics(phrase) for phrase in page_phrases}
        independent = {
            phrase for phrase in normalized if not any(phrase != other and phrase in other for other in normalized)
        }
        if len(independent) >= 2:
            corroborated.update(page_phrases)
    return phrases, corroborated


def qr_phishing_reasons(
    uri: str, texts: dict[int, str], pages_count: int, phrases: set[str], corroborated: set[str]
) -> list[str]:
    suspicious, reasons = is_suspicious_uri(uri, lure_phrases=corroborated)
    short_document = (
        pages_count <= 2 and len(texts) == pages_count and sum(len(text.strip()) for text in texts.values()) < 200
    )
    qr_lure = any(any(cue in _strip_diacritics(phrase) for cue in ("qr", "scan", "quet")) for phrase in phrases)
    if suspicious or (short_document or qr_lure) and is_untrusted_http_uri(uri):
        reasons.append("qr_code_phishing_uri")
    return reasons


def _analyze_phishing(
    reader: PdfReader | None,
    uris: list[dict[str, Any]],
    pages_count: int,
    records: list[dict[str, Any]],
    qr_analysis: dict[str, Any],
) -> dict[str, Any]:
    qr_uris = qr_analysis["decoded_uris"]
    overlay_pages = {item["page_index"] for item in uris if item["rect_area"] >= IMAGE_LURE_MIN_AREA}
    texts = {}
    if reader is not None and (uris or qr_uris):
        texts = bounded_lure_page_text(
            reader, pages_count, overlay_pages, priority_pages=set(qr_analysis.get("qr_pages") or ())
        )
    phrases, corroborated = lure_phrases_for_pages(texts)
    image_only_lure = False
    if corroborated or overlay_pages and texts:
        records_by_id = {record["evidence_id"]: record for record in records}
        for item in uris:
            suspicious, reasons = is_suspicious_uri(item["uri"], lure_phrases=corroborated)
            index = item["page_index"]
            visual_lure = None
            if reader is not None and index in texts and item["rect_area"] >= IMAGE_LURE_MIN_AREA:
                try:
                    visual_lure = visual_lure_kind(
                        reader.pages[index],
                        texts[index],
                        pages_count=pages_count,
                        page_area=item["page_area"],
                        rect_area=item["rect_area"],
                        uri=item["uri"],
                    )
                except (pypdf.errors.PyPdfError, ValueError, TypeError):
                    pass
            if visual_lure:
                reasons.append("large_overlay_visual_lure" if visual_lure == "overlay" else "image_only_visual_lure")
                suspicious = image_only_lure = True
            if suspicious:
                item.update(is_suspicious=True, reasons=list(dict.fromkeys([*item["reasons"], *reasons])))
                record = records_by_id.get(item["evidence_id"])
                if record is not None and record["action_role"] != "remote_goto":
                    record.update(is_threat_trigger=True, action_role="suspicious_uri")
    suspicious = [item for item in uris if item["is_suspicious"]]
    for index, uri in enumerate(qr_uris):
        uri_pages = (qr_analysis.get("uri_pages") or {}).get(uri) or []
        local_texts = texts if pages_count <= 3 else {p: texts[p] for p in uri_pages if p in texts}
        local_phrases, local_corroborated = lure_phrases_for_pages(local_texts)
        reasons = qr_phishing_reasons(uri, local_texts, pages_count, local_phrases, local_corroborated)
        if reasons:
            suspicious.append(
                {
                    "uri": uri,
                    "evidence_id": f"qr:image_{index}",
                    "invoker": "/Resources/XObject",
                    "source": "qr_image",
                    "is_suspicious": True,
                    "reasons": reasons,
                }
            )
    qr_suspicious = [item for item in suspicious if item.get("source") == "qr_image"]
    qr_analysis.update(has_qr_threat=bool(qr_suspicious), suspicious_uris=qr_suspicious)
    return {
        "has_phishing_threat": bool(suspicious),
        "has_qr_phishing": bool(qr_suspicious),
        "suspicious_uris": suspicious,
        "lure_phrases": sorted(phrases),
        "image_only_lure": image_only_lure,
    }


def _open_scanner_reader(data: bytes) -> tuple[PdfReader, int]:
    reader = PdfReader(io.BytesIO(data), strict=False)
    pages = len(reader.pages)
    reader.trailer["/Root"]
    return reader, pages


def bounded_lure_page_text(
    reader: PdfReader,
    pages_count: int,
    overlay_pages: set[int],
    *,
    priority_pages: set[int] | frozenset[int] = frozenset(),
) -> dict[int, str]:
    if pages_count > 10 and not overlay_pages and not priority_pages:
        return {}
    first_pages = set(range(pages_count)) if pages_count <= 3 else set()
    indices = sorted(priority_pages) + sorted(overlay_pages - priority_pages)
    indices += sorted(first_pages - priority_pages - overlay_pages)
    budget = DecodeBudget(_LURE_TEXT_LIMIT)
    texts = {}
    for index in indices[:8]:
        if not 0 <= index < pages_count:
            continue
        try:
            text = _page_lure_text(reader.pages[index], budget)
        except (pypdf.errors.PyPdfError, ValueError, TypeError):
            continue
        if text is not None:
            texts[index] = text
    return texts


def read_lure_page_text(
    data: bytes, overlay_pages: set[int], *, priority_pages: set[int] | frozenset[int] = frozenset()
) -> dict[int, str]:
    try:
        reader, pages_count = _open_scanner_reader(data)
    except (pypdf.errors.PyPdfError, ValueError, TypeError):
        return {}
    return bounded_lure_page_text(reader, pages_count, overlay_pages, priority_pages=priority_pages)


_CATALOG_EVIDENCE = {
    "/Root/OpenAction": ("OpenAction", "action:open_action", "action"),
    "/Root/AA": ("AA", "action:aa", "action"),
    "/Root/Names/JavaScript": ("JavaScript", "script:names_js", "script"),
    "/Root/Names/EmbeddedFiles": ("EmbeddedFile", "filespec:embedded_files", "filespec"),
    "/Root/AcroForm/XFA": ("XFA", "script:acroform_xfa", "script"),
}
_FORMCALC_NETWORK_CALL = re.compile(
    rb"""\b(?:Get|Post|Put)\s*\(\s*(?:["']|&quot;|&apos;)https?://|\bxfa\s*\.\s*host\s*\.\s*gotoURL\s*\(""",
    re.IGNORECASE,
)


def _inspect_xfa_payload(xfa_obj: Any, budget: DecodeBudget) -> dict[str, Any]:
    chunks = []
    anomalies = set()
    streams = (
        (xfa_obj[index] for index in range(1, min(len(xfa_obj), 64), 2))
        if isinstance(xfa_obj, pikepdf.Array)
        else (xfa_obj,)
    )
    for index, stream in enumerate(streams):
        if not isinstance(stream, pikepdf.Stream):
            continue
        try:
            body, reasons = _bounded_stream_bytes(stream, _stream_filters(stream.get("/Filter")), budget)
        except (pikepdf.PdfError, ValueError, TypeError, OverflowError):
            body, reasons = None, ["stream_decode_failed"]
        anomalies.update(reasons)
        if body is not None:
            chunks.append((body, {"packet_index": index}))
    if isinstance(xfa_obj, pikepdf.Array) and len(xfa_obj) > 64:
        anomalies.add("xfa_packet_limit")

    scripts: list[str] = []
    xml_nodes = 0
    non_js = 0

    def count_node() -> None:
        nonlocal xml_nodes
        xml_nodes += 1

    def parse(xml_chunks) -> int:
        result = inspect_xfa_xml(
            xml_chunks,
            start_script=dict,
            finish_script=lambda _, code: scripts.append(code),
            problem=anomalies.add,
            node_observed=count_node,
            max_nodes=5000,
            max_depth=64,
            max_script_bytes=262144,
        )
        return result["non_javascript_scripts"]

    if chunks:
        try:
            non_js = parse(chunks)
        except CodeInspectionError as exc:
            reason = str(exc)
            if reason == "xfa_xml_parse_error" and len(chunks) > 1:
                if b"<!DOCTYPE" in b"".join(body for body, _ in chunks).upper():
                    anomalies.update({reason, "xfa_xml_dtd_unsupported"})
                else:
                    scripts.clear()
                    xml_nodes = 0
                    prefix = (b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">', chunks[0][1])
                    suffix = (b"</xdp:xdp>", chunks[-1][1])
                    try:
                        non_js = parse([prefix, *chunks, suffix])
                    except CodeInspectionError as wrapped_exc:
                        anomalies.add(str(wrapped_exc))
            else:
                anomalies.add(reason)
    if non_js:
        remaining = 512 * 1024
        inspected = bytearray()
        for body, _ in chunks:
            inspected.extend(body[:remaining])
            remaining -= min(len(body), remaining)
            if not remaining:
                break
        if _FORMCALC_NETWORK_CALL.search(inspected):
            anomalies.add("xfa_formcalc_network_call")
    return {
        "present": True,
        "javascript_scripts": scripts,
        "javascript_count": len(scripts),
        "formcalc_count": non_js,
        "xml_nodes": xml_nodes,
        "anomalies": sorted(anomalies),
    }


def _container_size(value: Any) -> int:
    return len(value) if isinstance(value, pikepdf.Array) else len(value.keys())


_PDF_DELIM_BYTES = frozenset(b" \t\r\n\x00\x0c()<>[]{}/%")


def _non_stream_literal_delimiters(raw_pdf_bytes: bytes, expected_streams: int) -> dict[str, int] | None:
    n = len(raw_pdf_bytes)
    i = 0
    obj_hits = 0
    stream_hits = 0
    skipped_streams = 0
    while i < n:
        ch = raw_pdf_bytes[i]
        if ch == 0x25:  # '%' comment — single forward scan to CR or LF
            j = i + 1
            while j < n and raw_pdf_bytes[j] not in (0x0A, 0x0D):
                j += 1
            seg = raw_pdf_bytes[i:j]
            if b"endobj" in seg or b"endstream" in seg:
                return None
            obj_hits += seg.count(b"obj")
            stream_hits += seg.count(b"stream")
            i = j + 1
        elif ch == 0x28:  # '(' balanced PDF literal string
            start = i + 1
            depth = 1
            i += 1
            while i < n and depth > 0:
                b = raw_pdf_bytes[i]
                if b == 0x5C:
                    i += 2
                    continue
                if b == 0x28:
                    depth += 1
                elif b == 0x29:
                    depth -= 1
                i += 1
            if depth != 0:
                return None
            seg = raw_pdf_bytes[start : i - 1]
            if b"endobj" in seg or b"endstream" in seg:
                return None
            obj_hits += seg.count(b"obj")
            stream_hits += seg.count(b"stream")
        elif (
            ch == 0x73
            and raw_pdf_bytes[i : i + 6] == b"stream"
            and (i == 0 or raw_pdf_bytes[i - 1] in _PDF_DELIM_BYTES)
            and i + 6 < n
            and raw_pdf_bytes[i + 6] in (0x0A, 0x0D, 0x20, 0x09)
        ):
            k = i + 6
            while k < n and raw_pdf_bytes[k] in (0x20, 0x09):
                k += 1
            if k >= n or raw_pdf_bytes[k] not in (0x0A, 0x0D):
                i += 6
                continue
            if raw_pdf_bytes[k : k + 2] == b"\r\n":
                k += 2
            else:
                k += 1
            end_s = raw_pdf_bytes.find(b"endstream", k)
            if end_s == -1:
                return None
            skipped_streams += 1
            i = end_s + 9
        else:
            i += 1
    if skipped_streams != expected_streams:
        return None
    return {"obj": obj_hits, "stream": stream_hits}


def _stream_interior_tokens(
    pdf: pikepdf.Pdf, raw_tokens: dict[str, int], byte_limit: int, raw_pdf_bytes: bytes | None = None
) -> dict[str, int]:
    objects = pdf.objects
    if pdf.is_encrypted or len(objects) > _CODEC_OBJECT_LIMIT:
        return {}
    streams = []
    excluded = set()
    pending = [obj for obj in objects if isinstance(obj, _PDF_CONTAINERS)]
    for _ in range(_ACTION_CONTAINER_LIMIT):
        if not pending:
            break
        value = pending.pop()
        if len(pending) > _ACTION_CONTAINER_LIMIT or _container_size(value) > _ACTION_CONTAINER_LIMIT:
            return {}
        if isinstance(value, pikepdf.Stream):
            streams.append(value)
            if value.get("/Type") == pikepdf.Name.ObjStm:
                excluded.add(value.objgen)
        if isinstance(value, pikepdf.Array):
            children = value
        else:
            for key in ("/JS", "/XFA"):
                body = value.get(key)
                if isinstance(body, pikepdf.Stream):
                    excluded.add(body.objgen)
                elif key == "/XFA" and isinstance(body, pikepdf.Array):
                    if len(body) > _ACTION_CONTAINER_LIMIT:
                        return {}
                    excluded.update(item.objgen for item in body if isinstance(item, pikepdf.Stream))
            children = value.values()
        pending.extend(child for child in children if isinstance(child, _PDF_CONTAINERS) and not child.is_indirect)
    if pending:
        return {}

    counts: dict[str, int] = {}
    max_stream = _CODEC_FILTER_LIMITS.max_input_bytes
    for stream in streams:
        if not 0 <= int(stream.get("/Length") or 0) <= max_stream:
            return {}
        raw = stream.read_raw_bytes()
        byte_limit -= len(raw)
        if byte_limit < 0 or len(raw) > max_stream or b"endstream" in raw or b"endobj" in raw:
            return {}
        if stream.objgen in excluded:
            continue
        interior = _scan_scanner_raw_tokens(raw)
        for token in _AUDITED_STREAM_TOKENS:
            if interior[token] and raw_tokens.get(token, 0):
                counts[token] = min(raw_tokens[token], counts.get(token, 0) + interior[token])
    if raw_pdf_bytes is not None:
        lit_counts = _non_stream_literal_delimiters(raw_pdf_bytes, len(streams))
        if lit_counts is None:
            return {}
        for token, extra in lit_counts.items():
            if extra and raw_tokens.get(token, 0):
                counts[token] = min(raw_tokens[token], counts.get(token, 0) + extra)
    return counts


def _is_inactive_acroform(acroform: Any) -> bool:
    if not isinstance(acroform, pikepdf.Dictionary):
        return False
    pending = [acroform]
    seen = set()
    for _ in range(_ACTION_CONTAINER_LIMIT):
        if not pending:
            return True
        value = pending.pop()
        if value.is_indirect:
            if value.objgen in seen:
                continue
            seen.add(value.objgen)
        if len(pending) > _ACTION_CONTAINER_LIMIT or _container_size(value) > _ACTION_CONTAINER_LIMIT:
            return False
        if isinstance(value, pikepdf.Array):
            children = value
        else:
            keys = value.keys()
            action = str(value.get("/S") or "")
            uri = value.get("/URI")
            if (
                (_NON_JS_KEYS | {"/JS", "/JavaScript", "/OpenAction"}).intersection(keys)
                or action == "/JavaScript"
                or action in _NON_JS_ACTIONS
                or str(value.get("/Subtype") or "") in _EXTERNAL_ANNOTATIONS
                or "/AA" in keys
                and not is_benign_catalog_aa(value["/AA"])
                or isinstance(uri, pikepdf.String)
                and is_suspicious_uri(str(uri))[0]
            ):
                return False
            children = (child for key, child in value.items() if key not in {"/Parent", "/P"})
        pending.extend(child for child in children if isinstance(child, _PDF_CONTAINERS))
    return not pending


def _inspect_additional_evidence(
    data: bytes,
    reader: PdfReader,
    original_data: bytes,
    incremental_eof_count: int,
    records: list[dict[str, Any]],
    scripts: list[dict[str, Any]],
    uris: list[dict[str, Any]],
    codec_anomalies: list[dict[str, Any]],
    xfa_analysis: dict[str, Any],
    recovered: list[str],
    register: Any,
    raw_tokens: dict[str, int],
    structural_audit: dict[str, Any],
    *,
    codec_inspection_limits: list[dict[str, Any]],
    doc_budget: DecodeBudget,
) -> tuple[set[str], dict[str, Any], dict[str, Any], int]:
    non_js: set[str] = set()
    differential = _differential_summary()
    qr_analysis = empty_qr_analysis()
    script_codes = {item["code"] for item in scripts}
    script_ids = {item["script_id"] for item in scripts}
    seen_uris = {item["uri"] for item in uris}
    inspected_uri_tokens = 0
    budget = DecodeBudget(_STATIC_BYTE_LIMIT)
    xfa_budget = DecodeBudget(_STATIC_BYTE_LIMIT)
    seen_xfa = set()
    xfa_script_index = 0
    attachment_index = 0
    gotor_index = 0
    has_jbig2_magic = _JBIG2_MAGIC in data

    def inspect_uri(value: Any, path: str, action: str) -> int:
        uri = value.get("/URI")
        if not isinstance(uri, pikepdf.String):
            return 0
        target = str(uri)
        if target not in seen_uris:
            evidence_id = f"action:uri_{len(uris)}"
            evidence = _uri_evidence(target, evidence_id, path)
            if not evidence:
                return 0
            seen_uris.add(target)
            uris.append(evidence)
            if evidence["is_suspicious"]:
                register(evidence_id, "action", value, path, action_role="suspicious_uri")
        return 1 + int(action == "/URI")

    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            known_uri_ids = {item["evidence_id"] for item in uris}
            annotations_left = 4096
            for page_index, page in enumerate(islice(pdf.pages, 2048)):
                annotations = page.obj.get("/Annots")
                if not isinstance(annotations, pikepdf.Array):
                    continue
                for index, annotation in enumerate(islice(annotations, annotations_left)):
                    evidence_id = f"action:annot_{page_index}_{index}"
                    if evidence_id in known_uri_ids or not isinstance(annotation, pikepdf.Dictionary):
                        continue
                    if str(annotation.get("/Subtype")) not in VISUAL_LURE_SUBTYPES:
                        continue
                    action_obj = annotation.get("/A")
                    uri = action_obj.get("/URI") if isinstance(action_obj, pikepdf.Dictionary) else None
                    if isinstance(uri, pikepdf.String):
                        invoker = f"/Annot[{page_index},{index}]/A"
                        evidence = _uri_evidence(
                            str(uri),
                            evidence_id,
                            invoker,
                            page_index,
                            annotation_rect_area(annotation.get("/Rect")),
                            page_box_area(page.obj),
                        )
                        if evidence:
                            seen_uris.add(evidence["uri"])
                            uris.append(evidence)
                annotations_left -= min(annotations_left, len(annotations))
                if not annotations_left:
                    break
            root = pdf.Root
            acroform = root.get("/AcroForm")
            pending = [(root, "/Root", "", 0, False)]
            if isinstance(acroform, _PDF_CONTAINERS):
                pending.append((acroform, "/Root/AcroForm", "", 0, False))
            seen_objects = set()
            for _ in range(_ACTION_CONTAINER_LIMIT):
                if not pending:
                    break
                if len(pending) > _ACTION_CONTAINER_LIMIT:
                    non_js.add("action_inspection_limit")
                    break
                value, path, parent_id, depth, in_resources = pending.pop()
                fallback = _CATALOG_EVIDENCE.get(path)
                if fallback and not isinstance(value, pikepdf.Array):
                    _, parent_id, kind = fallback
                    if fallback[0] in recovered:
                        register(parent_id, kind, value, path)
                if value.is_indirect:
                    if value.objgen in seen_objects:
                        continue
                    seen_objects.add(value.objgen)
                if depth > 128 or _container_size(value) > _ACTION_CONTAINER_LIMIT:
                    non_js.add("action_inspection_limit")
                    continue
                if isinstance(value, pikepdf.Array):
                    pending.extend(
                        (item, f"{path}[{idx}]"[:256], parent_id, 0 if item.is_indirect else depth + 1, in_resources)
                        for idx, item in enumerate(value)
                        if isinstance(item, _PDF_CONTAINERS)
                    )
                    continue
                action = str(value.get("/S") or "")
                subtype = str(value.get("/Subtype") or "")
                non_js.update(_NON_JS_KEYS.intersection(value.keys()))
                if "/Next" in value and (path == "/Root/OpenAction" or path.startswith("/Root/AA/")):
                    non_js.add("catalog_action_chain")
                if subtype in _EXTERNAL_ANNOTATIONS:
                    non_js.add(subtype)
                if subtype == "/FileAttachment":
                    filespec = value.get("/FS")
                    register(
                        f"filespec:annot_file_attachment_{attachment_index}",
                        "filespec",
                        filespec if isinstance(filespec, pikepdf.Dictionary) else value,
                        f"{path}/FS" if filespec is not None else path,
                        action_role="file_attachment",
                    )
                    attachment_index += 1
                if "/XFA" in value:
                    xfa_obj = value["/XFA"]
                    identity = getattr(xfa_obj, "objgen", (0, 0))
                    if identity == (0, 0) or identity not in seen_xfa:
                        seen_xfa.add(identity)
                        xfa_path = f"{path}/XFA"
                        xfa_id = "script:acroform_xfa"
                        register(xfa_id, "script", xfa_obj, xfa_path)
                        observed = _inspect_xfa_payload(xfa_obj, xfa_budget)
                        xfa_analysis["present"] = True
                        for key in ("javascript_count", "formcalc_count", "xml_nodes"):
                            xfa_analysis[key] += observed[key]
                        anomalies = set(observed["anomalies"])
                        xfa_analysis["anomalies"] = sorted(anomalies.union(xfa_analysis["anomalies"]))
                        if anomalies.intersection({"xfa_xml_dtd_unsupported", "xfa_reference_unsupported"}):
                            non_js.add("xfa_xml_anomaly")
                        if "xfa_formcalc_network_call" in anomalies:
                            non_js.add("xfa_formcalc_network_call")
                        if "xfa_xml_dtd_unsupported" in anomalies:
                            codec_anomalies.append(
                                {
                                    "evidence_id": xfa_id,
                                    "object_number": identity[0],
                                    "generation": identity[1],
                                    "codec": "XFA_XML",
                                    "reason_codes": ["xfa_xml_dtd_unsupported"],
                                }
                            )
                        for code in observed["javascript_scripts"]:
                            if code.strip() and code not in script_codes:
                                script_codes.add(code)
                                script_id = f"script:xfa_{xfa_script_index}"
                                xfa_script_index += 1
                                script_ids.add(script_id)
                                scripts.append({"script_id": script_id, "parent_id": xfa_id, "code": code})
                if action in _NON_JS_ACTIONS:
                    non_js.add(action)
                if action == "/GoToR":
                    evidence_id = f"action:gotor_{gotor_index}"
                    gotor_index += 1
                    register(evidence_id, "action", value, path, action_role="remote_goto")
                    for key in ("/UF", "/F"):
                        target_obj = value.get(key)
                        targets = (
                            (target_obj.get("/UF"), target_obj.get("/F"))
                            if isinstance(target_obj, pikepdf.Dictionary)
                            else (target_obj,)
                        )
                        for target in targets:
                            if isinstance(target, pikepdf.String) and is_risky_remote_target(str(target)):
                                non_js.add("gotor_unc_ntlm_risk")
                                uris.append(
                                    {
                                        "uri": str(target),
                                        "evidence_id": evidence_id,
                                        "invoker": path,
                                        "page_index": None,
                                        "rect_area": 0.0,
                                        "is_suspicious": True,
                                        "reasons": ["gotor_remote_unc_target"],
                                    }
                                )
                                break
                        else:
                            continue
                        break
                inspected_uri_tokens += inspect_uri(value, path, action)
                if "/JS" in value or action == "/JavaScript":
                    code_value = value.get("/JS")
                    code = None
                    if isinstance(code_value, pikepdf.String):
                        code = str(code_value)
                    elif isinstance(code_value, pikepdf.Stream):
                        filters = _stream_filters(code_value.get("/Filter"))
                        decoded, _ = _bounded_stream_bytes(code_value, filters, budget)
                        if decoded is not None:
                            try:
                                code = _decode_script_bytes(decoded)
                            except UnicodeDecodeError:
                                pass
                    if code is None:
                        non_js.add("javascript_body_unavailable")
                    elif code not in script_codes:
                        script_parent = parent_id or f"action:script_{len(scripts)}"
                        if not parent_id:
                            register(script_parent, "action", value, path)
                        script_id = script_parent if script_parent.startswith("script:") else f"script:{script_parent}"
                        if script_id in script_ids:
                            script_id = f"{script_id}_{len(scripts)}"
                        if not script_parent.startswith("script:"):
                            register(script_id, "script", code_value, f"{path}/JS", parent_id=script_parent)
                        script_codes.add(code)
                        script_ids.add(script_id)
                        scripts.append({"script_id": script_id, "parent_id": script_parent, "code": code})
                resource_owner = str(value.get("/Type") or "") in {"/Page", "/Pages", "/XObject"}
                pending.extend(
                    (
                        child,
                        f"{path}{key[:256]}"[:256],
                        parent_id,
                        0 if child.is_indirect else depth + 1,
                        in_resources or (resource_owner and key == "/Resources"),
                    )
                    for key, child in value.items()
                    if isinstance(child, _PDF_CONTAINERS)
                    and key != "/Parent"
                    and (path != "/Root" or key not in {"/AcroForm", "/StructTreeRoot"})
                    and (not in_resources or key not in _NON_ACTION_RESOURCE_KEYS)
                )
            if pending:
                non_js.add("action_inspection_limit")

            if "action_inspection_limit" not in non_js:
                for obj in islice(pdf.objects, _CODEC_OBJECT_LIMIT):
                    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)) and obj.objgen not in seen_objects:
                        inspected_uri_tokens += inspect_uri(obj, f"/Object[{obj.objgen[0]}]", str(obj.get("/S") or ""))
            object_limit_reached = len(pdf.objects) > _CODEC_OBJECT_LIMIT
            if object_limit_reached:
                non_js.add("codec_inspection_limit")
            stream_records = {(r["obj_num"], r["generation"]): r for r in reversed(records) if r["has_stream"]}
            findings, clean_streams = _inspect_pdf_codecs(pdf, has_jbig2_magic, codec_inspection_limits, doc_budget)
            for record in records:
                if (record["obj_num"], record["generation"]) in clean_streams:
                    record["stream_decode_failed"] = False
            if codec_inspection_limits:
                non_js.add("codec_inspection_limit")
            for anomaly in findings:
                stream = anomaly.pop("stream")
                object_number, generation = anomaly["object_number"], anomaly["generation"]
                evidence_id = f"stream:{anomaly['codec'].lower()}_{object_number}_{generation}"
                existing = stream_records.get((object_number, generation))
                if existing is not None:
                    evidence_id = existing["evidence_id"]
                    existing["is_threat_trigger"] = True
                else:
                    register(evidence_id, "stream", stream, f"/Object[{object_number}]/Filter")
                    if records and records[-1]["evidence_id"] == evidence_id:
                        records[-1].update(filter=anomaly["filter"], raw_stream_bytes=anomaly["stream_size"])
                codec_anomalies.append({"evidence_id": evidence_id, **anomaly})
            differential = inspect_parser_differential(original_data, reader, pdf, incremental_eof_count)
            if (
                not codec_anomalies
                and not object_limit_reached
                and not any(
                    record["stream_decode_failed"] or record["decompression_ratio_exceeded"] for record in records
                )
            ):
                qr_analysis = scan_pdf_qr_codes(
                    data,
                    pdf,
                    pages_count=len(pdf.pages),
                    codec_anomalies=codec_anomalies,
                    uninspected_xrefs={
                        item["object_number"] for item in codec_inspection_limits if item.get("object_number")
                    },
                )
            else:
                qr_analysis["coverage_complete"] = False
            audit: dict[str, Any] = {}
            if data is original_data:
                audit["stream_interior_tokens"] = _stream_interior_tokens(
                    pdf, raw_tokens, len(data), raw_pdf_bytes=data
                )
            if "action_inspection_limit" not in non_js:
                audit["inspected_benign_openaction_tokens"] = int(is_benign_catalog_navigation(root.get("/OpenAction")))
                audit["inspected_benign_aa_tokens"] = (
                    int(is_benign_catalog_aa(root.get("/AA")))
                    + int(isinstance(acroform, pikepdf.Dictionary) and is_benign_catalog_aa(acroform.get("/AA")))
                    + sum(is_benign_catalog_aa(page.obj.get("/AA")) for page in pdf.pages)
                )
                if not scripts and not xfa_analysis["present"] and "javascript_body_unavailable" not in non_js:
                    audit["inspected_acroform_tokens"] = sum(
                        _is_inactive_acroform(root.get(key)) for key in ("/AcroForm", "/Acroform")
                    )
            structural_audit.update(audit)
    except (pikepdf.PdfError, pypdf.errors.PyPdfError, ValueError, TypeError):
        non_js.add("supplemental_inspection_incomplete")
    return non_js, qr_analysis, differential, inspected_uri_tokens


def _build_xref_offset_map(reader: PdfReader, raw_pdf_bytes: bytes) -> dict[tuple[int, int], int]:
    offset_map: dict[tuple[int, int], int] = {}
    xref = getattr(reader, "xref", None)
    if not isinstance(xref, dict):
        return offset_map
    total_len = len(raw_pdf_bytes)
    for gen, entries in xref.items():
        if not isinstance(entries, dict):
            continue
        gen_int = int(gen)
        for obj_num, pos in entries.items():
            if not isinstance(pos, int) or not 0 <= pos < total_len:
                continue
            key = (int(obj_num), gen_int)
            if key in offset_map:
                continue
            prefix = f"{key[0]} {gen_int} obj".encode("ascii")
            if raw_pdf_bytes[pos : pos + 40].lstrip().startswith(prefix):
                offset_map[key] = pos
    return offset_map


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr)
    nonzero = counts[counts > 0].astype(np.float64)
    probs = nonzero / float(len(data))
    return float(-np.sum(probs * np.log2(probs)))


def _build_hex_dump_lines(raw_bytes: bytes, base_offset: int = 0, max_lines: int = 4) -> list[str]:
    if not raw_bytes:
        return []
    lines: list[str] = []
    slice_data = raw_bytes[: max_lines * 16]
    for row_idx in range(0, len(slice_data), 16):
        chunk = slice_data[row_idx : row_idx + 16]
        left_hex = " ".join(f"{b:02x}" for b in chunk[:8]).ljust(23)
        right_hex = " ".join(f"{b:02x}" for b in chunk[8:16]).ljust(23)
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        addr = base_offset + row_idx
        lines.append(f"{addr:08X}: {left_hex}  {right_hex}  |{ascii_repr}|")
    return lines


def _safe_raw_get(obj: Any, key: str) -> Any:
    if isinstance(obj, DictionaryObject) and key in obj:
        try:
            return obj.raw_get(key)
        except Exception:
            return obj.get(key)
    if hasattr(obj, "get"):
        try:
            return obj.get(key)
        except Exception:
            return None
    return None


def _index_physical_object_spans(
    raw_pdf_bytes: bytes,
) -> tuple[dict[tuple[int, int], int], dict[tuple[int, int], tuple[int, int]]]:
    offset_map: dict[tuple[int, int], int] = {}
    span_map: dict[tuple[int, int], tuple[int, int]] = {}
    endobj_pattern = re.compile(rb"\bendobj\b")
    for m in re.finditer(rb"(?m)(?:^|[\r\n])(\d+)\s+(\d+)\s+obj\b", raw_pdf_bytes):
        key = (int(m.group(1)), int(m.group(2)))
        start_pos = m.start(1)
        if key not in offset_map:
            offset_map[key] = start_pos
            end_m = endobj_pattern.search(raw_pdf_bytes, m.end(0))
            if end_m is not None and end_m.end(0) > start_pos:
                span_map[key] = (start_pos, end_m.end(0))
    return offset_map, span_map


def _extract_object_metadata(
    obj: Any,
    raw_pdf_bytes: bytes,
    fallback_index: int,
    indirect_id: int | None = None,
    offset_map: dict[tuple[int, int], int] | None = None,
    span_map: dict[tuple[int, int], tuple[int, int]] | None = None,
    *,
    doc_budget: DecodeBudget | None = None,
) -> dict[str, Any]:
    resolved = obj
    obj_num = indirect_id
    if isinstance(obj, IndirectObject):
        obj_num = obj.idnum
        try:
            resolved = obj.get_object()
        except Exception:
            resolved = obj

    reference = obj if isinstance(obj, IndirectObject) else getattr(resolved, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        obj_num = reference.idnum
    generation = reference.generation if isinstance(reference, IndirectObject) else 0
    obj_ref_str = f"obj_{obj_num} {generation} R" if obj_num is not None else None
    filter_name = "Uncompressed"
    is_stream = isinstance(resolved, StreamObject) or hasattr(resolved, "get_data")
    raw_obj_bytes = b""
    raw_stream_bytes: int | None = None
    decoded_stream_bytes: int | None = None
    stream_decode_failed = False
    decompression_ratio_exceeded = False
    content_preview = ""

    if is_stream:
        if isinstance(resolved, DictionaryObject) and "/Filter" in resolved:
            filter_name = str(resolved.get("/Filter"))
        else:
            filter_name = "Uncompressed"
        raw_stream_buf = getattr(resolved, "_data", None)
        filters = _stream_filters(resolved.get("/Filter")) if isinstance(resolved, DictionaryObject) else []
        if isinstance(raw_stream_buf, (bytes, bytearray)):
            raw_stream_bytes = len(raw_stream_buf)
            raw_obj_bytes = bytes(raw_stream_buf[:_STREAM_PREVIEW_LIMIT])
            if not filters:
                decoded_stream_bytes = raw_stream_bytes
        if filters and raw_stream_bytes is not None and raw_stream_bytes <= _STREAM_PREVIEW_LIMIT:
            budget = doc_budget if doc_budget is not None else DecodeBudget(_CODEC_DOC_BUDGET_BYTES)
            if budget.remaining and not _JBIG2_FILTERS.intersection(filters):
                try:
                    preview = decode_filters(
                        raw_obj_bytes,
                        filters,
                        decode_parms=_stream_decode_parms(resolved, filters),
                        limits=_STREAM_PREVIEW_LIMITS,
                        budget=budget,
                    )
                except (pypdf.errors.PyPdfError, ValueError, TypeError, OverflowError):
                    stream_decode_failed = True
                else:
                    if preview.data is not None:
                        raw_obj_bytes = preview.data
                        decoded_stream_bytes = len(preview.data)
                    elif preview.partial_data is not None and len(filters) == 1:
                        raw_obj_bytes = preview.partial_data[:_STREAM_PREVIEW_LIMIT]
                    status = preview.metadata["status"]
                    stream_decode_failed = status == "decode_error"
                    if (
                        status == "resource_limit"
                        and filters in (["/FlateDecode"], ["/Fl"])
                        and raw_stream_bytes <= 32768
                        and budget.remaining
                    ):
                        threshold = max(32 * 1024**2, 1000 * max(raw_stream_bytes, 1))
                        cap = min(threshold, budget.remaining)
                        _, _, reasons = _flate_prefix_and_length(bytes(raw_stream_buf), budget, prefix_cap=0, cap=cap)
                        quota_stop = bool(CODEC_QUOTA_REASON_CODES.intersection(reasons))
                        decompression_ratio_exceeded = quota_stop and cap == threshold
                        stream_decode_failed = bool(reasons) and not quota_stop
        decoded_text = raw_obj_bytes[:1200].decode("utf-8", errors="replace").strip()
        printable_ratio = sum(1 for c in decoded_text[:200] if c.isprintable() or c in "\r\n\t") / max(
            len(decoded_text[:200]), 1
        )
        if printable_ratio > 0.75 and decoded_text:
            content_preview = decoded_text[:600]
        else:
            if isinstance(resolved, DictionaryObject):
                key_parts: list[str] = []
                for k in list(resolved.keys())[:8]:
                    rv = _safe_raw_get(resolved, k)
                    if isinstance(rv, IndirectObject):
                        key_parts.append(f"{k}: {rv.idnum} {rv.generation} R")
                    elif isinstance(rv, (DictionaryObject, ArrayObject)):
                        key_parts.append(f"{k}: [...]")
                    else:
                        key_parts.append(f"{k}: {str(rv)[:24]}")
                dict_keys = " ".join(key_parts)
            else:
                dict_keys = "Binary Stream"
            payload_len = raw_stream_bytes if raw_stream_bytes is not None else len(raw_obj_bytes)
            content_preview = f"<< {dict_keys} >>\n[Luồng nhị phân: {payload_len} byte, bộ lọc: {filter_name}]"
    elif isinstance(resolved, DictionaryObject):
        filter_name = "Dictionary"
        pairs: list[str] = []
        for k in list(resolved.keys())[:12]:
            try:
                v_val = _safe_raw_get(resolved, k)
                if isinstance(v_val, IndirectObject):
                    v_str = f"{v_val.idnum} {v_val.generation} R"
                elif isinstance(v_val, DictionaryObject):
                    v_str = f"<< Dict ({len(v_val)} keys) >>"
                elif isinstance(v_val, ArrayObject):
                    v_str = f"[ Array ({len(v_val)} items) ]"
                else:
                    v_str = str(v_val)
                    if len(v_str) > 80:
                        v_str = v_str[:77] + "..."
                pairs.append(f"  {k} {v_str}")
            except Exception:
                pairs.append(f"  {k} [Object]")
        content_preview = "<<\n" + "\n".join(pairs) + "\n>>"
        raw_obj_bytes = content_preview.encode("utf-8", errors="ignore")
    elif isinstance(resolved, ArrayObject):
        filter_name = "Array"
        arr_items: list[str] = []
        for item in list(resolved)[:12]:
            if isinstance(item, IndirectObject):
                arr_items.append(f"{item.idnum} {item.generation} R")
            else:
                arr_items.append(str(type(item).__name__))
        content_preview = "[ " + ", ".join(arr_items) + (" ..." if len(resolved) > 12 else "") + " ]"
        raw_obj_bytes = content_preview.encode("utf-8", errors="ignore")
    else:
        text_repr = str(resolved)
        content_preview = text_repr[:600]
        raw_obj_bytes = text_repr.encode("utf-8", errors="ignore")

    offset_pos: int | None = None
    phys_span_bytes: int | None = None
    if obj_num is not None:
        if offset_map is not None:
            offset_pos = offset_map.get((obj_num, generation))
        else:
            marker = re.search(
                rb"(?m)(?:^|[\r\n])(" + str(obj_num).encode() + rb"\s+" + str(generation).encode() + rb"\s+obj\b)",
                raw_pdf_bytes,
            )
            if marker is not None:
                offset_pos = marker.start(1)
                end_m = re.search(rb"\bendobj\b", raw_pdf_bytes[marker.end(1) :])
                if end_m is not None:
                    phys_span_bytes = (marker.end(1) + end_m.end(0)) - offset_pos
        if span_map is not None and (obj_num, generation) in span_map:
            s_pos, e_pos = span_map[(obj_num, generation)]
            phys_span_bytes = e_pos - s_pos
        elif offset_pos is not None:
            end_idx = raw_pdf_bytes.find(b"endobj", offset_pos)
            if end_idx >= offset_pos:
                phys_span_bytes = (end_idx + 6) - offset_pos

    pdf_window = raw_pdf_bytes[offset_pos : offset_pos + 64] if offset_pos is not None else b""
    hex_dump = _build_hex_dump_lines(pdf_window, base_offset=offset_pos or 0, max_lines=4)
    fallback_size = raw_stream_bytes if raw_stream_bytes is not None else len(raw_obj_bytes)
    actual_size = (
        float(phys_span_bytes) if phys_span_bytes is not None and phys_span_bytes > 0 else float(fallback_size)
    )
    entropy_sample = raw_obj_bytes[:65536] if raw_obj_bytes else pdf_window
    entropy_val = round(_shannon_entropy(entropy_sample), 4)

    physical_bytes = (
        raw_pdf_bytes[offset_pos : offset_pos + min(phys_span_bytes, 65536)]
        if offset_pos is not None
        and phys_span_bytes
        and 0 <= offset_pos < len(raw_pdf_bytes)
        and offset_pos + phys_span_bytes <= len(raw_pdf_bytes)
        else None
    )
    if physical_bytes is not None:
        measured_size, size_source = phys_span_bytes, "pdf_object_span"
        measured_entropy, entropy_source = round(_shannon_entropy(physical_bytes), 4), "pdf_object_span"
    elif is_stream and isinstance(raw_stream_buf, (bytes, bytearray)):
        measured_size, size_source = len(raw_stream_buf), "encoded_stream"
        measured_entropy = round(_shannon_entropy(bytes(raw_stream_buf[:65536])), 4)
        entropy_source = "encoded_stream"
    else:
        measured_size = size_source = measured_entropy = entropy_source = None

    return {
        "obj_ref_str": obj_ref_str,
        "obj_num": obj_num,
        "generation": generation,
        "filter": filter_name,
        "size_bytes": actual_size,
        "byte_measurements": {
            "size_bytes": measured_size,
            "size_source": size_source,
            "entropy": measured_entropy,
            "entropy_source": entropy_source,
        },
        "phys_span_bytes": phys_span_bytes,
        "raw_stream_bytes": raw_stream_bytes,
        "decoded_stream_bytes": decoded_stream_bytes,
        "stream_decode_failed": stream_decode_failed,
        "decompression_ratio_exceeded": decompression_ratio_exceeded,
        "has_stream": bool(is_stream),
        "entropy": entropy_val,
        "offset_int": offset_pos,
        "offset_hex": f"0x{offset_pos:08X}" if offset_pos is not None else None,
        "hex_dump": hex_dump,
        "content_preview": content_preview,
    }


def _measure_byte_image_file_ratios(data: bytes) -> tuple[float, float]:
    if not data:
        return 0.0, 0.0
    limits = ByteImageLimits()
    capacity = limits.width * limits.rows_per_tile
    total_len = len(data)
    planned_tiles = (total_len + capacity - 1) // capacity
    encoded_bytes = 0
    mapped_pixels_work = 0
    attempted = 0
    for tile_idx in _tile_order(planned_tiles):
        if attempted >= limits.max_tiles:
            break
        attempted += 1
        start = tile_idx * capacity
        end = min(total_len, start + capacity)
        count = end - start
        height = (count + limits.width - 1) // limits.width
        pixels = height * limits.width
        if mapped_pixels_work + pixels > limits.max_mapped_pixels:
            continue
        mapped_pixels_work += pixels
        encoded_bytes += count
    return float(encoded_bytes) / float(total_len), 0.0


def compute_rwse(adj_matrix: np.ndarray, steps: int = 16) -> np.ndarray:
    n = adj_matrix.shape[0]
    if n == 0:
        return np.zeros((0, steps), dtype=np.float32)
    degrees = adj_matrix.sum(axis=1)
    degrees[degrees == 0] = 1.0
    transition = adj_matrix / degrees[:, None]
    for i in range(n):
        if adj_matrix[i].sum() == 0:
            transition[i, i] = 1.0
    rwse = np.zeros((n, steps), dtype=np.float32)
    power = transition.copy()
    for k in range(steps):
        rwse[:, k] = np.diag(power)
        power = np.matmul(power, transition)
    return rwse


class InstantPDFIngestion:
    def __init__(
        self,
        scaler_path: Path | str | None = None,
        node_in_dim: int = 23,
        as_numpy: bool = False,
        v3_contract_path: Path | str | None = None,
        v4_contract_path: Path | str | None = None,
    ) -> None:
        if node_in_dim not in (19, 23):
            raise ValueError("unsupported_node_in_dim")
        self.node_in_dim: int = int(node_in_dim)
        self._torch = None
        if not as_numpy:
            try:
                import torch
            except ImportError:
                pass
            else:
                self._torch = torch
        self.as_numpy: bool = self._torch is None
        path = Path(scaler_path) if scaler_path is not None else DEFAULT_SCALER_PATH
        with path.open("r", encoding="utf-8") as stream:
            scaler_data = json.load(stream)
        self.contract_version: str | None = scaler_data.get("contract_version") or scaler_data.get("fitted_on")
        self.contract_verified: bool = bool(
            self.contract_version and VERIFIED_CONTRACT_VERSION in str(self.contract_version)
        )
        self.feature_names: list[str] = scaler_data["feature_names"]
        self.scaler_mean: np.ndarray = np.array(scaler_data["mean"], dtype=np.float32)
        self.scaler_scale: np.ndarray = np.array(scaler_data["scale"], dtype=np.float32)
        if (
            len(self.feature_names) != 38
            or len(set(self.feature_names)) != 38
            or self.scaler_mean.shape != (38,)
            or self.scaler_scale.shape != (38,)
            or not np.isfinite(self.scaler_mean).all()
            or not np.isfinite(self.scaler_scale).all()
            or not (self.scaler_scale > 0).all()
        ):
            raise ValueError("invalid_training_scaler")

        self.v3_contract: dict[str, Any] = {}
        self.v3_feature_names: list[str] = []
        self.v3_center = np.empty(0, dtype=np.float64)
        self.v3_scale = np.empty(0, dtype=np.float64)
        v3_path = DEFAULT_V3_CONTRACT_PATH
        if not v3_path.is_file():
            v3_path = REPO_ROOT / "production" / "configs" / v3_path.name
        if v3_contract_path is not None or v3_path.is_file():
            if v3_contract_path is not None:
                v3_path = Path(v3_contract_path)
            self.v3_contract = json.loads(v3_path.read_text(encoding="utf-8"))
            self.v3_feature_names = self.v3_contract["feature_names"]
            self.v3_center = np.asarray(self.v3_contract["center"], dtype=np.float64)
            self.v3_scale = np.asarray(self.v3_contract["scale"], dtype=np.float64)
            if (
                tuple(self.v3_feature_names) != REGIME_B_NAMES
                or tuple(self.v3_contract["feature_indices_73"]) != REGIME_B_INDICES
                or self.v3_center.shape != (29,)
                or self.v3_scale.shape != (29,)
                or not np.isfinite(self.v3_center).all()
                or not np.isfinite(self.v3_scale).all()
                or np.any(self.v3_scale == 0)
            ):
                raise ValueError("invalid_transgraph_v3_contract")

        self.v4_contract: dict[str, Any] = {}
        self.v4_feature_names: list[str] = []
        self.v4_center = np.empty(0, dtype=np.float64)
        self.v4_scale = np.empty(0, dtype=np.float64)
        v4_path = DEFAULT_V4_CONTRACT_PATH
        if not v4_path.is_file():
            v4_path = REPO_ROOT / "production" / "configs" / v4_path.name
        if v4_contract_path is not None or v4_path.is_file():
            if v4_contract_path is not None:
                v4_path = Path(v4_contract_path)
            self.v4_contract = json.loads(v4_path.read_text(encoding="utf-8"))
            self.v4_feature_names = self.v4_contract["feature_names"]
            self.v4_center = np.asarray(self.v4_contract["center"], dtype=np.float64)
            self.v4_scale = np.asarray(self.v4_contract["scale"], dtype=np.float64)
            if (
                tuple(self.v4_feature_names) != REGIME_B_NAMES
                or tuple(self.v4_contract["feature_indices_73"]) != REGIME_B_INDICES
                or self.v4_center.shape != (29,)
                or self.v4_scale.shape != (29,)
                or not np.isfinite(self.v4_center).all()
                or not np.isfinite(self.v4_scale).all()
                or np.any(self.v4_scale == 0)
            ):
                raise ValueError("invalid_transgraph_v4_contract")

    def _build_regime_b_tabular_features(
        self,
        data: bytes,
        raw_entropy: float,
        header_pos: int,
        center: np.ndarray,
        scale: np.ndarray,
        recovered_tokens: dict[str, int] | None = None,
    ) -> tuple[list[float], Any]:
        if center.size == 0:
            return [], None
        tok = scan_raw_pdf_tokens(data)
        for key, count in (recovered_tokens or {}).items():
            if key in tok:
                tok[key] = max(tok[key], count)
        denom = max(float(tok["obj"]), 1.0)
        raw = [float(tok[name.removeprefix("lexical_")]) for name in REGIME_B_NAMES if name.startswith("lexical_")]
        raw.extend(
            (
                float(len(data)),
                raw_entropy,
                float(max(header_pos, 0)),
                float(tok["JS"] + tok["JavaScript"]) / denom,
                float(tok["stream"]) / denom,
                float(tok["obj"] - tok["endobj"]),
                float(tok["stream"] - tok["endstream"]),
            )
        )
        if not self.contract_verified:
            return raw, None
        scaled = ((log_matrix([raw]) - center) / scale).astype(np.float32)
        return raw, scaled if self.as_numpy else self._torch.from_numpy(scaled)

    def _build_v3_tabular_features(
        self,
        data: bytes,
        raw_entropy: float,
        header_pos: int,
        recovered_tokens: dict[str, int] | None = None,
    ) -> tuple[list[float], Any]:
        if not self.v3_contract:
            return [], None
        return self._build_regime_b_tabular_features(
            data, raw_entropy, header_pos, self.v3_center, self.v3_scale, recovered_tokens
        )

    def _build_v4_tabular_features(
        self,
        data: bytes,
        raw_entropy: float,
        header_pos: int,
        recovered_tokens: dict[str, int] | None = None,
    ) -> tuple[list[float], Any]:
        if not self.v4_contract:
            return [], None
        return self._build_regime_b_tabular_features(
            data, raw_entropy, header_pos, self.v4_center, self.v4_scale, recovered_tokens
        )

    def read_bytes(self, source: str | Path | bytes, max_bytes: int = DEFAULT_MAX_PDF_BYTES) -> tuple[bytes, str]:
        if isinstance(source, bytes):
            data = source
            if len(data) > max_bytes:
                raise ValueError("size_limit_exceeded")
            sha256 = hashlib.sha256(data).hexdigest()
            return data, sha256
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"PDF file not found: {path}")
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError("size_limit_exceeded")
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("size_limit_exceeded")
        sha256 = hashlib.sha256(data).hexdigest()
        return data, sha256

    def ingest(
        self, source: str | Path | bytes, max_bytes: int = DEFAULT_MAX_PDF_BYTES, *, password: str | None = None
    ) -> dict[str, Any]:
        data, sha256 = self.read_bytes(source, max_bytes=max_bytes)
        if b"%PDF-" not in data[:1024]:
            raise ValueError("not_a_pdf_missing_header")
        pdf_size = len(data)
        raw_tokens, evasion_unpack_audit = _recover_hidden_evasion_tokens(data, _scan_scanner_raw_tokens(data))
        raw_entropy = _shannon_entropy(data)
        header_pos = data.find(b"%PDF-")
        pdf_version = "1.7"
        if header_pos >= 0 and len(data) >= header_pos + 8:
            ver_candidate = data[header_pos + 5 : header_pos + 8].decode("ascii", errors="ignore")
            if re.match(r"^\d\.\d$", ver_candidate):
                pdf_version = ver_candidate

        last_eof = data.rfind(b"%%EOF")
        prefix_bytes = data[:header_pos] if header_pos > 0 else b""
        suffix_bytes = data[last_eof + 5 :] if last_eof >= 0 else b""
        raw_prefix_entropy = _shannon_entropy(prefix_bytes)
        raw_suffix_entropy = _shannon_entropy(suffix_bytes)

        records: list[dict[str, Any]] = []
        raw_edges: list[dict[str, Any]] = []
        extracted_scripts: list[dict[str, Any]] = []
        extracted_uris: list[dict[str, Any]] = []
        codec_anomalies: list[dict[str, Any]] = []
        codec_inspection_limits: list[dict[str, Any]] = []
        doc_budget = DecodeBudget(_CODEC_DOC_BUDGET_BYTES)
        xfa_analysis = {"present": False, "javascript_count": 0, "formcalc_count": 0, "xml_nodes": 0, "anomalies": []}
        graph_bytes = data
        metadata_size = 0.0
        encrypted = bool(raw_tokens.get("Encrypt"))
        password_locked = unlocked_with_password = unlocked_empty_password = False
        inspection_warnings: list[str] = []

        try:
            reader, pages_count = _open_scanner_reader(data)
        except Exception:
            reader, pages_count = None, max(raw_tokens["page_command"], 1)

        if reader is None or (encrypted and reader.is_encrypted):
            try:
                with pikepdf.open(io.BytesIO(data), password=password or "") as pdf:
                    unlocked = io.BytesIO()
                    pdf.save(unlocked, encryption=False)
                    unlocked_with_password = pdf.is_encrypted and password is not None
                    unlocked_empty_password = pdf.is_encrypted and password is None
                graph_bytes = unlocked.getvalue()
                reader, pages_count = _open_scanner_reader(graph_bytes)
            except pikepdf.PasswordError as exc:
                if not encrypted:
                    raise ValueError("pdf_parse_failed") from exc
                reader, pages_count = None, max(raw_tokens["page_command"], 1)
                password_locked = True
                inspection_warnings.append(
                    "encrypted_pdf_structure_hidden_password_required"
                    if password is None
                    else "encrypted_pdf_incorrect_password"
                )
            except Exception as exc:
                raise ValueError("pdf_parse_failed") from exc
        non_js_triggers = set()
        qr_analysis = empty_qr_analysis()
        differential_analysis = _differential_summary()
        inspected_uri_tokens = 0
        structural_audit = {
            "stream_interior_tokens": {},
            "inspected_acroform_tokens": 0,
            "inspected_benign_openaction_tokens": 0,
            "inspected_benign_aa_tokens": 0,
        }
        polyglot_analysis = inspect_polyglot_and_revisions(data, header_pos, last_eof)
        recovered = evasion_unpack_audit["recovered_hidden_triggers"]
        try:
            if reader is not None:
                if reader.metadata:
                    metadata_size = float(len(str(reader.metadata).encode("utf-8", errors="ignore")))
                root = reader.trailer["/Root"]
                meta_stream = root["/Metadata"] if isinstance(root, DictionaryObject) and "/Metadata" in root else None
                if isinstance(meta_stream, StreamObject) and not _JBIG2_FILTERS.intersection(
                    _stream_filters(meta_stream.get("/Filter"))
                ):
                    metadata_size = max(float(len(meta_stream.get_data())), metadata_size)
        except Exception as exc:
            raise ValueError("pdf_parse_failed") from exc
        if reader is not None and not password_locked:
            non_js_triggers, qr_analysis, differential_analysis, inspected_uri_tokens = self._extract_graph_and_scripts(
                reader,
                graph_bytes,
                records,
                raw_edges,
                extracted_scripts,
                extracted_uris,
                codec_anomalies,
                xfa_analysis,
                raw_tokens,
                recovered,
                data,
                polyglot_analysis["incremental_eof_count"],
                structural_audit,
                codec_inspection_limits=codec_inspection_limits,
                doc_budget=doc_budget,
            )

        codec_records = {anomaly["evidence_id"] for anomaly in codec_anomalies}
        for record in records:
            reasons = [key for key in ("stream_decode_failed", "decompression_ratio_exceeded") if record[key]]
            if reasons and record["evidence_id"] not in codec_records:
                record["is_threat_trigger"] = True
                codec_anomalies.append(
                    {
                        "evidence_id": record["evidence_id"],
                        "object_number": record["obj_num"],
                        "generation": record["generation"],
                        "codec": record["filter"],
                        "reason_codes": reasons,
                    }
                )

        phishing_analysis = _analyze_phishing(reader, extracted_uris, pages_count, records, qr_analysis)
        graph_data = self._build_hetero_graph(records, raw_edges)
        ast_tokens, ast_stats, ast_node_counts = self._extract_ast_stream(extracted_scripts, xfa_analysis["anomalies"])
        js_semantics = evaluate_javascript_semantics(extracted_scripts, ast_stats, ast_node_counts)
        tab_features, raw_feature_vec = self._build_tabular_features(
            data=data,
            raw_tokens=raw_tokens,
            pages_count=pages_count,
            metadata_size=metadata_size,
            raw_entropy=raw_entropy,
            raw_prefix_entropy=raw_prefix_entropy,
            raw_suffix_entropy=raw_suffix_entropy,
            ast_stats=ast_stats,
            records=records,
            extracted_scripts=extracted_scripts,
            stream_interior_tokens=structural_audit["stream_interior_tokens"],
        )
        recovered_map = {key: raw_tokens[key] for key in recovered}
        v3_raw, v3_tab = self._build_v3_tabular_features(data, raw_entropy, header_pos, recovered_map)
        v4_raw, v4_tab = self._build_v4_tabular_features(data, raw_entropy, header_pos, recovered_map)
        eff_v3_names = self.v3_feature_names or self.v4_feature_names
        eff_v3_raw = v3_raw if v3_raw else v4_raw
        eff_v3_tab = v3_tab if v3_tab is not None else v4_tab
        eff_v3_center = self.v3_center.tolist() if self.v3_center.size else self.v4_center.tolist()
        eff_v3_scale = self.v3_scale.tolist() if self.v3_scale.size else self.v4_scale.tolist()

        ingest_data = {
            **graph_data,
            "sha256": sha256,
            "size_bytes": pdf_size,
            "pdf_version": pdf_version,
            "pages_count": pages_count,
            "encryption_analysis": {
                "encrypted": encrypted,
                "password_locked": password_locked,
                "unlocked_with_password": unlocked_with_password,
                "unlocked_empty_password": unlocked_empty_password,
                "graph_inspected": reader is not None,
                "inspection_warnings": inspection_warnings,
            },
            "graph_byte_source": (
                "unlocked_pdf_copy" if graph_bytes is not data else "original_pdf" if reader is not None else None
            ),
            "raw_entropy": round(raw_entropy, 4),
            "ast_tokens": ast_tokens,
            "ast_stats": ast_stats,
            "ast_node_counts": ast_node_counts,
            "tab_features": tab_features,
            "raw_feature_vec": raw_feature_vec,
            "v3_feature_names": eff_v3_names,
            "v3_raw_feature_vec": eff_v3_raw,
            "v3_tab_features": eff_v3_tab,
            "v3_scaler_center": eff_v3_center,
            "v3_scaler_scale": eff_v3_scale,
            "v4_feature_names": self.v4_feature_names,
            "v4_raw_feature_vec": v4_raw,
            "v4_tab_features": v4_tab,
            "v4_scaler_center": self.v4_center.tolist(),
            "v4_scaler_scale": self.v4_scale.tolist(),
            "prediction_blockers": [
                f"feature_not_observed:{name}"
                for name, value in zip(self.feature_names, raw_feature_vec)
                if value is None
            ],
            "feature_names": self.feature_names,
            "scaler_mean": self.scaler_mean.tolist(),
            "scaler_scale": self.scaler_scale.tolist(),
            "raw_records": records,
            "raw_edges": raw_edges,
            "extracted_scripts": extracted_scripts,
            "js_semantics": js_semantics,
            "extracted_uris": extracted_uris,
            "inspected_uri_tokens": inspected_uri_tokens,
            "structural_audit": structural_audit,
            "phishing_analysis": phishing_analysis,
            "qr_analysis": qr_analysis,
            "differential_analysis": differential_analysis,
            "polyglot_analysis": polyglot_analysis,
            "codec_anomalies": codec_anomalies,
            "codec_inspection_limits": codec_inspection_limits,
            "xfa_analysis": xfa_analysis,
            "evasion_unpack_audit": evasion_unpack_audit,
            "non_js_triggers": sorted(non_js_triggers),
            "raw_tokens": raw_tokens,
        }
        invalidate_incomplete_javascript_verification(ingest_data)
        ingest_data["signature_matches"] = match_pdf_signatures(data, ingest_data)
        return ingest_data

    def _extract_graph_and_scripts(
        self,
        reader: PdfReader,
        raw_pdf_bytes: bytes,
        records: list[dict[str, Any]],
        raw_edges: list[dict[str, Any]],
        extracted_scripts: list[dict[str, Any]],
        extracted_uris: list[dict[str, Any]],
        codec_anomalies: list[dict[str, Any]],
        xfa_analysis: dict[str, Any],
        raw_tokens: dict[str, int],
        recovered: list[str],
        original_data: bytes,
        incremental_eof_count: int,
        structural_audit: dict[str, Any],
        *,
        codec_inspection_limits: list[dict[str, Any]],
        doc_budget: DecodeBudget,
    ) -> tuple[set[str], dict[str, Any], dict[str, Any], int]:
        visited_ids: set[str] = set()
        node_limit = 200
        offset_map = _build_xref_offset_map(reader, raw_pdf_bytes)
        span_map: dict[tuple[int, int], tuple[int, int]] = {}
        if not offset_map and len(raw_pdf_bytes) <= 8 * 1024 * 1024:
            offset_map, span_map = _index_physical_object_spans(raw_pdf_bytes)

        def register_node(
            evidence_id: str,
            kind: str,
            size: float | None = None,
            has_stream: bool = False,
            obj_ref: Any = None,
            is_threat_trigger: bool = False,
            invoker: str = "/Root",
            indirect_id: int | None = None,
            action_type: str | None = None,
            action_role: str | None = None,
            page_index: int | None = None,
            rect_area: float = 0.0,
            page_area: float = 0.0,
        ) -> None:
            if evidence_id in visited_ids or len(records) >= node_limit:
                return
            visited_ids.add(evidence_id)
            seq_idx = len(records) + 1
            meta = _extract_object_metadata(
                obj=obj_ref,
                raw_pdf_bytes=raw_pdf_bytes,
                fallback_index=seq_idx,
                indirect_id=indirect_id,
                offset_map=offset_map,
                span_map=span_map,
                doc_budget=doc_budget,
            )
            final_size = size if size is not None and meta["phys_span_bytes"] is None else meta["size_bytes"]
            if kind == "action" and isinstance(obj_ref, DictionaryObject):
                action_type = action_type or str(obj_ref.get("/S") or "")
                if action_role is None and (action_type == "/URI" or "/URI" in obj_ref):
                    target = obj_ref["/URI"] if "/URI" in obj_ref else ""
                    if isinstance(target, bytes):
                        target = target.decode("utf-8", errors="ignore")
                    uri = (
                        _uri_evidence(target, evidence_id, invoker, page_index, rect_area, page_area)
                        if isinstance(target, str)
                        else None
                    )
                    if uri:
                        extracted_uris.append(uri)
                        if uri["is_suspicious"]:
                            is_threat_trigger = True
                            action_role = "suspicious_uri"
            if action_role is None and not is_threat_trigger:
                if evidence_id == "action:open_action":
                    if is_navigation_destination(obj_ref):
                        action_role = "destination"
                    elif is_benign_catalog_navigation(obj_ref):
                        action_role = "benign_navigation"
                elif evidence_id == "action:aa":
                    resolved_aa = _resolve_pdf_object(obj_ref)
                    if is_benign_catalog_aa(resolved_aa):
                        action_role = "empty_aa" if len(resolved_aa) == 0 else "benign_navigation"
            records.append(
                {
                    "evidence_id": evidence_id,
                    "kind": kind,
                    "size_bytes": final_size,
                    "byte_measurements": meta["byte_measurements"],
                    "action_type": action_type,
                    "action_role": action_role,
                    "phys_span_bytes": meta["phys_span_bytes"],
                    "raw_stream_bytes": meta["raw_stream_bytes"],
                    "decoded_stream_bytes": meta["decoded_stream_bytes"],
                    "stream_decode_failed": meta["stream_decode_failed"],
                    "decompression_ratio_exceeded": meta["decompression_ratio_exceeded"],
                    "has_stream": bool(has_stream or meta["has_stream"]),
                    "obj_ref": obj_ref,
                    "obj_ref_str": meta["obj_ref_str"],
                    "obj_num": meta["obj_num"],
                    "generation": meta["generation"],
                    "invoker": invoker,
                    "filter": meta["filter"],
                    "entropy": meta["entropy"],
                    "offset_hex": meta["offset_hex"],
                    "hex_dump": meta["hex_dump"],
                    "content_preview": meta["content_preview"],
                    "is_threat_trigger": is_threat_trigger,
                    "is_repaired": False,
                }
            )

        trailer = getattr(reader, "trailer", None) or {}
        raw_root_ref = _safe_raw_get(trailer, "/Root")
        root_idnum = raw_root_ref.idnum if isinstance(raw_root_ref, IndirectObject) else None
        root = trailer.get("/Root")
        if isinstance(root, IndirectObject):
            root_idnum = root.idnum
            root = root.get_object()
        root_id = "catalog:root"
        register_node(
            root_id,
            "catalog",
            has_stream=False,
            obj_ref=root,
            invoker="/Trailer/Root",
            indirect_id=root_idnum,
        )

        if isinstance(root, DictionaryObject):
            raw_pages_ref = _safe_raw_get(root, "/Pages")
            pages_idnum = raw_pages_ref.idnum if isinstance(raw_pages_ref, IndirectObject) else None
            pages_obj = root.get("/Pages")
            if isinstance(pages_obj, IndirectObject):
                pages_idnum = pages_obj.idnum
                pages_obj = pages_obj.get_object()
            pages_id = "pages:root"
            register_node(
                pages_id,
                "pages",
                has_stream=False,
                obj_ref=pages_obj,
                invoker="/Catalog/Pages",
                indirect_id=pages_idnum,
            )
            raw_edges.append({"source": root_id, "target": pages_id, "relation": ("catalog", "pages")})

            node_limit = 180
            for p_idx, page in enumerate(reader.pages):
                if len(records) >= node_limit:
                    break
                page_id = f"page:{p_idx}"
                page_ind = getattr(page, "indirect_reference", None)
                p_idnum = page_ind.idnum if isinstance(page_ind, IndirectObject) else None
                register_node(
                    page_id,
                    "page",
                    has_stream=False,
                    obj_ref=page,
                    invoker=f"/Pages/Kids[{p_idx}]",
                    indirect_id=p_idnum,
                )
                raw_edges.append({"source": pages_id, "target": page_id, "relation": ("pages", "page")})

                raw_contents = _safe_raw_get(page, "/Contents")
                c_idnum = raw_contents.idnum if isinstance(raw_contents, IndirectObject) else None
                contents = page.get("/Contents")
                if contents is not None:
                    if isinstance(contents, IndirectObject):
                        c_idnum = contents.idnum
                        contents = contents.get_object()
                    stream_id = f"stream:page_{p_idx}"
                    register_node(
                        stream_id,
                        "stream",
                        has_stream=True,
                        obj_ref=contents,
                        invoker=f"/Page[{p_idx}]/Contents",
                        indirect_id=c_idnum,
                    )
                    raw_edges.append({"source": page_id, "target": stream_id, "relation": ("page", "stream")})

                annots = page.get("/Annots")
                if isinstance(annots, IndirectObject):
                    annots = annots.get_object()
                if isinstance(annots, ArrayObject):
                    for a_idx, annot in enumerate(annots):
                        if len(records) >= node_limit:
                            break
                        a_idnum = annot.idnum if isinstance(annot, IndirectObject) else None
                        annot_resolved = annot.get_object() if isinstance(annot, IndirectObject) else annot
                        annot_id = f"annotation:{p_idx}_{a_idx}"
                        register_node(
                            annot_id,
                            "annotation",
                            has_stream=False,
                            obj_ref=annot_resolved,
                            invoker=f"/Page[{p_idx}]/Annots[{a_idx}]",
                            indirect_id=a_idnum,
                        )
                        if isinstance(annot_resolved, DictionaryObject):
                            raw_a_act = _safe_raw_get(annot_resolved, "/A")
                            act_idnum = raw_a_act.idnum if isinstance(raw_a_act, IndirectObject) else None
                            a_act = annot_resolved.get("/A")
                            if isinstance(a_act, IndirectObject):
                                act_idnum = a_act.idnum
                                a_act = a_act.get_object()
                            if a_act is not None:
                                act_id = f"action:annot_{p_idx}_{a_idx}"
                                act_type = ""
                                if isinstance(a_act, DictionaryObject):
                                    act_type = str(a_act.get("/S") or ("/JavaScript" if "/JS" in a_act else ""))
                                is_threat_act = act_type in (
                                    "/JavaScript",
                                    "/Launch",
                                    "/ImportData",
                                    "/GoToE",
                                    "/SubmitForm",
                                )
                                is_threat_act = is_threat_act or (
                                    isinstance(a_act, DictionaryObject) and "/JS" in a_act
                                )
                                rect = annot_resolved.get("/Rect")
                                if isinstance(rect, IndirectObject):
                                    rect = rect.get_object()
                                register_node(
                                    act_id,
                                    "action",
                                    has_stream=False,
                                    obj_ref=a_act,
                                    is_threat_trigger=is_threat_act,
                                    invoker=f"/Annot[{p_idx},{a_idx}]/A",
                                    indirect_id=act_idnum,
                                    action_type=act_type,
                                    page_index=p_idx,
                                    rect_area=annotation_rect_area(rect)
                                    if str(annot_resolved.get("/Subtype")) in VISUAL_LURE_SUBTYPES
                                    else 0.0,
                                    page_area=page_box_area(page)
                                    if str(annot_resolved.get("/Subtype")) in VISUAL_LURE_SUBTYPES
                                    else 0.0,
                                )
                                raw_edges.append({"source": page_id, "target": act_id, "relation": ("page", "action")})
                                self._check_action_for_script(
                                    a_act, act_id, records, raw_edges, extracted_scripts, register_node
                                )

            node_limit = 200
            if len(records) >= 180:
                raw_edges[:] = [
                    edge for edge in raw_edges if edge["source"] in visited_ids and edge["target"] in visited_ids
                ]
            raw_oa = _safe_raw_get(root, "/OpenAction")
            oa_idnum = raw_oa.idnum if isinstance(raw_oa, IndirectObject) else None
            open_action = root.get("/OpenAction")
            if open_action is not None:
                oa_resolved = open_action.get_object() if isinstance(open_action, IndirectObject) else open_action
                oa_id = "action:open_action"
                is_threat_oa = False
                s_type = ""
                if isinstance(oa_resolved, DictionaryObject):
                    s_type = str(oa_resolved.get("/S") or ("/JavaScript" if "/JS" in oa_resolved else ""))
                    if (
                        s_type in ("/JavaScript", "/Launch", "/ImportData", "/GoToE", "/SubmitForm")
                        or "/JS" in oa_resolved
                    ):
                        is_threat_oa = True
                register_node(
                    oa_id,
                    "action",
                    has_stream=False,
                    obj_ref=oa_resolved,
                    is_threat_trigger=is_threat_oa,
                    invoker="/Catalog/OpenAction",
                    indirect_id=oa_idnum,
                    action_type=s_type,
                )
                raw_edges.append({"source": root_id, "target": oa_id, "relation": ("catalog", "action")})
                self._check_action_for_script(oa_resolved, oa_id, records, raw_edges, extracted_scripts, register_node)

            raw_aa = _safe_raw_get(root, "/AA")
            aa_idnum = raw_aa.idnum if isinstance(raw_aa, IndirectObject) else None
            additional_actions = root.get("/AA")
            if additional_actions is not None:
                aa_resolved = (
                    additional_actions.get_object()
                    if isinstance(additional_actions, IndirectObject)
                    else additional_actions
                )
                aa_id = "action:aa"
                aa_action_types: set[str] = set()
                has_js_aa = False
                if isinstance(aa_resolved, DictionaryObject):
                    for k in aa_resolved:
                        sub = aa_resolved[k]
                        if isinstance(sub, IndirectObject):
                            sub = sub.get_object()
                        if isinstance(sub, DictionaryObject):
                            has_js_aa |= "/JS" in sub
                            aa_action_types.add(str(sub.get("/S") or ("/JavaScript" if "/JS" in sub else "")))
                is_threat_aa = has_js_aa or bool(
                    aa_action_types & {"/JavaScript", "/Launch", "/ImportData", "/GoToE", "/SubmitForm"}
                )
                register_node(
                    aa_id,
                    "action",
                    has_stream=False,
                    obj_ref=aa_resolved,
                    is_threat_trigger=is_threat_aa,
                    invoker="/Catalog/AA",
                    indirect_id=aa_idnum,
                    action_type=next(iter(aa_action_types)) if len(aa_action_types) == 1 else None,
                )
                raw_edges.append({"source": root_id, "target": aa_id, "relation": ("catalog", "action")})
                self._check_action_for_script(aa_resolved, aa_id, records, raw_edges, extracted_scripts, register_node)

            names = root.get("/Names")
            if isinstance(names, IndirectObject):
                names = names.get_object()
            if isinstance(names, DictionaryObject):
                raw_js_names = _safe_raw_get(names, "/JavaScript")
                js_names_idnum = raw_js_names.idnum if isinstance(raw_js_names, IndirectObject) else None
                js_names = names.get("/JavaScript")
                if isinstance(js_names, IndirectObject):
                    js_names_idnum = js_names.idnum
                    js_names = js_names.get_object()
                if js_names is not None:
                    js_id = "script:names_js"
                    register_node(
                        js_id,
                        "script",
                        has_stream=False,
                        obj_ref=js_names,
                        is_threat_trigger=True,
                        invoker="/Names/JavaScript",
                        indirect_id=js_names_idnum,
                    )
                    raw_edges.append({"source": root_id, "target": js_id, "relation": ("catalog", "script")})
                    self._extract_js_from_name_tree(js_names, extracted_scripts, js_id)

                raw_ef_names = _safe_raw_get(names, "/EmbeddedFiles")
                ef_names_idnum = raw_ef_names.idnum if isinstance(raw_ef_names, IndirectObject) else None
                ef_names = names.get("/EmbeddedFiles")
                if isinstance(ef_names, IndirectObject):
                    ef_names_idnum = ef_names.idnum
                    ef_names = ef_names.get_object()
                if ef_names is not None:
                    fs_id = "filespec:embedded_files"
                    register_node(
                        fs_id,
                        "filespec",
                        has_stream=False,
                        obj_ref=ef_names,
                        is_threat_trigger=True,
                        invoker="/Names/EmbeddedFiles",
                        indirect_id=ef_names_idnum,
                    )
                    raw_edges.append({"source": root_id, "target": fs_id, "relation": ("catalog", "filespec")})

            acroform = root.get("/AcroForm")
            if isinstance(acroform, IndirectObject):
                acroform = acroform.get_object()
            if isinstance(acroform, DictionaryObject) and "/XFA" in acroform:
                raw_xfa = _safe_raw_get(acroform, "/XFA")
                xfa_idnum = raw_xfa.idnum if isinstance(raw_xfa, IndirectObject) else None
                xfa_obj = acroform.get("/XFA")
                if isinstance(xfa_obj, IndirectObject):
                    xfa_idnum = xfa_obj.idnum
                    xfa_obj = xfa_obj.get_object()
                if xfa_obj is not None:
                    xfa_id = "script:acroform_xfa"
                    register_node(
                        xfa_id,
                        "script",
                        has_stream=isinstance(xfa_obj, StreamObject),
                        obj_ref=xfa_obj,
                        is_threat_trigger=True,
                        invoker="/AcroForm/XFA",
                        indirect_id=xfa_idnum,
                    )
                    raw_edges.append({"source": root_id, "target": xfa_id, "relation": ("catalog", "script")})

        if (
            incremental_eof_count <= 1
            and not any(
                raw_tokens.get(key)
                for key in (
                    "JavaScript",
                    "JS",
                    "AA",
                    "AcroForm",
                    "Acroform",
                    "URI",
                    "JBIG2Decode",
                    "ObjStm",
                    "OpenAction",
                    "Launch",
                    "EmbeddedFile",
                    "XFA",
                    "RichMedia",
                )
            )
            and not any(
                token in raw_pdf_bytes
                for token in (
                    b"/JB2",
                    b"/JPXDecode",
                    b"/FontFile",
                    b"/FontFile2",
                    b"/FontFile3",
                    b"/XFA",
                    b"/Image",
                    b"/DCTDecode",
                    b"/CCITTFaxDecode",
                    b"/ICCBased",
                    b"/GoToR",
                    b"/FileAttachment",
                    b"/3D",
                    b"/U3D",
                    b"/PRC",
                    b"/SubmitForm",
                    b"/ImportData",
                    b"/GoToE",
                    b"/Movie",
                    b"/Sound",
                    b"/Rendition",
                )
            )
            and _JBIG2_MAGIC not in raw_pdf_bytes
            and not recovered
            and not extracted_scripts
            and not _PDF_NAME.search(raw_pdf_bytes)
        ):
            if raw_pdf_bytes is original_data:
                try:
                    with pikepdf.open(io.BytesIO(raw_pdf_bytes)) as pdf:
                        structural_audit["stream_interior_tokens"] = _stream_interior_tokens(
                            pdf, raw_tokens, len(raw_pdf_bytes), raw_pdf_bytes=raw_pdf_bytes
                        )
                except (pikepdf.PdfError, ValueError, TypeError, OverflowError):
                    return {"supplemental_inspection_incomplete"}, empty_qr_analysis(), _differential_summary(), 0
            return set(), empty_qr_analysis(), _differential_summary(), 0

        def register_supplemental(
            evidence_id: str,
            kind: str,
            obj: Any,
            path: str,
            threat: bool = True,
            parent_id: str = "catalog:root",
            action_role: str | None = None,
        ) -> None:
            if evidence_id in visited_ids:
                return
            object_id = getattr(obj, "objgen", (0, 0))[0]
            obj_ref = None
            if isinstance(obj, pikepdf.Dictionary):
                try:
                    obj_ref = read_object(io.BytesIO(obj.unparse(resolved=True)), reader)
                except (pypdf.errors.PyPdfError, ValueError):
                    pass
            register_node(
                evidence_id,
                kind,
                obj_ref=obj_ref,
                is_threat_trigger=threat,
                invoker=path,
                indirect_id=object_id or None,
                has_stream=isinstance(obj, pikepdf.Stream),
                action_type=str(obj.get("/S") or ("/JavaScript" if "/JS" in obj else "")) if kind == "action" else None,
                action_role=action_role,
            )
            if evidence_id in visited_ids:
                parent_kind = "action" if parent_id.startswith("action:") else "catalog"
                raw_edges.append({"source": parent_id, "target": evidence_id, "relation": (parent_kind, kind)})

        return _inspect_additional_evidence(
            raw_pdf_bytes,
            reader,
            original_data,
            incremental_eof_count,
            records,
            extracted_scripts,
            extracted_uris,
            codec_anomalies,
            xfa_analysis,
            recovered,
            register_supplemental,
            raw_tokens,
            structural_audit,
            codec_inspection_limits=codec_inspection_limits,
            doc_budget=doc_budget,
        )

    def _check_action_for_script(
        self,
        action_obj: Any,
        action_id: str,
        records: list[dict[str, Any]],
        raw_edges: list[dict[str, Any]],
        extracted_scripts: list[dict[str, Any]],
        register_node: Any,
        depth: int = 0,
    ) -> None:
        if depth > 8:
            return
        if isinstance(action_obj, IndirectObject):
            action_obj = action_obj.get_object()
        if not isinstance(action_obj, DictionaryObject):
            return
        raw_js = _safe_raw_get(action_obj, "/JS")
        js_idnum = raw_js.idnum if isinstance(raw_js, IndirectObject) else None
        js_entry = action_obj.get("/JS")
        if isinstance(js_entry, IndirectObject):
            js_idnum = js_entry.idnum
            js_entry = js_entry.get_object()
        script_text = _pypdf_script_text(js_entry)
        if script_text is not None:
            script_id = f"script:{action_id}"
            register_node(
                script_id,
                "script",
                size=float(len(script_text.encode("utf-8", errors="ignore"))),
                has_stream=isinstance(js_entry, StreamObject),
                obj_ref=js_entry,
                is_threat_trigger=True,
                invoker=f"{action_id}/JS",
                indirect_id=js_idnum,
            )
            for rec in records:
                if rec["evidence_id"] == script_id and script_text:
                    rec["content_preview"] = script_text[:600]
            raw_edges.append({"source": action_id, "target": script_id, "relation": ("action", "script")})
            extracted_scripts.append(
                {
                    "script_id": script_id,
                    "parent_id": action_id,
                    "code": script_text,
                }
            )

        for k in list(action_obj.keys()):
            if str(k) in (
                "/O",
                "/C",
                "/E",
                "/X",
                "/D",
                "/U",
                "/Fo",
                "/Bl",
                "/PO",
                "/PC",
                "/PV",
                "/PI",
                "/K",
                "/F",
                "/V",
                "/WC",
                "/WS",
                "/DS",
                "/WP",
                "/DP",
            ):
                sub_act = action_obj.get(k)
                if sub_act is not None:
                    self._check_action_for_script(
                        sub_act,
                        action_id,
                        records,
                        raw_edges,
                        extracted_scripts,
                        register_node,
                        depth=depth + 1,
                    )

        if "/Next" in action_obj:
            next_act = action_obj.get("/Next")
            if isinstance(next_act, ArrayObject):
                for n_item in next_act:
                    self._check_action_for_script(
                        n_item,
                        action_id,
                        records,
                        raw_edges,
                        extracted_scripts,
                        register_node,
                        depth=depth + 1,
                    )
            elif next_act is not None:
                self._check_action_for_script(
                    next_act,
                    action_id,
                    records,
                    raw_edges,
                    extracted_scripts,
                    register_node,
                    depth=depth + 1,
                )

    def _extract_js_from_name_tree(self, node: Any, extracted_scripts: list[dict[str, Any]], script_id: str) -> None:
        if isinstance(node, IndirectObject):
            node = node.get_object()
        if not isinstance(node, DictionaryObject):
            return
        kids = node.get("/Kids")
        if isinstance(kids, ArrayObject):
            for k in kids:
                self._extract_js_from_name_tree(k, extracted_scripts, script_id)
        names = node.get("/Names")
        if isinstance(names, ArrayObject):
            for i in range(1, len(names), 2):
                val = names[i]
                if isinstance(val, IndirectObject):
                    val = val.get_object()
                if isinstance(val, DictionaryObject) and "/JS" in val:
                    js_obj = val.get("/JS")
                    if isinstance(js_obj, IndirectObject):
                        js_obj = js_obj.get_object()
                    code = _pypdf_script_text(js_obj)
                    if code is None:
                        continue
                    extracted_scripts.append(
                        {
                            "script_id": f"{script_id}_{i}",
                            "parent_id": script_id,
                            "code": code,
                        }
                    )

    def _build_hetero_graph(self, records: list[dict[str, Any]], raw_edges: list[dict[str, Any]]) -> dict[str, Any]:
        id_map: dict[str, int] = {}
        node_types: list[int] = []
        node_raw_features: list[list[float]] = []
        incoming_counts: dict[int, int] = {}

        for r in records[:200]:
            eid = r["evidence_id"]
            kind = r["kind"]
            if kind in NODE_TYPES:
                idx = len(node_types)
                id_map[eid] = idx
                node_types.append(NODE_TYPES[kind])
                size_val = float(r.get("phys_span_bytes") or r.get("size_bytes") or 0.0)
                has_stream_val = 1.0 if r.get("has_stream") else 0.0
                log_size = float(np.log1p(max(0.0, size_val)))
                if self.node_in_dim == 23:
                    phys_mask = 1.0 if size_val > 0.0 else 0.0
                    raw_stream = r.get("raw_stream_bytes")
                    stream_bytes_val = (
                        float(raw_stream) if isinstance(raw_stream, int) and raw_stream >= 0 else size_val
                    )
                    stream_log = float(np.log1p(max(0.0, stream_bytes_val))) if has_stream_val > 0.0 else 0.0
                    stream_mask = has_stream_val
                    ind_flag = 1.0
                    rep_flag = 1.0 if r.get("is_repaired") else 0.0
                    node_raw_features.append([log_size, phys_mask, stream_log, stream_mask, ind_flag, rep_flag])
                else:
                    node_raw_features.append([log_size, has_stream_val])
                incoming_counts[idx] = 0

        torch = self._torch
        num_nodes = len(node_types)
        if num_nodes == 0:
            if self.as_numpy or torch is None:
                return {
                    "graph_present": False,
                    "node_features": np.zeros((1, self.node_in_dim), dtype=np.float32),
                    "node_types": np.array([8], dtype=np.int64),
                    "edge_index": np.zeros((2, 0), dtype=np.int64),
                    "edge_rel": np.zeros((0,), dtype=np.int64),
                    "batch": np.zeros((1,), dtype=np.int64),
                }
            return {
                "graph_present": False,
                "node_features": torch.zeros((1, self.node_in_dim), dtype=torch.float32),
                "node_types": torch.tensor([8], dtype=torch.long),
                "edge_index": torch.zeros((2, 0), dtype=torch.long),
                "edge_rel": torch.zeros((0,), dtype=torch.long),
                "batch": torch.zeros((1,), dtype=torch.long),
            }

        adj = np.zeros((num_nodes, num_nodes), dtype=np.float32)
        edge_src: list[int] = []
        edge_dst: list[int] = []
        edge_rel: list[int] = []
        inv_node_types = {v: k for k, v in NODE_TYPES.items()}

        for e in raw_edges:
            s_id = e.get("source")
            t_id = e.get("target")
            s_idx = id_map.get(s_id)
            t_idx = id_map.get(t_id)
            if s_idx is not None and t_idx is not None:
                adj[s_idx, t_idx] = 1.0
                incoming_counts[t_idx] = incoming_counts.get(t_idx, 0) + 1
                s_kind = inv_node_types[node_types[s_idx]]
                t_kind = inv_node_types[node_types[t_idx]]
                rel = EDGE_TYPES.get((s_kind, t_kind), 7)
                edge_src.append(s_idx)
                edge_dst.append(t_idx)
                edge_rel.append(rel)

        rwse = compute_rwse(adj, steps=16)
        full_node_features: list[list[float]] = []
        for i in range(num_nodes):
            is_orphan = 1.0 if incoming_counts.get(i, 0) == 0 and node_types[i] != 0 else 0.0
            feat = node_raw_features[i] + [is_orphan] + rwse[i].tolist()
            full_node_features.append(feat)

        if self.as_numpy or torch is None:
            node_feat_np = np.asarray(full_node_features, dtype=np.float32)
            node_types_np = np.asarray(node_types, dtype=np.int64)
            if len(edge_src) > 0:
                edge_index_np = np.vstack(
                    [
                        np.asarray(edge_src, dtype=np.int64),
                        np.asarray(edge_dst, dtype=np.int64),
                    ]
                )
                edge_rel_np = np.asarray(edge_rel, dtype=np.int64)
            else:
                edge_index_np = np.zeros((2, 0), dtype=np.int64)
                edge_rel_np = np.zeros((0,), dtype=np.int64)
            batch_np = np.zeros((num_nodes,), dtype=np.int64)
            return {
                "graph_present": True,
                "node_features": node_feat_np,
                "node_types": node_types_np,
                "edge_index": edge_index_np,
                "edge_rel": edge_rel_np,
                "batch": batch_np,
            }

        node_feat_tensor = torch.tensor(full_node_features, dtype=torch.float32)
        node_types_tensor = torch.tensor(node_types, dtype=torch.long)
        if len(edge_src) > 0:
            edge_index_tensor = torch.stack(
                [
                    torch.tensor(edge_src, dtype=torch.long),
                    torch.tensor(edge_dst, dtype=torch.long),
                ],
                dim=0,
            )
            edge_rel_tensor = torch.tensor(edge_rel, dtype=torch.long)
        else:
            edge_index_tensor = torch.zeros((2, 0), dtype=torch.long)
            edge_rel_tensor = torch.zeros((0,), dtype=torch.long)

        batch_tensor = torch.zeros(num_nodes, dtype=torch.long)
        return {
            "graph_present": True,
            "node_features": node_feat_tensor,
            "node_types": node_types_tensor,
            "edge_index": edge_index_tensor,
            "edge_rel": edge_rel_tensor,
            "batch": batch_tensor,
        }

    def _extract_ast_stream(
        self, extracted_scripts: list[dict[str, Any]], xfa_anomalies: list[str]
    ) -> tuple[Any, dict[str, float], dict[str, int]]:
        counts: dict[str, int] = {k: 0 for k in AST_NODE_TYPES}
        total_nodes = 0
        max_depth = 0
        computed_members = 0
        loops = 0

        if extracted_scripts:
            xfa_sources = [item["code"] for item in extracted_scripts if item["script_id"].startswith("script:xfa_")]
            other_sources = [
                item["code"] for item in extracted_scripts if not item["script_id"].startswith("script:xfa_")
            ]
            try:
                import esprima

                def walk(node: Any, depth: int) -> None:
                    nonlocal total_nodes, max_depth, computed_members, loops
                    if not hasattr(node, "type"):
                        return
                    total_nodes += 1
                    max_depth = max(max_depth, depth)
                    n_type = node.type
                    if n_type in counts:
                        counts[n_type] += 1
                    if n_type in ("ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement"):
                        loops += 1
                    if n_type == "MemberExpression" and getattr(node, "computed", False):
                        computed_members += 1
                    for k, v in node.items():
                        if isinstance(v, list):
                            for item in v:
                                if hasattr(item, "type"):
                                    walk(item, depth + 1)
                        elif hasattr(v, "type"):
                            walk(v, depth + 1)

                for code in other_sources:
                    try:
                        walk(esprima.parseScript(code, tolerant=True), 1)
                    except Exception:
                        continue
                for code in xfa_sources:
                    try:
                        tree = esprima.parseScript(code, tolerant=True)
                    except Exception:
                        if "xfa_javascript_parse_error" not in xfa_anomalies:
                            xfa_anomalies.append("xfa_javascript_parse_error")
                            xfa_anomalies.sort()
                        continue
                    walk(tree, 1)
            except Exception as exc:
                raise ValueError("javascript_ast_parse_failed") from exc

        ast_values = [counts[k] for k in AST_NODE_TYPES]
        while len(ast_values) < 32:
            ast_values.append(0)
        torch = self._torch
        if self.as_numpy or torch is None:
            tokens: Any = np.asarray([[int(v) % 64 for v in ast_values[:32]]], dtype=np.int64)
        else:
            tokens = torch.tensor([[int(v) % 64 for v in ast_values[:32]]], dtype=torch.long)

        call_count = float(counts.get("CallExpression", 0))
        id_count = float(counts.get("Identifier", 0))
        stats = {
            "total_nodes": float(total_nodes),
            "max_depth": float(max_depth),
            "loops": float(loops),
            "computed_members": float(computed_members),
            "call_count": call_count,
            "id_count": id_count,
        }
        return tokens, stats, counts

    def _build_tabular_features(
        self,
        data: bytes,
        raw_tokens: dict[str, int],
        pages_count: int,
        metadata_size: float,
        raw_entropy: float,
        raw_prefix_entropy: float,
        raw_suffix_entropy: float,
        ast_stats: dict[str, float],
        records: list[dict[str, Any]] | None = None,
        extracted_scripts: list[dict[str, Any]] | None = None,
        stream_interior_tokens: dict[str, int] | None = None,
    ) -> tuple[Any, list[float | None]]:
        size_kb = len(data) / 1024.0
        ast_total = max(ast_stats["total_nodes"], 1.0)
        stream_count = float(raw_tokens.get("stream", raw_tokens.get("Stream", 0)))
        endstream_count = float(raw_tokens.get("endstream", raw_tokens.get("Endstream", 0)))
        object_count = float(raw_tokens.get("obj", raw_tokens.get("Obj", 0)))
        endobj_count = float(raw_tokens.get("endobj", raw_tokens.get("Endobj", 0)))
        structural_js_count = float(len(extracted_scripts or []))
        has_names_js = any(r.get("evidence_id") == "script:names_js" for r in (records or []))
        structural_javascript_count = structural_js_count + (1.0 if has_names_js else 0.0)
        js_full_count = max(
            float(raw_tokens.get("JavaScript", raw_tokens.get("Javascript", 0))), structural_javascript_count
        )
        js_short_count = max(float(raw_tokens.get("JS", 0)), structural_js_count)
        page_cmd_count = float(raw_tokens.get("page_command", pages_count))
        images_count = float(data.count(b"/Image"))

        measured: dict[str, float | None] = {
            "Javascript": js_full_count,
            "JS": js_short_count,
            "Stream": stream_count,
            "Endstream": endstream_count,
            "Obj": object_count,
            "Endobj": endobj_count,
            "MetadataSize": metadata_size,
            "PdfSize": size_kb,
            "Pages": float(pages_count),
            "PageNo": page_cmd_count,
            "XFA": float(raw_tokens.get("XFA", 0)),
            "OpenAction": float(raw_tokens.get("OpenAction", 0)),
            "Colors": float(raw_tokens.get("Colors", 0)),
            "Images": images_count,
            "density_stream_ratio": stream_count / max(abs(size_kb), 1.0),
            "density_obj_stream_ratio": object_count / max(abs(stream_count), 1.0),
            "density_metadata_ratio": metadata_size / max(abs(size_kb), 1.0),
            "entropy_gap": abs(raw_prefix_entropy - raw_suffix_entropy),
            "ast_complexity_per_node": ast_stats["max_depth"] / ast_total,
            "ast_call_ratio": ast_stats["call_count"] / ast_total,
            "ast_identifier_ratio": ast_stats["id_count"] / ast_total,
            "ast_computed_ratio": ast_stats["computed_members"] / ast_total,
            "legacy_observed_ast_node_count": ast_stats["total_nodes"],
            "legacy_observed_ast_max_depth": ast_stats["max_depth"],
            "legacy_observed_ast_loops": ast_stats["loops"],
            "legacy_observed_ast_computed_members": ast_stats["computed_members"],
            "raw_entropy": raw_entropy,
            "raw_prefix_entropy": raw_prefix_entropy,
            "raw_suffix_entropy": raw_suffix_entropy,
        }

        if self.contract_verified:
            byte_img_encoded, byte_img_persisted = _measure_byte_image_file_ratios(data)
            obs_records = records or []
            stream_records = [r for r in obs_records if r.get("has_stream")]
            discovered_streams = len(stream_records)
            decode_failures = sum(1 for r in stream_records if r.get("stream_decode_failed"))
            decomp_exceeded = any(bool(r.get("decompression_ratio_exceeded")) for r in stream_records)
            interior_stream_count = (stream_interior_tokens or {}).get("stream", 0)
            effective_stream_count = (
                max(endstream_count, stream_count - interior_stream_count)
                if interior_stream_count and stream_count >= endstream_count
                else stream_count
            )
            lexical_stream_mismatch = effective_stream_count != endstream_count
            is_truncated_stream = decomp_exceeded or decode_failures > 0 or lexical_stream_mismatch
            truncated_streams = decode_failures + (1 if decomp_exceeded and decode_failures == 0 else 0)
            if discovered_streams > 0:
                stream_trunc_ratio = min(1.0, float(truncated_streams) / float(discovered_streams))
            else:
                stream_trunc_ratio = 1.0 if is_truncated_stream else 0.0

            spec_flood = abs(object_count - endobj_count) > 50.0 or abs(stream_count - endstream_count) > 50.0
            excessive_graph = object_count > 10000.0 or len(obs_records) >= 200
            ast_truncated = ast_stats["total_nodes"] >= 50000.0 or ast_stats["max_depth"] >= 128.0

            measured.update(
                {
                    "byte_image_file_encoded_ratio": byte_img_encoded,
                    "byte_image_file_persisted_ratio": byte_img_persisted,
                    "stream_truncation_ratio": stream_trunc_ratio,
                    # A completed synchronous ingest has no parser timeout event.
                    "evasive_timeout_anomaly": 0.0,
                    "flag_decompression_ratio_exceeded": 1.0 if decomp_exceeded else 0.0,
                    "is_truncated_stream": 1.0 if is_truncated_stream else 0.0,
                    "flag_spec_violation_flood": 1.0 if spec_flood else 0.0,
                    "flag_excessive_object_graph": 1.0 if excessive_graph else 0.0,
                    "flag_ast_complexity_truncated": 1.0 if ast_truncated else 0.0,
                }
            )
        else:
            measured.update(
                {
                    "byte_image_file_encoded_ratio": None,
                    "byte_image_file_persisted_ratio": None,
                    "stream_truncation_ratio": None,
                    "evasive_timeout_anomaly": None,
                    "flag_decompression_ratio_exceeded": None,
                    "is_truncated_stream": None,
                    "flag_spec_violation_flood": None,
                    "flag_excessive_object_graph": None,
                    "flag_ast_complexity_truncated": None,
                }
            )

        raw_vec: list[float | None] = [measured.get(name) for name in self.feature_names]
        if any(v is None for v in raw_vec):
            return None, raw_vec
        arr = np.array([float(v) for v in raw_vec if v is not None], dtype=np.float32)
        scaled = (arr - self.scaler_mean) / self.scaler_scale
        torch = self._torch
        if self.as_numpy or torch is None:
            return scaled.astype(np.float32, copy=False)[None, :], raw_vec
        tab_tensor = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
        return tab_tensor, raw_vec
