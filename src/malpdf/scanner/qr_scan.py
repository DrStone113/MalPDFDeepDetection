from collections.abc import Iterator
from itertools import islice
from typing import Any
import zlib

import numpy as np
import pikepdf
import pymupdf as fitz
from pypdf.generic import DictionaryObject, IndirectObject, StreamObject

from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters
from malpdf.scanner.forensic import EMBEDDED_URI_PATTERN

try:
    import zxingcpp
except ImportError:
    zxingcpp = None

_MAX_IMAGE_PIXELS = 4_000_000
_MAX_IMAGES = 8
_MAX_QR_PAGES = 6


def _image_xobjects(owner: Any, depth: int = 0, seen: dict[tuple[int, int], int] | None = None) -> Iterator[Any]:
    if depth > 4 or not isinstance(owner, (DictionaryObject, pikepdf.Dictionary, pikepdf.Stream)):
        return
    seen = {} if seen is None else seen
    resources = owner.get("/Resources")
    if isinstance(resources, IndirectObject):
        resources = resources.get_object()
    if not isinstance(resources, (DictionaryObject, pikepdf.Dictionary)):
        return
    objects = resources.get("/XObject")
    if isinstance(objects, IndirectObject):
        objects = objects.get_object()
    if not isinstance(objects, (DictionaryObject, pikepdf.Dictionary)):
        return
    for name in islice(objects.keys(), 64):
        stream = objects[name]
        if not isinstance(stream, (StreamObject, pikepdf.Stream)):
            continue
        subtype = str(stream.get("/Subtype"))
        if subtype == "/Image":
            yield stream
        elif subtype == "/Form":
            ref = getattr(stream, "indirect_reference", None)
            identity = (ref.idnum, ref.generation) if ref is not None else getattr(stream, "objgen", (0, 0))
            if identity != (0, 0):
                if seen.get(identity, 5) <= depth:
                    continue
                seen[identity] = depth
            yield from _image_xobjects(stream, depth + 1, seen)


def page_has_image_xobject(page: Any) -> bool:
    return next(_image_xobjects(page), None) is not None


def empty_qr_analysis() -> dict[str, Any]:
    return {
        "scanner_available": zxingcpp is not None,
        "images_scanned": 0,
        "qr_codes_found": 0,
        "decoded_uris": [],
        "qr_pages": [],
        "uri_pages": {},
        "coverage_complete": True,
        "anomalies": [],
    }


def _image_dimensions(stream: pikepdf.Stream) -> tuple[int, int] | None:
    try:
        w, h, length = (int(stream.get(key, 0)) for key in ("/Width", "/Height", "/Length"))
    except (ValueError, TypeError, OverflowError):
        return None
    if 0 < w <= 2500 and 0 < h <= 2500 and w * h <= _MAX_IMAGE_PIXELS and 0 < length <= 8 * 1024 * 1024:
        return w, h
    return None


_NATIVE_IMAGE_CODECS = frozenset({"/DCTDecode", "/DCT", "/JPXDecode", "/JBIG2Decode", "/CCITTFaxDecode", "/CCF"})


def _pikepdf_parms(parms: Any, count: int) -> dict[str, Any] | list[dict[str, Any] | None] | None:
    def one(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, pikepdf.Dictionary):
            return None
        out: dict[str, Any] = {}
        for k, v in item.items():
            try:
                out[str(k)] = bool(v) if isinstance(v, bool) else int(v)
            except (TypeError, ValueError, OverflowError):
                out[str(k)] = str(v)
        return out

    if isinstance(parms, pikepdf.Dictionary):
        return one(parms)
    if isinstance(parms, pikepdf.Array):
        return [one(item) for item in islice(parms, count)]
    return None


def _validate_qr_image_stream(stream: pikepdf.Stream, width: int, height: int) -> str:
    raw_filters = stream.get("/Filter")
    if raw_filters is None:
        return "ok"
    filter_names = [str(item) for item in raw_filters] if isinstance(raw_filters, pikepdf.Array) else [str(raw_filters)]
    if not filter_names:
        return "ok"
    limit = max((width * 8 + 1) * height, 65536)
    if len(filter_names) == 1 and filter_names[0] in _NATIVE_IMAGE_CODECS:
        return "ok"
    if len(filter_names) == 1 and filter_names[0] in {"/FlateDecode", "/Fl"}:
        try:
            inflater = zlib.decompressobj()
            decoded = inflater.decompress(stream.read_raw_bytes(), limit + 1)
            if inflater.unconsumed_tail or len(decoded) > limit:
                return "quota"
            return "ok" if inflater.eof and len(decoded) > 0 else "invalid"
        except (zlib.error, pikepdf.PdfError):
            return "invalid"
    wrappers = filter_names[:-1] if filter_names[-1] in _NATIVE_IMAGE_CODECS else filter_names
    try:
        raw = stream.read_raw_bytes()
    except pikepdf.PdfError:
        return "invalid"
    res = decode_filters(
        raw,
        wrappers,
        decode_parms=_pikepdf_parms(stream.get("/DecodeParms"), len(wrappers)),
        limits=FilterLimits(
            max_input_bytes=8 * 1024 * 1024,
            max_stage_bytes=min(limit, 8 * 1024 * 1024),
            max_total_bytes=min(limit, 8 * 1024 * 1024),
            max_filters=8,
            max_expansion_ratio=500,
        ),
        budget=DecodeBudget(min(limit, 8 * 1024 * 1024)),
    )
    status = res.metadata["status"]
    if status == "resource_limit":
        return "quota"
    return "invalid" if status == "decode_error" else "ok"


def scan_pdf_qr_codes(
    raw_bytes: bytes,
    pdf: pikepdf.Pdf,
    *,
    pages_count: int,
    codec_anomalies: list[dict[str, Any]],
    uninspected_xrefs: set[int] | frozenset[int] = frozenset(),
) -> dict[str, Any]:
    result = empty_qr_analysis()
    if zxingcpp is None or codec_anomalies or pages_count <= 0:
        result["coverage_complete"] = pages_count <= 0
        return result

    scan_cap = min(pages_count, 256)
    scanned_pages = list(islice(pdf.pages, scan_cap))
    all_image_pages = [index for index, page in enumerate(scanned_pages) if page_has_image_xobject(page.obj)]
    if not all_image_pages:
        result["coverage_complete"] = pages_count <= 256
        return result
    priorities = [index for index in (0, 1, pages_count - 1) if index < scan_cap and index in all_image_pages]
    image_pages = list(dict.fromkeys([*priorities, *all_image_pages]))[:_MAX_QR_PAGES]

    images: dict[int, bool | None] = {}
    xref_uris: dict[int, list[str]] = {}
    hit_image_cap = hit_uninspected = False
    formats = zxingcpp.BarcodeFormat.QRCode | zxingcpp.BarcodeFormat.MicroQRCode

    def _record_qr_page(page_idx: int) -> None:
        if page_idx not in result["qr_pages"]:
            result["qr_pages"].append(page_idx)
            result["qr_pages"].sort()

    def _record_uri_page(uri: str, page_idx: int) -> None:
        _record_qr_page(page_idx)
        if uri not in result["uri_pages"]:
            if len(result["decoded_uris"]) >= 16:
                return
            result["decoded_uris"].append(uri)
        pages = result["uri_pages"].setdefault(uri, [])
        if page_idx not in pages:
            pages.append(page_idx)
            pages.sort()

    def decode(pix: fitz.Pixmap, page_idx: int) -> tuple[bool, list[str]]:
        if not 0 < pix.width * pix.height <= _MAX_IMAGE_PIXELS:
            raise ValueError("qr_pixmap_exceeds_limits")
        if pix.n > 3 or pix.alpha:
            pix = fitz.Pixmap(fitz.csRGB, pix)
            if pix.alpha:
                pix = fitz.Pixmap(pix, 0)
        shape = (pix.height, pix.width) if pix.n == 1 else (pix.height, pix.width, pix.n)
        pixels = np.frombuffer(pix.samples, dtype=np.uint8).reshape(shape)
        result["images_scanned"] += 1
        codes = zxingcpp.read_barcodes(pixels, formats=formats)
        result["qr_codes_found"] += len(codes)
        if codes:
            _record_qr_page(page_idx)
        uris = []
        for code in codes:
            for match in EMBEDDED_URI_PATTERN.finditer(code.text):
                uri = match.group()
                _record_uri_page(uri, page_idx)
                if uri in result["uri_pages"] and uri not in uris:
                    uris.append(uri)
        return bool(codes), uris

    try:
        with fitz.open(stream=raw_bytes, filetype="pdf") as doc:
            for page_index in image_pages:
                found = False
                fallback_allowed = True
                for stream in _image_xobjects(scanned_pages[page_index].obj):
                    xref = stream.objgen[0]
                    if xref in uninspected_xrefs:
                        fallback_allowed = False
                        hit_uninspected = True
                        continue
                    if xref in images:
                        if images[xref]:
                            found = True
                            _record_qr_page(page_index)
                            for uri in xref_uris[xref]:
                                _record_uri_page(uri, page_index)
                        fallback_allowed &= images[xref] is not None
                        continue
                    if len(images) >= _MAX_IMAGES:
                        fallback_allowed = False
                        hit_image_cap = True
                        continue
                    images[xref] = None
                    dimensions = _image_dimensions(stream)
                    if not xref or dimensions is None:
                        fallback_allowed = False
                        continue
                    stream_check = _validate_qr_image_stream(stream, *dimensions)
                    if stream_check == "quota":
                        fallback_allowed = False
                        hit_uninspected = True
                        continue
                    if stream_check != "ok":
                        result["anomalies"].append(f"qr_image_stream_invalid:{xref}")
                        fallback_allowed = False
                        continue
                    images[xref] = False
                    if min(dimensions) < 21:
                        continue
                    try:
                        images[xref], xref_uris[xref] = decode(fitz.Pixmap(doc, xref), page_index)
                    except (RuntimeError, ValueError, TypeError):
                        result["anomalies"].append(f"qr_image_decode_failed:{xref}")
                    found |= images[xref] is True
                if fallback_allowed and not found and pages_count <= 2 and not uninspected_xrefs:
                    page = doc[page_index]
                    bounds = (page.rect * (110 / 72)).irect
                    if 0 < bounds.width * bounds.height <= _MAX_IMAGE_PIXELS:
                        try:
                            decode(page.get_pixmap(dpi=110, alpha=False, annots=False), page_index)
                        except (RuntimeError, ValueError, TypeError):
                            result["anomalies"].append(f"qr_page_decode_failed:{page_index}")
    except (RuntimeError, ValueError, TypeError, IndexError, OverflowError):
        result["anomalies"].append("qr_pdf_inspection_failed")
    result["coverage_complete"] = (
        pages_count <= 256 and len(all_image_pages) <= _MAX_QR_PAGES and not hit_image_cap and not hit_uninspected
    )
    return result
