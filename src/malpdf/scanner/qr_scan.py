from collections.abc import Iterator
from itertools import islice
from typing import Any
import zlib

import numpy as np
import pikepdf
import pymupdf as fitz
from pypdf.generic import DictionaryObject, IndirectObject, StreamObject

from malpdf.scanner.forensic import EMBEDDED_URI_PATTERN

try:
    import zxingcpp
except ImportError:
    zxingcpp = None

_MAX_IMAGE_PIXELS = 4_000_000
_MAX_IMAGES = 6


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


def _valid_flate_image(stream: pikepdf.Stream, width: int, height: int) -> bool:
    filters = stream.get("/Filter")
    if isinstance(filters, pikepdf.Array) and len(filters) == 1:
        filters = filters[0]
    if str(filters) not in {"/FlateDecode", "/Fl"}:
        return True
    try:
        inflater = zlib.decompressobj()
        limit = (width * 8 + 1) * height
        decoded = inflater.decompress(stream.read_raw_bytes(), limit + 1)
        return inflater.eof and 0 < len(decoded) <= limit
    except (zlib.error, pikepdf.PdfError):
        return False


def scan_pdf_qr_codes(
    raw_bytes: bytes,
    pdf: pikepdf.Pdf,
    *,
    pages_count: int,
    codec_anomalies: list[dict[str, Any]],
) -> dict[str, Any]:
    result = empty_qr_analysis()
    if zxingcpp is None or codec_anomalies or pages_count > 3:
        return result

    pages = list(islice(pdf.pages, min(pages_count, 3)))
    image_pages = [index for index, page in enumerate(pages) if page_has_image_xobject(page.obj)]
    if not image_pages:
        return result

    images: dict[int, bool | None] = {}
    formats = zxingcpp.BarcodeFormat.QRCode | zxingcpp.BarcodeFormat.MicroQRCode

    def decode(pix: fitz.Pixmap) -> bool:
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
        for code in codes:
            for match in EMBEDDED_URI_PATTERN.finditer(code.text):
                uri = match.group()
                if len(result["decoded_uris"]) < 16 and uri not in result["decoded_uris"]:
                    result["decoded_uris"].append(uri)
        return bool(codes)

    try:
        with fitz.open(stream=raw_bytes, filetype="pdf") as doc:
            for page_index in image_pages:
                found = False
                fallback_allowed = pages_count <= 2
                for stream in _image_xobjects(pages[page_index].obj):
                    xref = stream.objgen[0]
                    if xref in images:
                        found |= images[xref] is True
                        fallback_allowed &= images[xref] is not None
                        continue
                    if len(images) >= _MAX_IMAGES:
                        fallback_allowed = False
                        break
                    images[xref] = None
                    dimensions = _image_dimensions(stream)
                    if not xref or dimensions is None:
                        fallback_allowed = False
                        continue
                    if not _valid_flate_image(stream, *dimensions):
                        result["anomalies"].append(f"qr_image_stream_invalid:{xref}")
                        fallback_allowed = False
                        continue
                    images[xref] = False
                    if min(dimensions) < 21:
                        continue
                    try:
                        images[xref] = decode(fitz.Pixmap(doc, xref))
                    except (RuntimeError, ValueError, TypeError):
                        result["anomalies"].append(f"qr_image_decode_failed:{xref}")
                    found |= images[xref] is True
                if fallback_allowed and not found:
                    page = doc[page_index]
                    bounds = (page.rect * (110 / 72)).irect
                    if 0 < bounds.width * bounds.height <= _MAX_IMAGE_PIXELS:
                        try:
                            decode(page.get_pixmap(dpi=110, alpha=False, annots=False))
                        except (RuntimeError, ValueError, TypeError):
                            result["anomalies"].append(f"qr_page_decode_failed:{page_index}")
    except (RuntimeError, ValueError, TypeError, IndexError, OverflowError):
        result["anomalies"].append("qr_pdf_inspection_failed")
    return result
