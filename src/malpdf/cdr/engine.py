from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
import hashlib
import io
from itertools import islice
from pathlib import Path
import time
from typing import Any
import zlib

import numpy as np
import pikepdf
import pymupdf as fitz

from malpdf.scanner.forensic import EMBEDDED_URI_PATTERN, is_suspicious_uri
from malpdf.scanner.ingestion import (
    IMAGE_LURE_MIN_AREA,
    VISUAL_LURE_SUBTYPES,
    annotation_rect_area,
    inspect_pdf_codec_anomalies,
    inspect_polyglot_and_revisions,
    is_benign_catalog_navigation,
    lure_phrases_for_pages,
    page_box_area,
    qr_phishing_reasons,
    read_lure_page_text,
    visual_lure_kind,
)
from malpdf.scanner.ingestion import (
    is_navigation_destination as is_navigation_destination,
)
from malpdf.scanner.qr_scan import scan_pdf_qr_codes, zxingcpp

_JBIG2_MAGIC = b"\x97JB2\r\n\x1a\n"
_MEDIA_TRIGGER_KEYS = {"/3D", "/U3D", "/PRC"}
_REMOVED_ANNOT_SUBTYPES = {"/FileAttachment", *_MEDIA_TRIGGER_KEYS}
_MINIMAL_MEDIA_SUBTYPES = {"/Movie", "/Sound", "/Screen", "/RichMedia", *_REMOVED_ANNOT_SUBTYPES}
_REMOVED_ANNOT_LABELS = {name[1:] for name in _MINIMAL_MEDIA_SUBTYPES}
_MINIMAL_ATTACHMENT_KEYS = {"/AF", "/EF", "/EmbeddedFiles", "/Collection"}
_AA_EVENTS = {
    "/WC",
    "/WS",
    "/DS",
    "/WP",
    "/DP",
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
}
_MINIMUM_SSIM = 0.95


def _pixmap_pixels(pixmap: fitz.Pixmap) -> np.ndarray:
    return np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(pixmap.height, pixmap.width, pixmap.n)


def _compute_ssim_uint8(img_a: np.ndarray, img_b: np.ndarray) -> float:
    if img_a.shape != img_b.shape or not img_a.size:
        raise ValueError("ssim_requires_matching_nonempty_images")
    if np.array_equal(img_a, img_b):
        return 1.0

    pixel_count = img_a.shape[0] * img_a.shape[1] if img_a.ndim >= 2 else img_a.size
    stride = 4 if pixel_count >= 512 * 512 else 2 if pixel_count >= 256 * 256 else 1
    block = 8 // stride

    def luminance_blocks(image: np.ndarray) -> np.ndarray:
        image = np.atleast_2d(image)[::stride, ::stride]
        if image.ndim == 3 and image.shape[-1] >= 3:
            luminance = image[..., 0] * np.float32(0.299)
            luminance += image[..., 1] * np.float32(0.587)
            luminance += image[..., 2] * np.float32(0.114)
        else:
            luminance = image.reshape(image.shape[:2]).astype(np.float32)
        height, width = luminance.shape
        luminance = np.pad(luminance, ((0, -height % block), (0, -width % block)), mode="edge")
        return luminance.reshape((height + block - 1) // block, block, (width + block - 1) // block, block)

    a, b = luminance_blocks(img_a), luminance_blocks(img_b)
    scale = 1.0 / (block * block)
    mean_a = np.einsum("ijkl->ik", a) * scale
    mean_b = np.einsum("ijkl->ik", b) * scale
    mean_sq_a, mean_sq_b = mean_a**2, mean_b**2
    mean_product = mean_a * mean_b
    var_sum = (np.einsum("ijkl,ijkl->ik", a, a) + np.einsum("ijkl,ijkl->ik", b, b)) * scale
    var_sum -= mean_sq_a + mean_sq_b
    covariance = np.einsum("ijkl,ijkl->ik", a, b) * scale - mean_product
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    luminance = (2 * mean_product + c1) / (mean_sq_a + mean_sq_b + c1)
    structure = (2 * covariance + c2) / (np.maximum(var_sum, 0) + c2)
    return float(np.clip(np.mean(luminance * structure), -1.0, 1.0))


def _safe_navigation_action(action: Any) -> bool:
    if not is_benign_catalog_navigation(action):
        return False
    destination = action
    if isinstance(action, pikepdf.Dictionary):
        argument = "/D" if str(action["/S"]) == "/GoTo" else "/N"
        if not set(action.keys()) <= {"/Type", "/S", argument}:
            return False
        if "/Type" in action and action["/Type"] != pikepdf.Name("/Action"):
            return False
        destination = action[argument]
    return not isinstance(destination, pikepdf.Array) or destination[0].is_indirect


def _detach_navigation_groups(
    pdf: pikepdf.Pdf, allowed: set[str] | None = None
) -> Iterator[tuple[str, pikepdf.Dictionary, str, Any]]:
    root = pdf.Root
    acroform = root.get("/AcroForm")
    slots = [
        ("catalog_OpenAction", root, "/OpenAction"),
        ("catalog_AdditionalActions", root, "/AA"),
        ("acroform_AA", acroform, "/AA"),
        *((f"page_{index}_AA", page.obj, "/AA") for index, page in enumerate(pdf.pages)),
    ]
    for label, owner, key in slots:
        if (
            (allowed is not None and label not in allowed)
            or not isinstance(owner, pikepdf.Dictionary)
            or key not in owner
        ):
            continue
        value = owner[key]
        safe = (
            _safe_navigation_action(value)
            if key == "/OpenAction"
            else isinstance(value, pikepdf.Dictionary)
            and bool(value.keys())
            and set(value.keys()) <= _AA_EVENTS
            and all(
                isinstance(action, pikepdf.Dictionary) and _safe_navigation_action(action) for action in value.values()
            )
        )
        if safe:
            del owner[key]
            yield label, owner, key, value


def _active_keys_with_verified_navigation(
    pdf: pikepdf.Pdf, preserved: list[str], *, strict: bool, lure_phrases: set[str]
) -> list[str]:
    groups = list(_detach_navigation_groups(pdf, set(preserved))) if preserved else []
    try:
        if {group[0] for group in groups} != set(preserved):
            raise ValueError("cdr_preserved_navigation_verification_failed")
        return _active_keys(pdf, remove=False, strict=strict, lure_phrases=lure_phrases)
    finally:
        for _, owner, key, value in groups:
            owner[key] = value


def _visual_lure_action(
    annot: pikepdf.Dictionary, page: pikepdf.Dictionary, page_text: str | None, pages_count: int
) -> str | None:
    if page_text is None or str(annot.get("/Subtype")) not in VISUAL_LURE_SUBTYPES:
        return None
    action = annot.get("/A")
    uri = action.get("/URI") if isinstance(action, pikepdf.Dictionary) else None
    if not isinstance(uri, pikepdf.String):
        return None
    return visual_lure_kind(
        page,
        page_text,
        pages_count=pages_count,
        page_area=page_box_area(page),
        rect_area=annotation_rect_area(annot.get("/Rect")),
        uri=str(uri),
    )


def _qr_lure_annotations(
    data: bytes,
    page_texts: dict[int, str],
    pages_count: int,
    all_phrases: set[str],
    lure_phrases: set[str],
) -> set[tuple[int, int]]:
    if zxingcpp is None or pages_count > 3:
        return set()
    matches = set()
    formats = zxingcpp.BarcodeFormat.QRCode | zxingcpp.BarcodeFormat.MicroQRCode
    remaining_previews = 16
    with fitz.open(stream=data, filetype="pdf") as rendered, pikepdf.open(io.BytesIO(data)) as structure:
        for page_index, page in enumerate(structure.pages):
            annotations = page.obj.get("/Annots")
            if not isinstance(annotations, pikepdf.Array):
                continue
            render_page = rendered[page_index]
            for annot_index, annot in enumerate(islice(annotations, 64)):
                if remaining_previews == 0:
                    return matches
                if (
                    not isinstance(annot, pikepdf.Dictionary)
                    or not annot.is_indirect
                    or "/AP" not in annot
                    or str(annot.get("/Subtype")) in _MINIMAL_MEDIA_SUBTYPES
                ):
                    continue
                try:
                    preview = render_page.load_annot(annot.objgen[0])
                    bounds = (preview.rect * (110 / 72)).irect
                    if min(bounds.width, bounds.height) < 21 or bounds.width * bounds.height > 1_000_000:
                        continue
                    remaining_previews -= 1
                    pixmap = preview.get_pixmap(dpi=110, colorspace=fitz.csRGB, alpha=False)
                    if pixmap.alpha:
                        pixmap = fitz.Pixmap(pixmap, 0)
                    pixels = _pixmap_pixels(pixmap)
                    codes = zxingcpp.read_barcodes(pixels, formats=formats)
                except Exception:
                    continue
                if any(
                    qr_phishing_reasons(match.group(), page_texts, pages_count, all_phrases, lure_phrases)
                    for code in codes
                    for match in EMBEDDED_URI_PATTERN.finditer(code.text)
                ):
                    matches.add((page_index, annot_index))
    return matches


def _overlay_pages(pdf: pikepdf.Pdf) -> set[int]:
    if not 3 < len(pdf.pages) <= 10:
        return set()
    pages = set()
    for index, page in enumerate(pdf.pages):
        annotations = page.obj.get("/Annots")
        if not isinstance(annotations, pikepdf.Array):
            continue
        for annot in annotations:
            if (
                isinstance(annot, pikepdf.Dictionary)
                and str(annot.get("/Subtype")) in VISUAL_LURE_SUBTYPES
                and annotation_rect_area(annot.get("/Rect")) >= IMAGE_LURE_MIN_AREA
            ):
                action = annot.get("/A")
                if isinstance(action, pikepdf.Dictionary) and isinstance(action.get("/URI"), pikepdf.String):
                    pages.add(index)
                    break
    return pages


def _sample_original_pages(data: bytes) -> tuple[list[str] | None, dict[int, np.ndarray]]:
    samples = {}
    try:
        with fitz.open(stream=data, filetype="pdf") as doc:
            total = len(doc)
            indices = range(total) if total <= 12 else (*range(8), *range(total - 4, total))
            preview_limit = 2 if total > 8 else min(total, 4)
            texts = []
            for index in indices:
                page = doc[index]
                texts.append(page.get_text("text", flags=0))
                if index < preview_limit:
                    try:
                        pixmap = page.get_pixmap(dpi=84)
                        samples[index] = _pixmap_pixels(pixmap)
                    except (RuntimeError, ValueError):
                        continue
    except Exception:
        return None, samples
    return texts, samples


def _bounded_stream_digest(stream: pikepdf.Stream, *, max_decoded_bytes: int = 32 * 1024**2) -> str:
    try:
        raw = stream.read_raw_bytes()
    except Exception:
        return hashlib.sha256(b"").hexdigest()
    filters = stream.get("/Filter")
    if isinstance(filters, pikepdf.Array):
        filter_names = [str(item) for item in filters]
    else:
        filter_names = [str(filters)] if filters is not None else []
    parms = stream.get("/DecodeParms")
    has_predictor = False
    if isinstance(parms, pikepdf.Dictionary) and "/Predictor" in parms:
        try:
            has_predictor = int(parms.get("/Predictor", 1) or 1) != 1
        except (TypeError, ValueError, OverflowError):
            return hashlib.sha256(raw).hexdigest()
    if not filter_names:
        return hashlib.sha256(raw).hexdigest()
    if filter_names in (["/FlateDecode"], ["/Fl"]) and not has_predictor and len(raw) <= 16 * 1024**2:
        try:
            decoder = zlib.decompressobj()
            hasher = hashlib.sha256()
            total = 0
            for start in range(0, len(raw), 16 * 1024):
                chunk = decoder.decompress(raw[start : start + 16 * 1024], max(1, max_decoded_bytes - total + 1))
                total += len(chunk)
                if total > max_decoded_bytes or decoder.unconsumed_tail:
                    return hashlib.sha256(raw).hexdigest()
                hasher.update(chunk)
            tail = decoder.flush()
            total += len(tail)
            if total <= max_decoded_bytes and decoder.eof:
                hasher.update(tail)
                return hasher.hexdigest()
        except Exception:
            return hashlib.sha256(raw).hexdigest()
    if len(raw) <= 4 * 1024**2:
        try:
            decoded = stream.read_bytes()
            if len(decoded) <= max_decoded_bytes:
                return hashlib.sha256(decoded).hexdigest()
        except Exception:
            pass
    return hashlib.sha256(raw).hexdigest()


def _preserved_document_state(
    pdf: pikepdf.Pdf,
    *,
    uninspected_objgens: set[tuple[int, int]] | frozenset[tuple[int, int]] = frozenset(),
) -> list[dict[str, Any]]:
    active: set[tuple[int, int]] = set()
    memo: dict[tuple[int, int], Any] = {}
    skip_keys = {"/Length", "/Filter", "/DecodeParms", "/Parent", "/P"}

    def snapshot(value: Any) -> Any:
        if isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            identity = value.objgen
            if identity != (0, 0):
                if identity in active:
                    return {"cycle": True}
                if identity in memo:
                    return memo[identity]
                active.add(identity)
            try:
                if isinstance(value, pikepdf.Array):
                    res: Any = [snapshot(item) for item in value]
                else:
                    items: dict[str, Any] = {
                        str(key): snapshot(value[key]) for key in sorted(value.keys()) if str(key) not in skip_keys
                    }
                    if isinstance(value, pikepdf.Stream):
                        if identity in uninspected_objgens:
                            try:
                                raw_fallback = value.read_raw_bytes()
                            except Exception:
                                raw_fallback = b""
                            items["decoded_sha256"] = hashlib.sha256(raw_fallback).hexdigest()
                        else:
                            items["decoded_sha256"] = _bounded_stream_digest(value)
                    res = items
                if identity != (0, 0):
                    memo[identity] = res
                return res
            finally:
                active.discard(identity)
        return str(value)

    states = []
    for page in pdf.pages:
        state = {key: snapshot(page.obj.get(key)) for key in ("/Contents", "/Resources")}
        states.append(state)
    return states


def _walk_indirect_ids(roots: list[Any]) -> set[tuple[int, int]]:
    pending = list(roots)
    seen: set[tuple[int, int]] = set()
    for _ in range(100000):
        if not pending:
            return seen
        value = pending.pop()
        if not isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            continue
        if value.is_indirect:
            if value.objgen in seen:
                continue
            seen.add(value.objgen)
        if isinstance(value, pikepdf.Array):
            pending.extend(value)
        else:
            pending.extend(child for key, child in value.items() if key not in {"/Parent", "/P"})
    raise ValueError("cdr_resource_traversal_limit")


def _page_resource_ids(pdf: pikepdf.Pdf) -> set[tuple[int, int]]:
    return _walk_indirect_ids([page.obj.get("/Resources") for page in pdf.pages])


def _retained_document_ids(pdf: pikepdf.Pdf) -> set[tuple[int, int]]:
    return _walk_indirect_ids([pdf.Root, *(page.obj for page in pdf.pages)])


def _active_keys(
    pdf: pikepdf.Pdf,
    *,
    remove: bool,
    strict: bool = False,
    lure_phrases: set[str] | frozenset[str] = frozenset(),
) -> list[str]:
    pending = [(pdf.Root, "/Root", 0, False)] + [
        (obj, f"{obj.objgen[0]} {obj.objgen[1]} R", 0, False)
        for obj in pdf.objects
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array))
    ]
    seen = set()
    paths = []
    visited = 0
    forbidden = {
        "/OpenAction",
        "/AA",
        "/JS",
        "/JavaScript",
        "/Launch",
        "/XFA",
        *_MINIMAL_ATTACHMENT_KEYS,
    }
    media_keys = {
        *_MEDIA_TRIGGER_KEYS,
        "/RichMedia",
        "/RichMediaContent",
        "/RichMediaSettings",
        "/Movie",
        "/Sound",
        "/Rendition",
    }
    forbidden_actions = {
        "/JavaScript",
        "/Launch",
        "/ImportData",
        "/SubmitForm",
        "/GoToE",
        "/GoToR",
        "/RichMediaExecute",
        "/Movie",
        "/Sound",
        "/Rendition",
    }
    resource_ids = _page_resource_ids(pdf)
    while pending:
        value, location, depth, in_resources = pending.pop()
        if not isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            continue
        identity = value.objgen
        if identity != (0, 0) and identity in seen:
            continue
        if identity != (0, 0):
            seen.add(identity)
            in_resources = identity in resource_ids
        visited += 1
        if visited > 100000 or depth > 128:
            raise ValueError("cdr_action_traversal_limit")
        if isinstance(value, pikepdf.Array):
            pending.extend(
                (
                    item,
                    f"{location}[{index}]",
                    0 if getattr(item, "objgen", (0, 0)) != (0, 0) else depth + 1,
                    in_resources,
                )
                for index, item in enumerate(value)
            )
            continue
        uri = value.get("/URI")
        uri_text = (
            uri.decode("utf-8", errors="ignore")
            if isinstance(uri, bytes)
            else (str(uri) if isinstance(uri, pikepdf.String) else "")
        )
        suspicious_uri = bool(uri_text) and is_suspicious_uri(uri_text, lure_phrases=lure_phrases)[0]
        is_page = str(value.get("/Type")) == "/Page"
        action = str(value.get("/S") or "")
        for key in list(value.keys()):
            child = value[key]
            active = (
                key in forbidden
                or not in_resources
                and (key in media_keys or key == "/Subtype" and str(child) in _MINIMAL_MEDIA_SUBTYPES)
                or key in {"/F", "/UF"}
                and action in {"/Launch", "/GoToR"}
                or key == "/URI"
                and suspicious_uri
                or key == "/S"
                and (str(child) in forbidden_actions or str(child) == "/URI" and suspicious_uri)
            )
            navigation = (
                str(key) == "/OpenAction"
                and is_navigation_destination(child)
                and (not strict or _safe_navigation_action(child))
            )
            if active and not navigation:
                paths.append(f"{location}{key}")
                if remove:
                    del value[key]
            else:
                next_depth = 0 if getattr(child, "objgen", (0, 0)) != (0, 0) else depth + 1
                pending.append((child, f"{location}{key}", next_depth, in_resources or is_page and key == "/Resources"))
    return paths


@dataclass
class CDRAuditLog:
    sha256_before: str
    sha256_after: str
    size_before: int
    size_after: int
    removed_triggers: list[str]
    neutralized_scripts: int
    preserved_pages: int
    is_sanitized: bool
    file_name: str = ""
    sanitized_path: str = ""
    original_pages: int = 0
    sanitized_pages: int = 0
    extracted_text_chars: int = 0
    disarm_latency_ms: float = 0.0
    actions_stripped: list[str] = field(default_factory=list)
    streams_sanitized: list[str] = field(default_factory=list)
    structure_elements_removed: list[str] = field(default_factory=list)
    original_text_chars: int = 0
    size_retention_pct: float = 100.0
    object_diff_matrix: list[dict[str, Any]] = field(default_factory=list)
    page_previews: list[dict[str, Any]] = field(default_factory=list)
    trailer_state: dict[str, Any] = field(default_factory=dict)
    document_metadata: dict[str, str] = field(default_factory=dict)
    text_integrity_verified: bool | None = None
    content_streams_preserved: bool = False
    resources_preserved: bool = False
    residual_codec_anomalies: list[dict[str, Any]] = field(default_factory=list)
    residual_codec_inspection_limits: list[dict[str, Any]] = field(default_factory=list)
    quarantine_recommended: bool = False
    residual_qr_anomalies: list[str] = field(default_factory=list)
    sanitization_mode: str = "full"
    visual_similarity: dict[str, Any] = field(default_factory=dict)
    preserved_interactive_elements: list[str] = field(default_factory=list)
    cdr_evaluation_pillars: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PDFDisarmer:
    def __init__(self) -> None:
        pass

    def sanitize_bytes(
        self,
        data: bytes,
        targeted_objects: list[str] | None = None,
        file_name: str = "",
        *,
        password: str | None = None,
        mode: str = "full",
        rescore_fn: Callable[[bytes], dict[str, Any]] | None = None,
    ) -> tuple[bytes, CDRAuditLog]:
        if mode not in {"full", "minimal_cut"}:
            raise ValueError("invalid_disarm_mode")
        minimal = mode == "minimal_cut"
        sanitization_mode = "full_fallback" if minimal else "full"
        preserved_interactive: list[str] = []
        visual_lure_pages: set[int] = set()
        rescore_verified = not minimal or rescore_fn is None
        start_time = time.perf_counter()
        sha_before = hashlib.sha256(data).hexdigest()
        size_before = len(data)
        removed_triggers: list[str] = []
        neutralized_scripts = 0
        object_diff_matrix: list[dict[str, Any]] = []
        polyglot_before = inspect_polyglot_and_revisions(data)

        try:
            document = pikepdf.open(io.BytesIO(data), password=password or "")
        except pikepdf.PasswordError as exc:
            raise ValueError("cdr_password_protected_requires_quarantine") from exc
        with document as pdf:
            inspection_bytes = data
            if pdf.is_encrypted:
                unlocked = io.BytesIO()
                pdf.save(unlocked, encryption=False)
                inspection_bytes = unlocked.getvalue()
            original_uninspected: list[dict[str, Any]] = []
            original_codec_anomalies = inspect_pdf_codec_anomalies(
                pdf,
                has_jbig2_magic=_JBIG2_MAGIC in data,
                uninspected_out=original_uninspected,
            )
            orig_uninspected_objgens = {
                (int(item["object_number"]), int(item.get("generation", 0)))
                for item in original_uninspected
                if item.get("object_number") is not None
            }
            orig_uninspected_xrefs = {obj_num for obj_num, _ in orig_uninspected_objgens}
            native_render_safe = not original_codec_anomalies and not original_uninspected
            original_text, orig_pix_samples = (
                _sample_original_pages(inspection_bytes) if native_render_safe else (None, {})
            )
            original_chars = sum(map(len, original_text or []))
            original_state = _preserved_document_state(pdf, uninspected_objgens=orig_uninspected_objgens)
            preserved_pages = len(pdf.pages)
            overlay_pages = _overlay_pages(pdf)
            if pdf.is_encrypted and not original_codec_anomalies:
                with pikepdf.open(io.BytesIO(inspection_bytes)) as inspection_pdf:
                    qr_analysis = scan_pdf_qr_codes(
                        inspection_bytes,
                        inspection_pdf,
                        pages_count=preserved_pages,
                        codec_anomalies=original_codec_anomalies,
                        uninspected_xrefs=orig_uninspected_xrefs,
                    )
            else:
                qr_analysis = scan_pdf_qr_codes(
                    inspection_bytes,
                    pdf,
                    pages_count=preserved_pages,
                    codec_anomalies=original_codec_anomalies,
                    uninspected_xrefs=orig_uninspected_xrefs,
                )
            qr_pages = set(qr_analysis.get("qr_pages") or ())
            lure_texts = (
                read_lure_page_text(inspection_bytes, overlay_pages, priority_pages=qr_pages)
                if preserved_pages <= 3 or overlay_pages or qr_pages
                else {}
            )
            all_phrases, lure_phrases = lure_phrases_for_pages(lure_texts)
            qr_uri_pages = qr_analysis.get("uri_pages") or {}

            def _uri_qr_reasons(uri: str, texts_map: dict[int, str]) -> list[str]:
                u_pages = qr_uri_pages.get(uri) or []
                scoped = (
                    {p: texts_map[p] for p in u_pages if p in texts_map}
                    if preserved_pages > 3 and u_pages
                    else texts_map
                )
                u_all, u_corr = (
                    lure_phrases_for_pages(scoped) if scoped is not texts_map else (all_phrases, lure_phrases)
                )
                return qr_phishing_reasons(uri, scoped, preserved_pages, u_all, u_corr)

            has_qr_phishing = any(_uri_qr_reasons(uri, lure_texts) for uri in qr_analysis["decoded_uris"])
            qr_lures = (
                _qr_lure_annotations(inspection_bytes, lure_texts, preserved_pages, all_phrases, lure_phrases)
                if minimal and native_render_safe
                else set()
            )
            objects_before = len(pdf.objects)
            pdf_version = str(pdf.pdf_version)
            root = pdf.Root
            navigation_groups = list(_detach_navigation_groups(pdf)) if minimal else []
            annotation_actions = []

            if "/OpenAction" in root and not is_navigation_destination(root["/OpenAction"]):
                del root["/OpenAction"]
                removed_triggers.append("catalog_OpenAction")
                object_diff_matrix.append(
                    {
                        "object_id": f"{root.objgen[0]} {root.objgen[1]} R (/Root)",
                        "object_type": "Hành động tự chạy (/OpenAction)",
                        "diagnosis": "Tự chạy khi mở tệp PDF",
                        "cdr_action": "Gỡ bỏ hành động tự chạy",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    }
                )

            if "/AA" in root:
                del root["/AA"]
                removed_triggers.append("catalog_AdditionalActions")
                object_diff_matrix.append(
                    {
                        "object_id": f"{root.objgen[0]} {root.objgen[1]} R (/Root)",
                        "object_type": "Hành động tự động (/AA)",
                        "diagnosis": "Tự kích hoạt khi mở, đóng hoặc thao tác tệp",
                        "cdr_action": "Gỡ bỏ hành động tự động",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    }
                )

            if "/Names" in root and isinstance(root["/Names"], pikepdf.Dictionary):
                names = root["/Names"]
                if "/JavaScript" in names:
                    del names["/JavaScript"]
                    removed_triggers.append("catalog_Names_JavaScript")
                    neutralized_scripts += 1
                    object_diff_matrix.append(
                        {
                            "object_id": "Danh mục /Names",
                            "object_type": "Danh mục JavaScript (/Names/JavaScript)",
                            "diagnosis": "Lưu danh sách mã JavaScript trong tệp",
                            "cdr_action": "Xóa danh mục JavaScript",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )
                if "/EmbeddedFiles" in names:
                    del names["/EmbeddedFiles"]
                    removed_triggers.append("catalog_Names_EmbeddedFiles")
                    object_diff_matrix.append(
                        {
                            "object_id": "Danh mục /Names",
                            "object_type": "Tệp đính kèm (/EmbeddedFiles)",
                            "diagnosis": "Tệp nhúng bên trong tài liệu PDF",
                            "cdr_action": "Gỡ bỏ tệp đính kèm",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )

            if "/AcroForm" in root and isinstance(root["/AcroForm"], pikepdf.Dictionary):
                acro = root["/AcroForm"]
                if "/XFA" in acro:
                    del acro["/XFA"]
                    removed_triggers.append("acroform_XFA")
                    object_diff_matrix.append(
                        {
                            "object_id": "Biểu mẫu /AcroForm",
                            "object_type": "Biểu mẫu động (/XFA)",
                            "diagnosis": "Biểu mẫu XML động có thể kèm kịch bản",
                            "cdr_action": "Loại bỏ biểu mẫu XFA",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )
                if "/AA" in acro:
                    del acro["/AA"]
                    removed_triggers.append("acroform_AA")

            for page_idx, page in enumerate(pdf.pages):
                page_obj = page.obj
                if "/AA" in page_obj:
                    del page_obj["/AA"]
                    removed_triggers.append(f"page_{page_idx}_AA")
                    object_diff_matrix.append(
                        {
                            "object_id": f"Trang {page_idx + 1}",
                            "object_type": "Hành động tự động trên trang (/AA)",
                            "diagnosis": f"Tự kích hoạt khi mở hoặc chuyển trang {page_idx + 1}",
                            "cdr_action": "Gỡ bỏ hành động trên trang",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )
                if "/OpenAction" in page_obj and not is_navigation_destination(page_obj["/OpenAction"]):
                    del page_obj["/OpenAction"]
                    removed_triggers.append(f"page_{page_idx}_OpenAction")
                if "/Annots" in page_obj and isinstance(page_obj["/Annots"], pikepdf.Array):
                    annots = page_obj["/Annots"]
                    removed_indices = []
                    for a_idx, annot in enumerate(annots):
                        if not isinstance(annot, pikepdf.Dictionary):
                            continue
                        subtype = str(annot.get("/Subtype", ""))
                        if (page_idx, a_idx) in qr_lures:
                            visual_lure_pages.add(page_idx)
                            removed_indices.append(a_idx)
                            removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_qr_phishing")
                            continue
                        if subtype in _MINIMAL_MEDIA_SUBTYPES:
                            removed_indices.append(a_idx)
                            path = f"page_{page_idx}_annot_{a_idx}_{subtype[1:]}"
                            removed_triggers.append(path)
                            object_diff_matrix.append(
                                {
                                    "object_id": path,
                                    "object_type": f"Chú thích ({subtype})",
                                    "diagnosis": "Chú thích chứa tệp đính kèm hoặc nội dung đa phương tiện",
                                    "cdr_action": "Gỡ bỏ chú thích khỏi trang",
                                    "status": "Đã gỡ bỏ",
                                }
                            )
                            continue
                        if "/AA" in annot:
                            del annot["/AA"]
                            removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_AA")
                        visual_lure = _visual_lure_action(annot, page_obj, lure_texts.get(page_idx), preserved_pages)
                        if visual_lure:
                            visual_lure_pages.add(page_idx)
                            del annot["/A"]
                            path = f"page_{page_idx}_annot_{a_idx}_{visual_lure}_lure_URI"
                            removed_triggers.append(path)
                            object_diff_matrix.append(
                                {
                                    "object_id": path,
                                    "object_type": "Liên kết phủ nội dung trực quan (/URI)",
                                    "diagnosis": "Liên kết ngoài phủ vùng lớn trên trang ít văn bản",
                                    "cdr_action": "Gỡ bỏ hành động mở liên kết",
                                    "status": "Đã gỡ bỏ",
                                    "visual_impact": None,
                                }
                            )
                        elif "/A" in annot and isinstance(annot["/A"], pikepdf.Dictionary):
                            act = annot["/A"]
                            s_type = str(act.get("/S", ""))
                            if (
                                s_type in ("/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToE", "/GoToR")
                                or "/JS" in act
                                or "/JavaScript" in act
                            ):
                                del annot["/A"]
                                removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_action_{s_type or 'JS'}")
                                neutralized_scripts += 1
                                object_diff_matrix.append(
                                    {
                                        "object_id": f"Vùng tương tác trang {page_idx + 1}",
                                        "object_type": f"Vùng tương tác gắn hành động ({s_type or '/JS'})",
                                        "diagnosis": "Vùng tương tác có gắn mã hoặc lệnh thực thi",
                                        "cdr_action": "Gỡ bỏ lệnh khỏi vùng tương tác",
                                        "status": "Đã gỡ bỏ",
                                        "visual_impact": None,
                                    }
                                )
                            else:
                                annotation_actions.append((page_idx, a_idx, annot))
                    for a_idx in reversed(removed_indices):
                        del annots[a_idx]

            for obj_idx, obj in enumerate(pdf.objects, start=1):
                if not isinstance(obj, pikepdf.Dictionary):
                    continue
                if "/OpenAction" in obj and not is_navigation_destination(obj["/OpenAction"]):
                    del obj["/OpenAction"]
                    removed_triggers.append(f"obj_{obj_idx}_OpenAction")
                if "/AA" in obj:
                    del obj["/AA"]
                    removed_triggers.append(f"obj_{obj_idx}_AA")
                if "/JS" in obj:
                    del obj["/JS"]
                    removed_triggers.append(f"obj_{obj_idx}_JS_neutralized")
                    neutralized_scripts += 1
                    object_diff_matrix.append(
                        {
                            "object_id": f"{obj.objgen[0]} {obj.objgen[1]} R",
                            "object_type": "Mã JavaScript (/JS)",
                            "diagnosis": "Đoạn mã JavaScript nhúng trong đối tượng",
                            "cdr_action": "Xóa đoạn mã JavaScript",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )
                if "/JavaScript" in obj:
                    del obj["/JavaScript"]
                    removed_triggers.append(f"obj_{obj_idx}_JavaScript_neutralized")
                    neutralized_scripts += 1
                if "/Launch" in obj:
                    del obj["/Launch"]
                    removed_triggers.append(f"obj_{obj_idx}_Launch_removed")
                    object_diff_matrix.append(
                        {
                            "object_id": f"{obj.objgen[0]} {obj.objgen[1]} R",
                            "object_type": "Lệnh khởi chạy ngoài (/Launch)",
                            "diagnosis": "Lệnh khởi chạy ứng dụng ngoài trình đọc PDF (/Launch)",
                            "cdr_action": "Xóa lệnh khởi chạy (/Launch)",
                            "status": "Đã gỡ bỏ",
                            "visual_impact": None,
                        }
                    )
                s_val = str(obj.get("/S", ""))
                if s_val in ("/JavaScript", "/Launch", "/ImportData", "/SubmitForm", "/GoToE", "/GoToR"):
                    if s_val in ("/Launch", "/GoToR"):
                        for key in ("/F", "/UF"):
                            if key in obj:
                                del obj[key]
                    del obj["/S"]
                    removed_triggers.append(f"obj_{obj_idx}_action_{s_val}_removed")

            nested_removed = _active_keys(pdf, remove=True, strict=minimal, lure_phrases=lure_phrases)
            for page_idx, a_idx, annot in annotation_actions:
                action = annot.get("/A")
                if isinstance(action, pikepdf.Dictionary) and not {"/S", "/D", "/URI", "/Next"}.intersection(
                    action.keys()
                ):
                    del annot["/A"]
                    removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_empty_A")
            removed_triggers.extend(nested_removed)
            neutralized_scripts += sum(path.endswith(("/JS", "/JavaScript")) for path in nested_removed)
            object_diff_matrix.extend(
                {
                    "object_id": path,
                    "object_type": "Khóa kích hoạt lồng nhau",
                    "diagnosis": "Khóa kích hoạt nằm trong cấu trúc lồng nhau",
                    "cdr_action": "Gỡ bỏ khóa kích hoạt",
                    "status": "Đã gỡ bỏ",
                    "visual_impact": None,
                }
                for path in nested_removed
            )

            def serialize() -> bytes:
                out_buf = io.BytesIO()
                pdf.save(
                    out_buf,
                    encryption=False if pdf.is_encrypted else None,
                    compress_streams=not any(item["filter"] == "Uncompressed" for item in original_codec_anomalies),
                )
                return out_buf.getvalue()

            sanitized_bytes = None
            last_candidate = None
            if minimal and rescore_fn is not None and not has_qr_phishing and not original_codec_anomalies:
                targets = targeted_objects or []
                priorities = {name: index for index, name in reversed(list(enumerate(targets)))}
                evidence_aliases = {
                    "catalog_OpenAction": "action:open_action",
                    "catalog_AdditionalActions": "action:aa",
                }

                def priority(group: tuple[str, pikepdf.Dictionary, str, Any]) -> int:
                    label, owner, _, _ = group
                    object_id = f"{owner.objgen[0]} {owner.objgen[1]} R"
                    return min(
                        priorities.get(alias, len(targets)) for alias in (label, evidence_aliases.get(label), object_id)
                    )

                navigation_groups.sort(key=priority)
                for _, owner, key, value in navigation_groups:
                    owner[key] = value
                for prefix in range(min(len(navigation_groups) + 1, 7)):
                    remaining = [label for label, *_ in navigation_groups[prefix:]]
                    last_candidate = serialize()
                    if self._candidate_is_benign(last_candidate, remaining, lure_phrases, rescore_fn):
                        sanitized_bytes = last_candidate
                        sanitization_mode = "minimal_cut"
                        preserved_interactive = remaining
                        rescore_verified = True
                        break
                    if prefix < len(navigation_groups):
                        _, owner, key, _ = navigation_groups[prefix]
                        del owner[key]

            if sanitized_bytes is None:
                for label, owner, key, value in navigation_groups:
                    if label == "catalog_OpenAction" and is_navigation_destination(value):
                        owner[key] = value
                    elif key in owner:
                        del owner[key]
                sanitized_bytes = serialize()
                if (
                    minimal
                    and rescore_fn is not None
                    and not has_qr_phishing
                    and not original_codec_anomalies
                    and sanitized_bytes != last_candidate
                ):
                    rescore_verified = self._candidate_is_benign(sanitized_bytes, [], lure_phrases, rescore_fn)
            removed_triggers.extend(label for label, owner, key, _ in navigation_groups if key not in owner)

        polyglot_after = inspect_polyglot_and_revisions(sanitized_bytes)
        if polyglot_before["has_polyglot_payload"] and not polyglot_after["has_polyglot_payload"]:
            removed_triggers.append("polyglot_payload_stripped")
            object_diff_matrix.append(
                {
                    "object_id": "polyglot_payload_stripped",
                    "object_type": "Dữ liệu ngoài cấu trúc PDF",
                    "diagnosis": ", ".join(polyglot_before["anomalies"]),
                    "cdr_action": "Gỡ bỏ dữ liệu ngoài phần PDF khi ghi lại tệp",
                    "status": "Đã gỡ bỏ",
                }
            )
        residual_qr_anomalies = []
        with pikepdf.open(io.BytesIO(sanitized_bytes)) as verify_pdf:
            if _active_keys_with_verified_navigation(
                verify_pdf, preserved_interactive, strict=minimal, lure_phrases=lure_phrases
            ):
                raise ValueError("cdr_active_key_verification_failed")
            for index, page in enumerate(verify_pdf.pages):
                annotations = page.obj.get("/Annots")
                if not isinstance(annotations, pikepdf.Array):
                    continue
                for annot in annotations:
                    if not isinstance(annot, pikepdf.Dictionary):
                        continue
                    if str(annot.get("/Subtype")) in _MINIMAL_MEDIA_SUBTYPES or _visual_lure_action(
                        annot, page.obj, lure_texts.get(index), preserved_pages
                    ):
                        raise ValueError("cdr_active_key_verification_failed")
            residual_uninspected: list[dict[str, Any]] = []
            residual_codec_anomalies = inspect_pdf_codec_anomalies(
                verify_pdf,
                has_jbig2_magic=_JBIG2_MAGIC in sanitized_bytes,
                uninspected_out=residual_uninspected,
            )
            for anomaly in residual_codec_anomalies:
                del anomaly["stream"]
            retained_ids = _retained_document_ids(verify_pdf)
            residual_retained_limits: list[dict[str, Any]] = []
            for uninspected in residual_uninspected:
                ident = (int(uninspected.get("object_number") or 0), int(uninspected.get("generation") or 0))
                if ident in retained_ids or ident == (0, 0):
                    residual_retained_limits.append(
                        {
                            "object_number": uninspected.get("object_number"),
                            "generation": uninspected.get("generation", 0),
                            "codec": uninspected.get("codec", "STREAM"),
                            "filter": uninspected.get("filter", ""),
                            "stream_size": uninspected.get("stream_size"),
                            "reason_codes": [*uninspected.get("reason_codes", ()), "unverified_retained_resource"],
                        }
                    )
            res_uninspected_objgens = {
                (int(item["object_number"]), int(item.get("generation", 0)))
                for item in residual_uninspected
                if item.get("object_number") is not None
            }
            res_uninspected_xrefs = {obj_num for obj_num, _ in res_uninspected_objgens}
            if has_qr_phishing:
                verified_qr = scan_pdf_qr_codes(
                    sanitized_bytes,
                    verify_pdf,
                    pages_count=preserved_pages,
                    codec_anomalies=residual_codec_anomalies,
                    uninspected_xrefs=res_uninspected_xrefs,
                )
                verified_uri_pages = verified_qr.get("uri_pages") or {}

                def _verified_uri_reasons(uri: str) -> list[str]:
                    u_pages = verified_uri_pages.get(uri) or qr_uri_pages.get(uri) or []
                    scoped = (
                        {p: lure_texts[p] for p in u_pages if p in lure_texts}
                        if preserved_pages > 3 and u_pages
                        else lure_texts
                    )
                    u_all, u_corr = (
                        lure_phrases_for_pages(scoped) if scoped is not lure_texts else (all_phrases, lure_phrases)
                    )
                    return qr_phishing_reasons(uri, scoped, preserved_pages, u_all, u_corr)

                residual_qr_anomalies = [
                    f"qr_code_phishing_uri: {uri}" for uri in verified_qr["decoded_uris"] if _verified_uri_reasons(uri)
                ]
                if not residual_qr_anomalies:
                    residual_qr_anomalies.append("qr_phishing_removal_unverified")
            sanitized_state = _preserved_document_state(verify_pdf, uninspected_objgens=res_uninspected_objgens)
            sanitized_pages = len(verify_pdf.pages)
            objects_after = len(verify_pdf.objects)
            has_oa_after = "/OpenAction" in verify_pdf.Root
            navigation_preserved = has_oa_after and is_navigation_destination(verify_pdf.Root["/OpenAction"])
            has_aa_after = "/AA" in verify_pdf.Root
            has_names_js_after = "/Names" in verify_pdf.Root and "/JavaScript" in verify_pdf.Root["/Names"]
            root_reference = f"{verify_pdf.Root.objgen[0]} {verify_pdf.Root.objgen[1]} R"

        if minimal and not residual_codec_anomalies and not residual_uninspected:
            residual_qr_anomalies.extend(
                f"qr_annotation_phishing_remaining:page_{page}_annot_{annot}"
                for page, annot in sorted(
                    _qr_lure_annotations(sanitized_bytes, lure_texts, sanitized_pages, all_phrases, lure_phrases)
                )
            )
        quarantine_recommended = (
            bool(residual_codec_anomalies or residual_retained_limits or residual_qr_anomalies)
            or polyglot_after["has_polyglot_payload"]
        )
        content_preserved = [state["/Contents"] for state in original_state] == [
            state["/Contents"] for state in sanitized_state
        ]
        resources_preserved = [state["/Resources"] for state in original_state] == [
            state["/Resources"] for state in sanitized_state
        ]
        if sanitized_pages != preserved_pages or not content_preserved or not resources_preserved:
            raise ValueError("cdr_page_content_or_resources_changed")

        extracted_chars = 0
        sanitized_text: list[str] | None = None
        page_previews: list[dict[str, Any]] = []
        pixel_exact_pages = 0
        doc_metadata: dict[str, str] = {
            "title": "",
            "author": "",
            "subject": "",
            "version": f"PDF-{pdf_version}",
        }
        if not quarantine_recommended and not residual_uninspected:
            try:
                with fitz.open(stream=sanitized_bytes, filetype="pdf") as doc:
                    sanitized_text = []
                    meta = doc.metadata or {}
                    if meta.get("title"):
                        doc_metadata["title"] = str(meta["title"])
                    if meta.get("author"):
                        doc_metadata["author"] = str(meta["author"])
                    if meta.get("subject"):
                        doc_metadata["subject"] = str(meta["subject"])
                    total_clean_pages = len(doc)
                    sample_indices = (
                        list(range(total_clean_pages))
                        if total_clean_pages <= 12
                        else list(range(8)) + list(range(total_clean_pages - 4, total_clean_pages))
                    )
                    preview_limit = 2 if total_clean_pages > 8 else min(total_clean_pages, 4)
                    for p_idx in sample_indices:
                        p = doc[p_idx]
                        txt = p.get_text("text", flags=0)
                        sanitized_text.append(txt)
                        extracted_chars += len(txt)
                        if p_idx < preview_limit:
                            clean_txt = txt.strip()
                            rect = p.rect
                            img_uri = ""
                            pixel_mae = None
                            pixel_id_pct = None
                            page_ssim = None
                            try:
                                clean_pix = p.get_pixmap(dpi=84)
                                png_bytes = clean_pix.tobytes("png")
                                img_uri = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
                                clean_arr = _pixmap_pixels(clean_pix)
                                orig_arr = orig_pix_samples.get(p_idx)
                                if orig_arr is not None and orig_arr.shape == clean_arr.shape and orig_arr.size > 0:
                                    diff_mean = float(
                                        np.mean(np.abs(orig_arr.astype(np.float32) - clean_arr.astype(np.float32)))
                                    )
                                    pixel_mae = round(diff_mean, 6)
                                    matching_pixels = int(np.count_nonzero(orig_arr == clean_arr))
                                    pixel_id_pct = round(matching_pixels * 100.0 / orig_arr.size, 4)
                                    pixel_exact = matching_pixels == orig_arr.size
                                    page_ssim = 1.0 if pixel_exact else _compute_ssim_uint8(orig_arr, clean_arr)
                                    pixel_exact_pages += pixel_exact
                            except Exception:
                                img_uri = ""
                            if img_uri:
                                page_previews.append(
                                    {
                                        "page_number": p_idx + 1,
                                        "char_count": len(txt),
                                        "width_pt": round(float(rect.width), 1),
                                        "height_pt": round(float(rect.height), 1),
                                        "pixel_mean_absolute_error": pixel_mae,
                                        "pixel_identity_pct": pixel_id_pct,
                                        "ssim": round(page_ssim, 6) if page_ssim is not None else None,
                                        "image_data_uri": img_uri,
                                        "text_excerpt": clean_txt[:1200],
                                    }
                                )
            except Exception:
                extracted_chars = 0
                sanitized_text = None

        text_integrity = (
            original_text == sanitized_text
            if original_text is not None and sanitized_text is not None and original_chars > 0
            else None
        )
        compared = [preview for preview in page_previews if preview["ssim"] is not None]
        scores = [preview["ssim"] for preview in compared]
        visual_similarity = {
            "evaluated_pages": len(scores),
            "mean_ssim": round(float(np.mean(scores)), 6) if scores else None,
            "min_page_ssim": min(scores) if scores else None,
            "pixel_exact_pages": pixel_exact_pages,
        }
        if original_chars == 0 and any(
            preview["ssim"] < _MINIMUM_SSIM and preview["page_number"] - 1 not in visual_lure_pages
            for preview in compared
        ):
            raise ValueError("cdr_visual_similarity_degraded")
        if text_integrity is False:
            raise ValueError("cdr_extracted_text_changed")
        for item in object_diff_matrix:
            item["visual_impact"] = None
            item["visual_impact_status"] = "not_measured_per_object"

        sha_after = hashlib.sha256(sanitized_bytes).hexdigest()
        size_after = len(sanitized_bytes)
        size_retention_pct = round((size_after / max(size_before, 1)) * 100.0, 2)
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        actions_stripped = [
            t
            for t in removed_triggers
            if t.endswith(("/URI", "_lure_URI"))
            or any(k in t.lower() for k in ("action", "openaction", "aa", "launch"))
        ]
        streams_sanitized = [t for t in removed_triggers if "neutralized" in t or "js" in t.lower()]
        structure_elements_removed = [
            t
            for t in removed_triggers
            if any(key in t.lower() for key in ("names", "xfa", "embeddedfiles"))
            or t == "polyglot_payload_stripped"
            or t.rsplit("_", 1)[-1] in _REMOVED_ANNOT_LABELS
            or t.endswith(tuple(_MEDIA_TRIGGER_KEYS | _MINIMAL_ATTACHMENT_KEYS))
        ]

        trailer_state = {
            "pdf_version": f"PDF-{pdf_version}",
            "objects_before": objects_before,
            "objects_after": objects_after,
            "root_status": root_reference,
            "open_action_status": "Navigation destination" if navigation_preserved else "Absent after reparse",
            "additional_actions_status": "NULL (Scrubbed)" if not has_aa_after else "Present",
            "names_js_status": "Present" if has_names_js_after else "Absent after reparse",
            "residual_codec_anomalies_count": len(residual_codec_anomalies),
            "residual_codec_inspection_limits_count": len(residual_retained_limits),
            "content_streams_status": "decoded_content_and_resources_equal"
            if content_preserved and resources_preserved
            else "changed",
        }

        neutralization_verified = rescore_verified and not (
            (has_oa_after and not navigation_preserved and "catalog_OpenAction" not in preserved_interactive)
            or (has_aa_after and "catalog_AdditionalActions" not in preserved_interactive)
            or has_names_js_after
            or quarantine_recommended
        )
        audit_log = CDRAuditLog(
            sha256_before=sha_before,
            sha256_after=sha_after,
            size_before=size_before,
            size_after=size_after,
            removed_triggers=removed_triggers,
            neutralized_scripts=neutralized_scripts,
            preserved_pages=preserved_pages,
            is_sanitized=neutralization_verified,
            file_name=file_name,
            original_pages=preserved_pages,
            sanitized_pages=sanitized_pages,
            extracted_text_chars=extracted_chars,
            disarm_latency_ms=latency_ms,
            actions_stripped=actions_stripped,
            streams_sanitized=streams_sanitized,
            structure_elements_removed=structure_elements_removed,
            original_text_chars=original_chars,
            size_retention_pct=size_retention_pct,
            object_diff_matrix=object_diff_matrix,
            page_previews=page_previews,
            trailer_state=trailer_state,
            document_metadata=doc_metadata,
            text_integrity_verified=text_integrity,
            content_streams_preserved=content_preserved,
            resources_preserved=resources_preserved,
            residual_codec_anomalies=residual_codec_anomalies,
            residual_codec_inspection_limits=residual_retained_limits,
            quarantine_recommended=quarantine_recommended,
            residual_qr_anomalies=residual_qr_anomalies,
            sanitization_mode=sanitization_mode,
            visual_similarity=visual_similarity,
            preserved_interactive_elements=preserved_interactive,
            cdr_evaluation_pillars={
                "neutralization_verified": neutralization_verified,
                "functional_usability": {
                    "pages_preserved": sanitized_pages == preserved_pages,
                    "text_preserved": original_text is not None and original_text == sanitized_text,
                    "preserved_interactive_elements": preserved_interactive,
                },
                "visual_similarity_verified": (
                    bool(scores) and len(scores) == len(orig_pix_samples) and min(scores) >= _MINIMUM_SSIM
                ),
            },
        )

        return sanitized_bytes, audit_log

    @staticmethod
    def _candidate_is_benign(
        candidate: bytes,
        preserved: list[str],
        lure_phrases: set[str],
        rescore_fn: Callable[[bytes], dict[str, Any]],
    ) -> bool:
        if inspect_polyglot_and_revisions(candidate)["has_polyglot_payload"]:
            return False
        with pikepdf.open(io.BytesIO(candidate)) as pdf:
            if _active_keys_with_verified_navigation(pdf, preserved, strict=True, lure_phrases=lure_phrases):
                return False
        try:
            result = rescore_fn(candidate)
        except Exception:
            return False
        if not isinstance(result, dict):
            return False
        dossier = result.get("forensic_dossier") or {}
        heads = (result.get("threat_taxonomy") or dossier.get("threat_taxonomy") or {}).get(
            "ml_label_predictions"
        ) or ()
        return (
            result.get("verdict") == "BENIGN"
            and result.get("prediction_available", True)
            and ("is_ood" not in result or result.get("is_ood") is False)
            and not dossier.get("threat_scripts")
            and all(head.get("evidence_status") == "not_observed" for head in heads)
        )

    def sanitize_file(
        self,
        input_path: Path | str,
        output_path: Path | str | None = None,
        *,
        password: str | None = None,
    ) -> tuple[Path, CDRAuditLog]:
        in_path = Path(input_path)
        data = in_path.read_bytes()
        sanitized_bytes, audit = self.sanitize_bytes(data, file_name=in_path.name, password=password)
        if not audit.is_sanitized or audit.quarantine_recommended:
            raise ValueError("cdr_output_requires_quarantine")

        if output_path is not None:
            out_path = Path(output_path)
        else:
            stem = in_path.stem
            out_path = in_path.with_name(f"{stem}_sanitized.pdf")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(sanitized_bytes)
        audit.file_name = in_path.name
        audit.sanitized_path = str(out_path.resolve())
        return out_path, audit
