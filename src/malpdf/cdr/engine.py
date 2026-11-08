from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import io
from pathlib import Path
import time
from typing import Any

import pymupdf as fitz
import numpy as np
import pikepdf


def _preserved_document_state(pdf: pikepdf.Pdf) -> list[dict[str, Any]]:
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
                        str(key): snapshot(value[key])
                        for key in sorted(value.keys())
                        if str(key) not in skip_keys
                    }
                    if isinstance(value, pikepdf.Stream):
                        try:
                            stream_bytes = value.read_bytes()
                        except Exception:
                            try:
                                stream_bytes = value.read_raw_bytes()
                            except Exception:
                                stream_bytes = b""
                        items["decoded_sha256"] = hashlib.sha256(stream_bytes).hexdigest()
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


def _active_keys(pdf: pikepdf.Pdf, *, remove: bool) -> list[str]:
    pending = [(pdf.Root, "/Root", 0)] + [(obj, f"{obj.objgen[0]} {obj.objgen[1]} R", 0) for obj in pdf.objects]
    seen = set()
    paths = []
    visited = 0
    forbidden = {"/OpenAction", "/AA", "/JS", "/JavaScript", "/Launch", "/XFA"}
    while pending:
        value, location, depth = pending.pop()
        if not isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            continue
        identity = value.objgen
        if identity != (0, 0) and identity in seen:
            continue
        if identity != (0, 0):
            seen.add(identity)
        visited += 1
        if visited > 100000 or depth > 128:
            raise ValueError("cdr_action_traversal_limit")
        if isinstance(value, pikepdf.Array):
            pending.extend(
                (
                    item,
                    f"{location}[{index}]",
                    0 if getattr(item, "objgen", (0, 0)) != (0, 0) else depth + 1,
                )
                for index, item in enumerate(value)
            )
            continue
        for key in list(value.keys()):
            child = value[key]
            active = str(key) in forbidden or str(key) == "/S" and str(child) in {"/JavaScript", "/Launch", "/ImportData", "/SubmitForm", "/GoToE"}
            if active:
                paths.append(f"{location}{key}")
                if remove:
                    del value[key]
            else:
                next_depth = 0 if getattr(child, "objgen", (0, 0)) != (0, 0) else depth + 1
                pending.append((child, f"{location}{key}", next_depth))
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
    ) -> tuple[bytes, CDRAuditLog]:
        start_time = time.perf_counter()
        sha_before = hashlib.sha256(data).hexdigest()
        size_before = len(data)
        removed_triggers: list[str] = []
        neutralized_scripts = 0
        object_diff_matrix: list[dict[str, Any]] = []

        original_chars = 0
        original_text: list[str] | None = None
        orig_pix_samples: dict[int, np.ndarray] = {}
        try:
            with fitz.open(stream=data, filetype="pdf") as orig_doc:
                original_text = []
                total_orig_pages = len(orig_doc)
                sample_indices = (
                    list(range(total_orig_pages))
                    if total_orig_pages <= 12
                    else list(range(8)) + list(range(total_orig_pages - 4, total_orig_pages))
                )
                preview_limit = 2 if total_orig_pages > 8 else min(total_orig_pages, 4)
                for p_idx in sample_indices:
                    p = orig_doc[p_idx]
                    text = p.get_text("text", flags=0)
                    original_text.append(text)
                    original_chars += len(text)
                    if p_idx < preview_limit:
                        pix = p.get_pixmap(dpi=84)
                        orig_pix_samples[p_idx] = np.frombuffer(pix.samples, dtype=np.uint8).copy()
        except Exception:
            original_chars = 0
            original_text = None

        with pikepdf.open(io.BytesIO(data)) as pdf:
            original_state = _preserved_document_state(pdf)
            preserved_pages = len(pdf.pages)
            objects_before = len(pdf.objects)
            pdf_version = str(pdf.pdf_version)
            root = pdf.Root

            if "/OpenAction" in root:
                del root["/OpenAction"]
                removed_triggers.append("catalog_OpenAction")
                object_diff_matrix.append({
                    "object_id": f"{root.objgen[0]} {root.objgen[1]} R (/Root)",
                    "object_type": "Lệnh tự chạy (/OpenAction)",
                    "diagnosis": "Tự động chạy ngay khi mở tệp PDF",
                    "cdr_action": "Gỡ bỏ lệnh tự động mở",
                    "status": "Đã gỡ bỏ",
                    "visual_impact": None,
                })

            if "/AA" in root:
                del root["/AA"]
                removed_triggers.append("catalog_AdditionalActions")
                object_diff_matrix.append({
                    "object_id": f"{root.objgen[0]} {root.objgen[1]} R (/Root)",
                    "object_type": "Hành động phụ (/AA)",
                    "diagnosis": "Tự kích hoạt theo thao tác mở/đóng tài liệu",
                    "cdr_action": "Gỡ bỏ hành động tự động",
                    "status": "Đã gỡ bỏ",
                    "visual_impact": None,
                })

            if "/Names" in root and isinstance(root["/Names"], pikepdf.Dictionary):
                names = root["/Names"]
                if "/JavaScript" in names:
                    del names["/JavaScript"]
                    removed_triggers.append("catalog_Names_JavaScript")
                    neutralized_scripts += 1
                    object_diff_matrix.append({
                        "object_id": "Danh mục /Names",
                        "object_type": "Danh sách mã JavaScript",
                        "diagnosis": "Nơi lưu trữ kịch bản chạy ngầm trong tài liệu",
                        "cdr_action": "Xóa danh mục kịch bản",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })
                if "/EmbeddedFiles" in names:
                    del names["/EmbeddedFiles"]
                    removed_triggers.append("catalog_Names_EmbeddedFiles")
                    object_diff_matrix.append({
                        "object_id": "Danh mục /Names",
                        "object_type": "Tệp đính kèm ẩn (/EmbeddedFiles)",
                        "diagnosis": "Tệp lạ được giấu bên trong tài liệu PDF",
                        "cdr_action": "Loại bỏ tệp đính kèm ẩn",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })

            if "/AcroForm" in root and isinstance(root["/AcroForm"], pikepdf.Dictionary):
                acro = root["/AcroForm"]
                if "/XFA" in acro:
                    del acro["/XFA"]
                    removed_triggers.append("acroform_XFA")
                    object_diff_matrix.append({
                        "object_id": "Biểu mẫu /AcroForm",
                        "object_type": "Biểu mẫu động (/XFA)",
                        "diagnosis": "Biểu mẫu động có khả năng chứa mã kịch bản",
                        "cdr_action": "Loại bỏ biểu mẫu động",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })
                if "/AA" in acro:
                    del acro["/AA"]
                    removed_triggers.append("acroform_AA")

            for page_idx, page in enumerate(pdf.pages):
                page_obj = page.obj
                if "/AA" in page_obj:
                    del page_obj["/AA"]
                    removed_triggers.append(f"page_{page_idx}_AA")
                    object_diff_matrix.append({
                        "object_id": f"Trang {page_idx + 1}",
                        "object_type": "Hành động khi lật trang (/AA)",
                        "diagnosis": f"Tự kích hoạt khi người đọc xem trang {page_idx + 1}",
                        "cdr_action": "Gỡ bỏ lệnh trên trang",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })
                if "/OpenAction" in page_obj:
                    del page_obj["/OpenAction"]
                    removed_triggers.append(f"page_{page_idx}_OpenAction")
                if "/Annots" in page_obj and isinstance(page_obj["/Annots"], pikepdf.Array):
                    annots = page_obj["/Annots"]
                    for a_idx, annot in enumerate(annots):
                        if not isinstance(annot, pikepdf.Dictionary):
                            continue
                        if "/AA" in annot:
                            del annot["/AA"]
                            removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_AA")
                        if "/A" in annot and isinstance(annot["/A"], pikepdf.Dictionary):
                            act = annot["/A"]
                            s_type = str(act.get("/S", ""))
                            if (
                                s_type in ("/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToE")
                                or "/JS" in act
                                or "/JavaScript" in act
                            ):
                                del annot["/A"]
                                removed_triggers.append(f"page_{page_idx}_annot_{a_idx}_action_{s_type or 'JS'}")
                                neutralized_scripts += 1
                                object_diff_matrix.append({
                                    "object_id": f"Vùng tương tác trang {page_idx + 1}",
                                    "object_type": f"Nút bấm / liên kết ({s_type or '/JS'})",
                                    "diagnosis": "Vùng nhấn trên trang có gắn mã hoặc lệnh chạy ngầm",
                                    "cdr_action": "Gỡ bỏ lệnh khỏi vùng nhấn",
                                    "status": "Đã gỡ bỏ",
                                    "visual_impact": None,
                                })

            for obj_idx, obj in enumerate(pdf.objects, start=1):
                if not isinstance(obj, pikepdf.Dictionary):
                    continue
                if "/OpenAction" in obj:
                    del obj["/OpenAction"]
                    removed_triggers.append(f"obj_{obj_idx}_OpenAction")
                if "/AA" in obj:
                    del obj["/AA"]
                    removed_triggers.append(f"obj_{obj_idx}_AA")
                if "/JS" in obj:
                    del obj["/JS"]
                    removed_triggers.append(f"obj_{obj_idx}_JS_neutralized")
                    neutralized_scripts += 1
                    object_diff_matrix.append({
                        "object_id": f"{obj.objgen[0]} {obj.objgen[1]} R",
                        "object_type": "Đoạn mã ẩn (/JS)",
                        "diagnosis": "Nội dung mã JavaScript nhúng bên trong tệp",
                        "cdr_action": "Xóa bỏ đoạn mã JavaScript",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })
                if "/JavaScript" in obj:
                    del obj["/JavaScript"]
                    removed_triggers.append(f"obj_{obj_idx}_JavaScript_neutralized")
                    neutralized_scripts += 1
                if "/Launch" in obj:
                    del obj["/Launch"]
                    removed_triggers.append(f"obj_{obj_idx}_Launch_removed")
                    object_diff_matrix.append({
                        "object_id": f"{obj.objgen[0]} {obj.objgen[1]} R",
                        "object_type": "Lệnh hệ thống (/Launch)",
                        "diagnosis": "Lệnh tự mở phần mềm bên ngoài máy tính",
                        "cdr_action": "Xóa bỏ lệnh hệ thống",
                        "status": "Đã gỡ bỏ",
                        "visual_impact": None,
                    })
                s_val = str(obj.get("/S", ""))
                if s_val in ("/JavaScript", "/Launch", "/ImportData", "/SubmitForm", "/GoToE"):
                    if "/F" in obj and s_val == "/Launch":
                        del obj["/F"]
                    del obj["/S"]
                    removed_triggers.append(f"obj_{obj_idx}_action_{s_val}_removed")

            nested_removed = _active_keys(pdf, remove=True)
            removed_triggers.extend(nested_removed)
            neutralized_scripts += sum(path.endswith(("/JS", "/JavaScript")) for path in nested_removed)
            object_diff_matrix.extend({
                "object_id": path, "object_type": "Lệnh lồng bên trong",
                "diagnosis": "Khóa kích hoạt ẩn nằm sâu trong cấu trúc tệp", "cdr_action": "Gỡ bỏ khóa kích hoạt",
                "status": "Đã gỡ bỏ", "visual_impact": None,
            } for path in nested_removed)
            out_buf = io.BytesIO()
            pdf.save(out_buf)
            sanitized_bytes = out_buf.getvalue()

        with pikepdf.open(io.BytesIO(sanitized_bytes)) as verify_pdf:
            if _active_keys(verify_pdf, remove=False):
                raise ValueError("cdr_active_key_verification_failed")
            sanitized_state = _preserved_document_state(verify_pdf)
            sanitized_pages = len(verify_pdf.pages)
            objects_after = len(verify_pdf.objects)
            has_oa_after = "/OpenAction" in verify_pdf.Root
            has_aa_after = "/AA" in verify_pdf.Root
            has_names_js_after = "/Names" in verify_pdf.Root and "/JavaScript" in verify_pdf.Root["/Names"]
            root_reference = f"{verify_pdf.Root.objgen[0]} {verify_pdf.Root.objgen[1]} R"

        content_preserved = [state["/Contents"] for state in original_state] == [state["/Contents"] for state in sanitized_state]
        resources_preserved = [state["/Resources"] for state in original_state] == [state["/Resources"] for state in sanitized_state]
        if sanitized_pages != preserved_pages or not content_preserved or not resources_preserved:
            raise ValueError("cdr_page_content_or_resources_changed")

        extracted_chars = 0
        sanitized_text: list[str] | None = None
        page_previews: list[dict[str, Any]] = []
        doc_metadata: dict[str, str] = {
            "title": "",
            "author": "",
            "subject": "",
            "version": f"PDF-{pdf_version}",
        }
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
                        try:
                            clean_pix = p.get_pixmap(dpi=84)
                            png_bytes = clean_pix.tobytes("png")
                            img_uri = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
                            clean_arr = np.frombuffer(clean_pix.samples, dtype=np.uint8)
                            orig_arr = orig_pix_samples.get(p_idx)
                            if orig_arr is not None and orig_arr.shape == clean_arr.shape and orig_arr.size > 0:
                                diff_mean = float(np.mean(np.abs(orig_arr.astype(np.float32) - clean_arr.astype(np.float32))))
                                pixel_mae = round(diff_mean, 6)
                                pixel_id_pct = round(float(np.mean(orig_arr == clean_arr)) * 100.0, 4)
                        except Exception:
                            img_uri = ""
                        if img_uri:
                            page_previews.append({
                                "page_number": p_idx + 1,
                                "char_count": len(txt),
                                "width_pt": round(float(rect.width), 1),
                                "height_pt": round(float(rect.height), 1),
                                "pixel_mean_absolute_error": pixel_mae,
                                "pixel_identity_pct": pixel_id_pct,
                                "image_data_uri": img_uri,
                                "text_excerpt": clean_txt[:1200],
                            })
        except Exception:
            extracted_chars = 0
            sanitized_text = None

        text_integrity = original_text == sanitized_text if original_text is not None and sanitized_text is not None and original_chars > 0 else None
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
            t for t in removed_triggers if any(k in t.lower() for k in ("action", "openaction", "aa", "launch"))
        ]
        streams_sanitized = [
            t for t in removed_triggers if "neutralized" in t or "js" in t.lower()
        ]
        structure_elements_removed = [
            t for t in removed_triggers if "names" in t.lower() or "xfa" in t.lower() or "embeddedfiles" in t.lower()
        ]

        trailer_state = {
            "pdf_version": f"PDF-{pdf_version}",
            "objects_before": objects_before,
            "objects_after": objects_after,
            "root_status": root_reference,
            "open_action_status": "NULL (Scrubbed)" if not has_oa_after else "Present",
            "additional_actions_status": "NULL (Scrubbed)" if not has_aa_after else "Present",
            "names_js_status": "Present" if has_names_js_after else "Absent after reparse",
            "content_streams_status": "decoded_content_and_resources_equal" if content_preserved and resources_preserved else "changed",
        }

        audit_log = CDRAuditLog(
            sha256_before=sha_before,
            sha256_after=sha_after,
            size_before=size_before,
            size_after=size_after,
            removed_triggers=removed_triggers,
            neutralized_scripts=neutralized_scripts,
            preserved_pages=preserved_pages,
            is_sanitized=not (has_oa_after or has_aa_after or has_names_js_after),
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
        )

        return sanitized_bytes, audit_log

    def sanitize_file(
        self,
        input_path: Path | str,
        output_path: Path | str | None = None,
    ) -> tuple[Path, CDRAuditLog]:
        in_path = Path(input_path)
        data = in_path.read_bytes()
        sanitized_bytes, audit = self.sanitize_bytes(data, file_name=in_path.name)

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
