from __future__ import annotations

from collections import Counter
import hashlib
import io
import json
import math
from pathlib import Path
import re
import time
from typing import Any

import numpy as np
import pypdf
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject
try:
    import torch
except ImportError:
    torch = None

from malpdf.extraction.byte_images import ByteImageLimits, _tile_order, encode_tile
from malpdf.static.raw_scan import scan_raw_pdf_tokens

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

DEFAULT_SCALER_PATH = Path(__file__).resolve().parents[3] / "configs" / "tabular_scaler.json"
VERIFIED_CONTRACT_VERSION = "pdf-graph-projection-v2"


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


def _index_physical_object_spans(raw_pdf_bytes: bytes) -> tuple[dict[tuple[int, int], int], dict[tuple[int, int], tuple[int, int]]]:
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
        if isinstance(raw_stream_buf, (bytes, bytearray)):
            raw_stream_bytes = len(raw_stream_buf)
        if isinstance(raw_stream_buf, (bytes, bytearray)) and len(raw_stream_buf) > 65536:
            raw_obj_bytes = bytes(raw_stream_buf)
        else:
            try:
                decoded_buf = resolved.get_data()
                raw_obj_bytes = decoded_buf if isinstance(decoded_buf, bytes) else bytes(decoded_buf)
                decoded_stream_bytes = len(raw_obj_bytes)
                if raw_stream_bytes is None:
                    raw_stream_bytes = decoded_stream_bytes
                elif raw_stream_bytes > 0 and (decoded_stream_bytes / float(raw_stream_bytes)) > 100.0:
                    decompression_ratio_exceeded = True
                if decoded_stream_bytes > 4 * 1024 * 1024:
                    decompression_ratio_exceeded = True
            except Exception:
                stream_decode_failed = True
                raw_obj_bytes = bytes(raw_stream_buf) if isinstance(raw_stream_buf, (bytes, bytearray)) else b""
        decoded_text = raw_obj_bytes[:1200].decode("utf-8", errors="replace").strip()
        printable_ratio = sum(1 for c in decoded_text[:200] if c.isprintable() or c in "\r\n\t") / max(len(decoded_text[:200]), 1)
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
            content_preview = f"<< {dict_keys} >>\n[Binary Stream Payload: {len(raw_obj_bytes)} bytes, Filter: {filter_name}]"
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
            marker = re.search(rb"(?m)(?:^|[\r\n])(" + str(obj_num).encode() + rb"\s+" + str(generation).encode() + rb"\s+obj\b)", raw_pdf_bytes)
            if marker is not None:
                offset_pos = marker.start(1)
                end_m = re.search(rb"\bendobj\b", raw_pdf_bytes[marker.end(1) :])
                if end_m is not None:
                    phys_span_bytes = (marker.end(1) + end_m.end(0)) - offset_pos
        if span_map is not None and (obj_num, generation) in span_map:
            s_pos, e_pos = span_map[(obj_num, generation)]
            phys_span_bytes = e_pos - s_pos

    pdf_window = raw_pdf_bytes[offset_pos : offset_pos + 64] if offset_pos is not None else b""
    hex_dump = _build_hex_dump_lines(pdf_window, base_offset=offset_pos or 0, max_lines=4)
    actual_size = float(phys_span_bytes) if phys_span_bytes is not None and phys_span_bytes > 0 else float(len(raw_obj_bytes))
    entropy_sample = raw_obj_bytes[:65536] if raw_obj_bytes else pdf_window
    entropy_val = round(_shannon_entropy(entropy_sample), 4)

    return {
        "obj_ref_str": obj_ref_str,
        "obj_num": obj_num,
        "generation": generation,
        "filter": filter_name,
        "size_bytes": actual_size,
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
    unique_png_bytes = 0
    seen_png_digests: set[str] = set()
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
        block = data[start:end]
        png, _ = encode_tile(block, width=limits.width, rows=limits.rows_per_tile)
        digest = hashlib.sha256(png).hexdigest()
        if digest not in seen_png_digests:
            if unique_png_bytes + len(png) <= limits.max_png_bytes:
                unique_png_bytes += len(png)
            seen_png_digests.add(digest)
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
    ) -> None:
        if node_in_dim not in (19, 23):
            raise ValueError("unsupported_node_in_dim")
        self.node_in_dim: int = int(node_in_dim)
        self.as_numpy: bool = bool(as_numpy or torch is None)
        path = Path(scaler_path) if scaler_path is not None else DEFAULT_SCALER_PATH
        with path.open("r", encoding="utf-8") as stream:
            scaler_data = json.load(stream)
        self.contract_version: str | None = scaler_data.get("contract_version") or scaler_data.get("fitted_on")
        self.contract_verified: bool = bool(self.contract_version and VERIFIED_CONTRACT_VERSION in str(self.contract_version))
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

    def read_bytes(self, source: str | Path | bytes, max_bytes: int = 32 * 1024 * 1024) -> tuple[bytes, str]:
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

    def ingest(self, source: str | Path | bytes, max_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
        t0 = time.perf_counter()
        data, sha256 = self.read_bytes(source, max_bytes=max_bytes)
        if b"%PDF-" not in data[:1024]:
            raise ValueError("not_a_pdf_missing_header")
        pdf_size = len(data)
        raw_tokens = scan_raw_pdf_tokens(data)
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
        reader = None
        pages_count = 0
        metadata_size = 0.0

        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            pages_count = len(reader.pages)
            if reader.metadata:
                metadata_bytes = str(reader.metadata).encode("utf-8", errors="ignore")
                metadata_size = float(len(metadata_bytes))
            trailer = getattr(reader, "trailer", None) or {}
            root = trailer.get("/Root")
            if isinstance(root, IndirectObject):
                root = root.get_object()
            if isinstance(root, DictionaryObject) and "/Metadata" in root:
                meta_stream = root.get("/Metadata")
                if isinstance(meta_stream, IndirectObject):
                    meta_stream = meta_stream.get_object()
                if hasattr(meta_stream, "get_data"):
                    metadata_size = max(float(len(meta_stream.get_data())), metadata_size)
        except Exception as exc:
            raise ValueError("pdf_parse_failed") from exc

        if reader is not None:
            self._extract_graph_and_scripts(reader, data, records, raw_edges, extracted_scripts)

        graph_data = self._build_hetero_graph(records, raw_edges)
        ast_tokens, ast_stats, ast_node_counts = self._extract_ast_stream(extracted_scripts)
        elapsed_sec = time.perf_counter() - t0
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
            elapsed_sec=elapsed_sec,
        )

        return {
            "sha256": sha256,
            "size_bytes": pdf_size,
            "pdf_version": pdf_version,
            "pages_count": pages_count,
            "raw_entropy": round(raw_entropy, 4),
            "node_features": graph_data["node_features"],
            "node_types": graph_data["node_types"],
            "edge_index": graph_data["edge_index"],
            "edge_rel": graph_data["edge_rel"],
            "batch": graph_data["batch"],
            "ast_tokens": ast_tokens,
            "ast_stats": ast_stats,
            "ast_node_counts": ast_node_counts,
            "tab_features": tab_features,
            "raw_feature_vec": raw_feature_vec,
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
        }

    def _extract_graph_and_scripts(
        self,
        reader: PdfReader,
        raw_pdf_bytes: bytes,
        records: list[dict[str, Any]],
        raw_edges: list[dict[str, Any]],
        extracted_scripts: list[dict[str, Any]],
    ) -> None:
        visited_ids: set[str] = set()
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
        ) -> None:
            if evidence_id in visited_ids or len(records) >= 200:
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
            )
            final_size = size if size is not None and meta["phys_span_bytes"] is None else meta["size_bytes"]
            records.append({
                "evidence_id": evidence_id,
                "kind": kind,
                "size_bytes": final_size,
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
            })

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

            for p_idx, page in enumerate(reader.pages):
                if len(records) >= 200:
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
                        if len(records) >= 200:
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
                                    act_type = str(a_act.get("/S", ""))
                                is_threat_act = act_type in ("/JavaScript", "/Launch", "/ImportData")
                                register_node(
                                    act_id,
                                    "action",
                                    has_stream=False,
                                    obj_ref=a_act,
                                    is_threat_trigger=is_threat_act,
                                    invoker=f"/Annot[{p_idx},{a_idx}]/A",
                                    indirect_id=act_idnum,
                                )
                                raw_edges.append({"source": page_id, "target": act_id, "relation": ("page", "action")})
                                self._check_action_for_script(a_act, act_id, records, raw_edges, extracted_scripts, register_node)

            raw_oa = _safe_raw_get(root, "/OpenAction")
            oa_idnum = raw_oa.idnum if isinstance(raw_oa, IndirectObject) else None
            open_action = root.get("/OpenAction")
            if open_action is not None:
                oa_resolved = open_action.get_object() if isinstance(open_action, IndirectObject) else open_action
                oa_id = "action:open_action"
                is_threat_oa = False
                if isinstance(oa_resolved, DictionaryObject):
                    s_type = str(oa_resolved.get("/S", ""))
                    if s_type in ("/JavaScript", "/Launch", "/ImportData", "/GoToE", "/SubmitForm") or "/JS" in oa_resolved:
                        is_threat_oa = True
                register_node(
                    oa_id,
                    "action",
                    has_stream=False,
                    obj_ref=oa_resolved,
                    is_threat_trigger=is_threat_oa,
                    invoker="/Catalog/OpenAction",
                    indirect_id=oa_idnum,
                )
                raw_edges.append({"source": root_id, "target": oa_id, "relation": ("catalog", "action")})
                self._check_action_for_script(oa_resolved, oa_id, records, raw_edges, extracted_scripts, register_node)

            raw_aa = _safe_raw_get(root, "/AA")
            aa_idnum = raw_aa.idnum if isinstance(raw_aa, IndirectObject) else None
            additional_actions = root.get("/AA")
            if additional_actions is not None:
                aa_resolved = additional_actions.get_object() if isinstance(additional_actions, IndirectObject) else additional_actions
                aa_id = "action:aa"
                is_threat_aa = False
                if isinstance(aa_resolved, DictionaryObject):
                    for k in aa_resolved:
                        sub = aa_resolved[k]
                        if isinstance(sub, IndirectObject):
                            sub = sub.get_object()
                        if isinstance(sub, DictionaryObject) and (str(sub.get("/S", "")) in ("/JavaScript", "/Launch") or "/JS" in sub):
                            is_threat_aa = True
                register_node(
                    aa_id,
                    "action",
                    has_stream=False,
                    obj_ref=aa_resolved,
                    is_threat_trigger=is_threat_aa,
                    invoker="/Catalog/AA",
                    indirect_id=aa_idnum,
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
        if js_entry is not None:
            if isinstance(js_entry, IndirectObject):
                js_idnum = js_entry.idnum
                js_entry = js_entry.get_object()
            script_id = f"script:{action_id}"
            script_text = ""
            if hasattr(js_entry, "get_data"):
                try:
                    script_text = js_entry.get_data().decode("utf-8", errors="ignore")
                except Exception:
                    script_text = str(js_entry)
            else:
                script_text = str(js_entry)
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
            extracted_scripts.append({
                "script_id": script_id,
                "parent_id": action_id,
                "code": script_text,
            })

        for k in list(action_obj.keys()):
            if str(k) in ("/O", "/C", "/E", "/X", "/D", "/U", "/Fo", "/Bl", "/PO", "/PC", "/PV", "/PI", "/K", "/F", "/V", "/WC", "/WS", "/DS", "/WP", "/DP"):
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
                    if hasattr(js_obj, "get_data"):
                        try:
                            code = js_obj.get_data().decode("utf-8", errors="ignore")
                        except Exception:
                            code = str(js_obj)
                    else:
                        code = str(js_obj)
                    extracted_scripts.append({
                        "script_id": f"{script_id}_{i}",
                        "parent_id": script_id,
                        "code": code,
                    })

    def _build_hetero_graph(self, records: list[dict[str, Any]], raw_edges: list[dict[str, Any]]) -> dict[str, torch.Tensor]:
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
                    stream_bytes_val = float(raw_stream) if isinstance(raw_stream, int) and raw_stream >= 0 else size_val
                    stream_log = float(np.log1p(max(0.0, stream_bytes_val))) if has_stream_val > 0.0 else 0.0
                    stream_mask = has_stream_val
                    ind_flag = 1.0
                    rep_flag = 1.0 if r.get("is_repaired") else 0.0
                    node_raw_features.append([log_size, phys_mask, stream_log, stream_mask, ind_flag, rep_flag])
                else:
                    node_raw_features.append([log_size, has_stream_val])
                incoming_counts[idx] = 0

        num_nodes = len(node_types)
        if num_nodes == 0:
            if self.as_numpy or torch is None:
                return {
                    "node_features": np.zeros((1, self.node_in_dim), dtype=np.float32),
                    "node_types": np.array([8], dtype=np.int64),
                    "edge_index": np.zeros((2, 0), dtype=np.int64),
                    "edge_rel": np.zeros((0,), dtype=np.int64),
                    "batch": np.zeros((1,), dtype=np.int64),
                }
            return {
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
                edge_index_np = np.vstack([
                    np.asarray(edge_src, dtype=np.int64),
                    np.asarray(edge_dst, dtype=np.int64),
                ])
                edge_rel_np = np.asarray(edge_rel, dtype=np.int64)
            else:
                edge_index_np = np.zeros((2, 0), dtype=np.int64)
                edge_rel_np = np.zeros((0,), dtype=np.int64)
            batch_np = np.zeros((num_nodes,), dtype=np.int64)
            return {
                "node_features": node_feat_np,
                "node_types": node_types_np,
                "edge_index": edge_index_np,
                "edge_rel": edge_rel_np,
                "batch": batch_np,
            }

        node_feat_tensor = torch.tensor(full_node_features, dtype=torch.float32)
        node_types_tensor = torch.tensor(node_types, dtype=torch.long)
        if len(edge_src) > 0:
            edge_index_tensor = torch.stack([
                torch.tensor(edge_src, dtype=torch.long),
                torch.tensor(edge_dst, dtype=torch.long),
            ], dim=0)
            edge_rel_tensor = torch.tensor(edge_rel, dtype=torch.long)
        else:
            edge_index_tensor = torch.zeros((2, 0), dtype=torch.long)
            edge_rel_tensor = torch.zeros((0,), dtype=torch.long)

        batch_tensor = torch.zeros(num_nodes, dtype=torch.long)
        return {
            "node_features": node_feat_tensor,
            "node_types": node_types_tensor,
            "edge_index": edge_index_tensor,
            "edge_rel": edge_rel_tensor,
            "batch": batch_tensor,
        }

    def _extract_ast_stream(
        self, extracted_scripts: list[dict[str, Any]]
    ) -> tuple[torch.Tensor, dict[str, float], dict[str, int]]:
        counts: dict[str, int] = {k: 0 for k in AST_NODE_TYPES}
        total_nodes = 0
        max_depth = 0
        computed_members = 0
        loops = 0

        if extracted_scripts:
            full_js = "\n".join(item["code"] for item in extracted_scripts)
            try:
                import esprima
                tree = esprima.parseScript(full_js, tolerant=True)

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

                walk(tree, 1)
            except Exception as exc:
                raise ValueError("javascript_ast_parse_failed") from exc

        ast_values = [counts[k] for k in AST_NODE_TYPES]
        while len(ast_values) < 32:
            ast_values.append(0)
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
        elapsed_sec: float = 0.0,
    ) -> tuple[torch.Tensor | None, list[float | None]]:
        size_kb = len(data) / 1024.0
        ast_total = max(ast_stats["total_nodes"], 1.0)
        stream_count = float(raw_tokens.get("stream", raw_tokens.get("Stream", 0)))
        endstream_count = float(raw_tokens.get("endstream", raw_tokens.get("Endstream", 0)))
        object_count = float(raw_tokens.get("obj", raw_tokens.get("Obj", 0)))
        endobj_count = float(raw_tokens.get("endobj", raw_tokens.get("Endobj", 0)))
        structural_js_count = float(len(extracted_scripts or []))
        has_names_js = any(r.get("evidence_id") == "script:names_js" for r in (records or []))
        structural_javascript_count = structural_js_count + (1.0 if has_names_js else 0.0)
        js_full_count = max(float(raw_tokens.get("JavaScript", raw_tokens.get("Javascript", 0))), structural_javascript_count)
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
            lexical_stream_mismatch = abs(stream_count - endstream_count) > 0.0
            is_truncated_stream = decomp_exceeded or decode_failures > 0 or lexical_stream_mismatch
            truncated_streams = decode_failures + (1 if decomp_exceeded and decode_failures == 0 else 0)
            if discovered_streams > 0:
                stream_trunc_ratio = min(1.0, float(truncated_streams) / float(discovered_streams))
            else:
                stream_trunc_ratio = 1.0 if is_truncated_stream else 0.0

            spec_flood = abs(object_count - endobj_count) > 50.0 or abs(stream_count - endstream_count) > 50.0
            excessive_graph = object_count > 10000.0 or len(obs_records) >= 200
            ast_truncated = ast_stats["total_nodes"] >= 50000.0 or ast_stats["max_depth"] >= 128.0
            timeout_flag = elapsed_sec >= 30.0

            measured.update({
                "byte_image_file_encoded_ratio": byte_img_encoded,
                "byte_image_file_persisted_ratio": byte_img_persisted,
                "stream_truncation_ratio": stream_trunc_ratio,
                "evasive_timeout_anomaly": 1.0 if timeout_flag else 0.0,
                "flag_decompression_ratio_exceeded": 1.0 if decomp_exceeded else 0.0,
                "is_truncated_stream": 1.0 if is_truncated_stream else 0.0,
                "flag_spec_violation_flood": 1.0 if spec_flood else 0.0,
                "flag_excessive_object_graph": 1.0 if excessive_graph else 0.0,
                "flag_ast_complexity_truncated": 1.0 if ast_truncated else 0.0,
            })
        else:
            measured.update({
                "byte_image_file_encoded_ratio": None,
                "byte_image_file_persisted_ratio": None,
                "stream_truncation_ratio": None,
                "evasive_timeout_anomaly": None,
                "flag_decompression_ratio_exceeded": None,
                "is_truncated_stream": None,
                "flag_spec_violation_flood": None,
                "flag_excessive_object_graph": None,
                "flag_ast_complexity_truncated": None,
            })

        raw_vec: list[float | None] = [measured.get(name) for name in self.feature_names]
        if any(v is None for v in raw_vec):
            return None, raw_vec
        arr = np.array([float(v) for v in raw_vec if v is not None], dtype=np.float32)
        scaled = (arr - self.scaler_mean) / self.scaler_scale
        if self.as_numpy or torch is None:
            return scaled.astype(np.float32, copy=False)[None, :], raw_vec
        tab_tensor = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
        return tab_tensor, raw_vec
