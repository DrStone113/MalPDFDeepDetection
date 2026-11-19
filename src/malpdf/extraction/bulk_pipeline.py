"""Hybrid CPU/GPU chunked static extraction and clean manifest curation."""

from __future__ import annotations

from collections import Counter
from contextlib import closing, nullcontext
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import time
from typing import Callable

from malpdf.data.graph_contract import NODE_FEATURE_DIM_V2, index_measured_graphs_v2
from malpdf.extraction.graph_audit import canonical_bytes
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.bulk_checkpoint import (
    CHUNK_FILES, FINAL_FILES, MARKOV_FILES, matches_checkpoint, output_lock, publication, read_chunk,
    replacement_archive, verify_manifest,
)
from malpdf.extraction.graph_projection_v2 import (
    PROJECTION_CONTRACT_VERSION,
    SCHEMA_VERSION,
    _prepare_graph_projection_v2,
    finalize_graph_batch_v2,
    to_measured_graph_record_v2,
)
from malpdf.extraction.quality_gate import (
    GATE_CONTRACT_VERSION_V2,
    prepare_sample_quality_v2,
    finish_sample_quality_v2,
)
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.execution import available_cpus


def resolve_extraction_device(device: str = "auto"):
    from malpdf.extraction.gpu_accel import resolve_extraction_device as _impl

    return _impl(device)


def hardware_profile(device: str = "auto") -> dict:
    from malpdf.extraction.gpu_accel import hardware_profile as _impl

    return _impl(device)


def byte_transition_matrices_batch(*args, **kwargs):
    from malpdf.extraction.gpu_accel import byte_transition_matrices_batch as _impl

    return _impl(*args, **kwargs)


SKIP_NON_PDF_SUFFIXES = frozenset({
    ".json", ".csv", ".tsv", ".txt", ".parquet", ".xml", ".html", ".htm",
    ".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".onnx", ".npy", ".npz",
    ".py", ".pyc", ".sh", ".ps1", ".bat", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".md", ".rst", ".yml", ".yaml",
})


@dataclass(frozen=True)
class CleanCorpusEntry:
    index: int
    sha256: str
    pdf_path: Path
    stored_relpath: str
    source: str
    label: int | None
    label_source: str
    label_conflict: bool = False
    split: str | None = None
    sample_id: str | None = None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def is_non_dataset_pdf_member(source: str, filename: str) -> bool:
    norm = filename.replace("\\", "/")
    if "/site-packages/matplotlib/mpl-data/images/" in norm:
        return True
    if source == "vapd_v5" and norm.endswith("/Artifact_Documentation__USENIX_Security_25.pdf"):
        return True
    suffix = Path(norm).suffix.lower()
    if suffix and suffix != ".pdf" and suffix in SKIP_NON_PDF_SUFFIXES:
        return True
    return False


def _classify_row_provenance(source: str, filename: str, raw_label_source: str) -> tuple[int, int | None, str]:
    norm = filename.replace("\\", "/")
    if source in {"zenodo_3464032_clean_9000", "zenodo_clean_pdf_9000"} or raw_label_source == "publisher_reported_benign":
        return 2, 0, "publisher_reported_benign_clean_9000"
    if source == "vapd_v5":
        if "/D1 dataset/" in norm:
            parts = norm.split("/")
            if "ben" in parts:
                return 2, 0, "vapd_v5_d1_benign"
            if "mal" in parts:
                return 2, 1, "vapd_v5_d1_malicious"
        return 6, None, "vapd_v5_unverified"
    if source in {"zenodo_3464032_malware_2011", "zenodo_malware_pdf_2011"} or raw_label_source == "publisher_reported_malicious_virustotal_2011":
        return 2, 1, "publisher_reported_malicious_2011"
    if source.startswith("cve_t4pdf") or raw_label_source == "user_requested_malicious":
        return 3, 1, "user_requested_malicious"
    if source == "zenodo_3464032_malware_2017":
        return 4, None, "unverified_zenodo_2017"
    if source == "govdocs1_sample":
        return 5, None, "unverified_govdocs1_sample"
    if source.startswith("safedocs"):
        return 5, None, "unlabeled_safedocs_cc_main_2021_31"
    return 6, None, raw_label_source or "unlabeled"


def _load_cic_overrides(
    cic_manifest_csv: Path | None,
    *,
    cic_split_manifest_csv: Path | None = None,
) -> dict[str, tuple[int, str | None, str | None]]:
    overrides: dict[str, tuple[int, str | None, str | None]] = {}
    if cic_manifest_csv is None or not cic_manifest_csv.is_file():
        return overrides
    cic_splits: dict[str, tuple[int, str]] | None = None
    if cic_split_manifest_csv is not None and cic_split_manifest_csv.is_file():
        cic_splits = {}
        with cic_split_manifest_csv.open("r", encoding="utf-8") as sfh:
            for row in csv.DictReader(sfh):
                if (row.get("cohort") or "").strip() != "cic":
                    continue
                sid = (row.get("sample_id") or "").strip()
                lbl_raw = (row.get("Label") or row.get("label") or "").strip()
                split_val = (row.get("split") or "").strip()
                if sid and lbl_raw in {"0", "1"} and split_val in {"train", "validation", "test"}:
                    cic_splits[sid] = (int(lbl_raw), split_val)
    with cic_manifest_csv.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            sha = (row.get("pdf_sha256") or row.get("sha256") or "").strip().lower()
            sample_id = (row.get("sample_id") or "").strip() or None
            if cic_splits is not None:
                if sample_id not in cic_splits or len(sha) != 64:
                    continue
                lbl, split_val = cic_splits[sample_id]
                overrides[sha] = (lbl, split_val, sample_id)
                continue
            lbl_raw = (row.get("Label") or row.get("label") or "").strip()
            if len(sha) != 64 or lbl_raw not in {"0", "1"}:
                continue
            split_val = (row.get("split") or "").strip() or None
            overrides[sha] = (int(lbl_raw), split_val, sample_id)
    return overrides


def build_clean_corpus_manifest(
    manifest_csvs: list[Path],
    *,
    base_dir: Path,
    cic_manifest_csv: Path | None = None,
    cic_split_manifest_csv: Path | None = None,
    require_magic_offset0: bool = False,
) -> tuple[list[CleanCorpusEntry], dict]:
    cic_overrides = _load_cic_overrides(cic_manifest_csv, cic_split_manifest_csv=cic_split_manifest_csv)
    candidates: dict[str, list[dict]] = {}
    stats = Counter()

    for mpath in manifest_csvs:
        if not mpath.is_file():
            raise FileNotFoundError(f"Manifest not found: {mpath}")
        with mpath.open("r", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                stats["raw_rows"] += 1
                sha = (row.get("sha256") or row.get("pdf_sha256") or "").strip().lower()
                src = (row.get("source") or "").strip()
                fname = (row.get("filename") or row.get("pdf_relative_path") or "").strip()
                relpath = (row.get("stored_relpath") or row.get("pdf_relative_path") or "").strip()
                magic0 = str(row.get("magic_offset0", "True")).strip().lower() == "true"
                if len(sha) != 64 or not relpath:
                    stats["skipped_invalid"] += 1
                    continue
                if is_non_dataset_pdf_member(src, fname):
                    stats["skipped_non_dataset"] += 1
                    continue
                if require_magic_offset0 and not magic0:
                    stats["skipped_magic_offset"] += 1
                    continue
                full_path = (base_dir / relpath).resolve()
                if not full_path.is_file():
                    alt_path = (mpath.parent / relpath).resolve()
                    if not alt_path.is_file():
                        stats["skipped_missing_file"] += 1
                        continue
                    full_path = alt_path
                prio, lbl, lbl_src = _classify_row_provenance(src, fname, (row.get("label_source") or "").strip())
                candidates.setdefault(sha, []).append({
                    "priority": prio,
                    "label": lbl,
                    "label_source": lbl_src,
                    "source": src or "unknown",
                    "stored_relpath": relpath,
                    "pdf_path": full_path,
                })

    entries: list[CleanCorpusEntry] = []
    for idx, sha in enumerate(sorted(candidates)):
        obs = candidates[sha]
        obs.sort(key=lambda item: (item["priority"], item["source"], item["stored_relpath"]))
        if sha in cic_overrides:
            cic_lbl, cic_split, cic_id = cic_overrides[sha]
            chosen = obs[0]
            entries.append(CleanCorpusEntry(
                index=idx,
                sha256=sha,
                pdf_path=chosen["pdf_path"],
                stored_relpath=chosen["stored_relpath"],
                source=chosen["source"],
                label=cic_lbl,
                label_source="cic_protocol_g_verified",
                label_conflict=False,
                split=cic_split,
                sample_id=cic_id,
            ))
            stats["cic_override_applied"] += 1
            continue

        top_prio = obs[0]["priority"]
        top_group = [item for item in obs if item["priority"] == top_prio]
        labels = {item["label"] for item in top_group if item["label"] is not None}
        conflict = len(labels) > 1
        chosen = top_group[0]
        final_label = None if conflict else (next(iter(labels)) if labels else None)
        if conflict:
            stats["label_conflicts_cleared"] += 1
        entries.append(CleanCorpusEntry(
            index=idx,
            sha256=sha,
            pdf_path=chosen["pdf_path"],
            stored_relpath=chosen["stored_relpath"],
            source=chosen["source"],
            label=final_label,
            label_source="label_conflict_cleared" if conflict else chosen["label_source"],
            label_conflict=conflict,
        ))

    stats["unique_clean_pdfs"] = len(entries)
    stats["labeled_0"] = sum(1 for e in entries if e.label == 0)
    stats["labeled_1"] = sum(1 for e in entries if e.label == 1)
    stats["unlabeled_or_unverified"] = sum(1 for e in entries if e.label is None)
    return entries, dict(sorted(stats.items()))


def default_bulk_limits(
    *,
    wall_seconds: int = 45,
    cpu_seconds: int = 35,
    memory_mb: int = 2048,
    max_file_mb: int = 50,
) -> CodeInspectionLimits:
    return CodeInspectionLimits(
        max_file_bytes=max_file_mb * 1024 * 1024,
        wall_seconds=wall_seconds,
        cpu_seconds=cpu_seconds,
        memory_bytes=memory_mb * 1024 * 1024,
    )


def _write_gzip_jsonl(path: Path, records: list[dict]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with gzip.open(tmp, "wb", compresslevel=6) as out:
        for rec in records:
            out.write(canonical_bytes(rec) + b"\n")
    tmp.replace(path)


def _chunk_is_complete(chunk_dir: Path) -> bool:
    done_file = chunk_dir / "chunk_done.json"
    if not done_file.exists() and not done_file.is_symlink():
        return False
    verify_manifest(chunk_dir, "chunk_done.json", allowed=(CHUNK_FILES, CHUNK_FILES | MARKOV_FILES))
    return True


def _process_chunk(
    chunk_id: int,
    chunk_entries: list[CleanCorpusEntry],
    *,
    boundary: Path,
    chunk_dir: Path,
    workers: int,
    limits: CodeInspectionLimits,
    device: str,
    arlington_catalog: object | None,
    include_markov: bool,
    extractor_fn: Callable[..., object] | None,
) -> dict:
    t0 = time.monotonic()
    entry_by_idx = {e.index: e for e in chunk_entries}
    oversized = [entry for entry in chunk_entries if entry.pdf_path.stat().st_size > limits.max_file_bytes]
    oversized_indices = {entry.index for entry in oversized}
    admitted = [entry for entry in chunk_entries if entry.index not in oversized_indices]
    paths = [e.pdf_path for e in admitted]
    indices = [e.index for e in admitted]
    expected_hashes = {e.index: e.sha256 for e in admitted}

    raw_sub = (boundary / "data" / "raw").resolve()
    chunk_boundary = raw_sub if raw_sub.is_dir() and paths and all(p.is_relative_to(raw_sub) for p in paths) else boundary
    if extractor_fn is None:
        from malpdf.extraction.batch import extract_pdfs

        extract_opts: dict = {
            "boundary": chunk_boundary,
            "workers": workers,
            "expected_hashes": expected_hashes,
            "input_indices": indices,
            "profile": "deep-static",
            "limits": limits,
            "include_byte_images": False,
            "coalesce_checkpoints": True,
        }
        if arlington_catalog is not None:
            extract_opts["arlington_catalog"] = arlington_catalog
        results = extract_pdfs(paths, **extract_opts)
    else:
        results = extractor_fn(admitted, limits=limits, workers=workers)

    prepared = {}
    gate_facts = {}
    primary_available_count = 0
    for entry in oversized:
        bundle = normalize_profile(
            {"status": "resource_limit_or_signal", "errors": ["file_size_limit"]},
            entry.sha256, "deep-static", provenance={"input_identity": "manifest_only"},
        )
        prepared[entry.index] = _prepare_graph_projection_v2(bundle, entry.sha256)
        gate_facts[entry.index] = prepare_sample_quality_v2(bundle, entry.sha256)
    stream = iter(results)
    with (closing(stream) if hasattr(stream, "close") else nullcontext(stream)):
        for idx, bundle in stream:
            if idx not in entry_by_idx or idx in prepared:
                raise ValueError("bulk_extraction_index")
            digest = entry_by_idx[idx].sha256
            prepared[idx] = _prepare_graph_projection_v2(bundle, digest)
            gate_facts[idx] = prepare_sample_quality_v2(bundle, digest)
            primary_available_count += int(any(
                rec.get("kind") == "primary_checkpoint" for rec in bundle.get("evidence_store", {}).get("records", [])
            ))
            del bundle

    t_cpu_end = time.monotonic()
    resolved_device = resolve_extraction_device(device)
    ordered_indices = sorted(entry_by_idx)
    projected_list = finalize_graph_batch_v2([prepared[idx] for idx in ordered_indices], device=str(resolved_device))

    graph_records: list[dict] = []
    tabular_records: list[dict] = []
    unavailable_records: list[dict] = []
    status_counts = Counter()
    timeout_count = 0
    peak_rss_bytes = 0

    for idx, proj in zip(ordered_indices, projected_list):
        entry = entry_by_idx[idx]
        gate = finish_sample_quality_v2(gate_facts[idx], entry.sha256, proj)
        status_counts[proj["status"]] += 1
        timeout_count += int(proj["status"] == "timeout")
        worker_rss = proj["worker"]["peak_rss_bytes"]
        if type(worker_rss) is int and worker_rss > peak_rss_bytes:
            peak_rss_bytes = worker_rss

        tabular_records.append({
            "schema_version": SCHEMA_VERSION,
            "projection_contract_version": PROJECTION_CONTRACT_VERSION,
            "index": entry.index,
            "sha256": entry.sha256,
            "source": entry.source,
            "label": entry.label,
            "label_source": entry.label_source,
            "split": entry.split,
            "status": proj["status"],
            "sample_disposition": gate["sample_disposition"],
            "gnn_message_passing_eligible": gate["gnn_message_passing_eligible"],
            "evaluation_handling": gate["evaluation_handling"],
            "excluded_feature_count": proj["excluded_feature_count"],
            "features": proj["features"],
        })

        if gate["gnn_message_passing_eligible"]:
            rec = to_measured_graph_record_v2(proj, index=entry.index, split=entry.split, label=entry.label)
            graph_records.append(rec)
        else:
            unavailable_records.append({
                "index": entry.index,
                "sha256": entry.sha256,
                "source": entry.source,
                "label": entry.label,
                "split": entry.split,
                "sample_disposition": gate["sample_disposition"],
                "evaluation_handling": gate["evaluation_handling"],
                "placeholder_nodes_inserted": False,
            })

    chunk_files: list[str] = [
        "hetero_graphs_v2.jsonl.gz",
        "tabular_features_v2.jsonl.gz",
        "unavailable_records.json",
    ]
    _write_gzip_jsonl(chunk_dir / "hetero_graphs_v2.jsonl.gz", graph_records)
    _write_gzip_jsonl(chunk_dir / "tabular_features_v2.jsonl.gz", tabular_records)
    (chunk_dir / "unavailable_records.json").write_bytes(canonical_bytes(unavailable_records) + b"\n")

    markov_count = 0
    if include_markov:
        import numpy as np
        from malpdf.static.safety import read_bounded_bytes

        raw_bufs: list[bytes] = []
        markov_shas: list[str] = []
        mats = []
        pending_bytes = 0
        for idx in ordered_indices:
            entry = entry_by_idx[idx]
            size = entry.pdf_path.stat().st_size
            if not 2 <= size <= limits.max_file_bytes:
                continue
            raw = read_bounded_bytes(entry.pdf_path, boundary=chunk_boundary, max_bytes=limits.max_file_bytes)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != entry.sha256:
                raise ValueError("bulk_markov_input_changed")
            if raw_bufs and (pending_bytes + len(raw) > 32 * 1024**2 or len(raw_bufs) >= 128):
                mats.extend(byte_transition_matrices_batch(raw_bufs, device=str(resolved_device)))
                raw_bufs.clear()
                pending_bytes = 0
            raw_bufs.append(raw)
            pending_bytes += len(raw)
            markov_shas.append(entry.sha256)
        if raw_bufs:
            mats.extend(byte_transition_matrices_batch(raw_bufs, device=str(resolved_device)))
        if mats:
            stacked = np.stack(mats, axis=0).astype(np.float32)
        else:
            stacked = np.zeros((0, 256, 256), dtype=np.float32)
        tmp_npz = chunk_dir / "markov_f32.tmp.npz"
        final_npz = chunk_dir / "markov_f32.npz"
        np.savez_compressed(tmp_npz, matrices=stacked)
        tmp_npz.replace(final_npz)
        (chunk_dir / "markov_shas.json").write_bytes(canonical_bytes(markov_shas) + b"\n")
        chunk_files.extend(["markov_f32.npz", "markov_shas.json"])
        markov_count = len(markov_shas)

    t_gpu_end = time.monotonic()

    meta = {
        "schema_version": 1,
        "chunk_id": chunk_id,
        "count": len(chunk_entries),
        "gnn_graphs": len(graph_records),
        "unavailable_graphs": len(unavailable_records),
        "markov_matrices": markov_count,
        "status_counts": dict(sorted(status_counts.items())),
        "primary_available": primary_available_count,
        "timeout": timeout_count,
        "peak_rss_bytes": peak_rss_bytes,
        "cpu_seconds": round(t_cpu_end - t0, 3),
        "gpu_projection_markov_seconds": round(t_gpu_end - t_cpu_end, 3),
        "total_seconds": round(t_gpu_end - t0, 3),
        "device": str(resolved_device),
        "resumed_from_checkpoint": False,
        "files": {name: _sha256_file(chunk_dir / name) for name in chunk_files},
    }
    (chunk_dir / "chunk_done.json").write_bytes(canonical_bytes(meta) + b"\n")
    return meta


def merge_bulk_chunks(
    output_dir: Path,
    entries: list[CleanCorpusEntry],
    chunk_metas: list[dict],
    *,
    hw_info: dict,
    manifest_stats: dict,
    final_dir: Path | None = None,
) -> dict:
    final_dir = output_dir / "final" if final_dir is None else final_dir
    final_dir.mkdir(parents=True, exist_ok=True)

    chunks_root = output_dir / "chunks"
    total_graphs = 0
    expected_gnn_shas: set[str] = set()
    unavailable_records: list[dict] = []
    markov_shards: list[dict] = []
    status_totals = Counter()
    corpus_meta_rows: list[list] = []
    primary_available_total = 0
    timeout_total = 0
    peak_rss_max = 0

    graph_out_tmp = final_dir / "hetero_graphs_v2.jsonl.gz.tmp"
    tab_out_tmp = final_dir / "tabular_features_v2.jsonl.gz.tmp"

    with gzip.open(graph_out_tmp, "wb", compresslevel=6) as g_out, gzip.open(tab_out_tmp, "wb", compresslevel=6) as t_out:
        for meta in chunk_metas:
            cdir = chunks_root / f"chunk_{meta['chunk_id']:05d}"
            primary_available_total += int(meta.get("primary_available", 0))
            timeout_total += int(meta.get("timeout", 0))
            peak_rss_max = max(peak_rss_max, int(meta.get("peak_rss_bytes", 0)))
            for k, v in meta.get("status_counts", {}).items():
                status_totals[k] += int(v)
            chunk_graphs: list[dict] = []
            chunk_shas: set[str] = set()
            with gzip.open(cdir / "hetero_graphs_v2.jsonl.gz", "rt", encoding="utf-8") as gin:
                for line in gin:
                    if line.strip():
                        rec = json.loads(line)
                        sha = rec["sha256"]
                        if sha in expected_gnn_shas:
                            raise ValueError("duplicate_measured_graph")
                        chunk_graphs.append(rec)
                        chunk_shas.add(sha)
                        expected_gnn_shas.add(sha)
                        g_out.write(canonical_bytes(rec) + b"\n")
                        total_graphs += 1
            if chunk_graphs:
                index_measured_graphs_v2(chunk_graphs, chunk_shas)
            with gzip.open(cdir / "tabular_features_v2.jsonl.gz", "rt", encoding="utf-8") as tin:
                for line in tin:
                    if line.strip():
                        rec = json.loads(line)
                        corpus_meta_rows.append([
                            rec["index"],
                            rec["sha256"],
                            rec["source"],
                            "" if rec["label"] is None else rec["label"],
                            rec["label_source"],
                            rec["split"] or "",
                            rec["status"],
                            rec["gnn_message_passing_eligible"],
                        ])
                        t_out.write(canonical_bytes(rec) + b"\n")
            unavail = json.loads((cdir / "unavailable_records.json").read_text(encoding="utf-8"))
            unavailable_records.extend(unavail)
            if (cdir / "markov_f32.npz").is_file() and (cdir / "markov_shas.json").is_file():
                markov_shards.append({
                    "chunk_id": meta["chunk_id"],
                    "npz_relpath": f"../chunks/chunk_{meta['chunk_id']:05d}/markov_f32.npz",
                    "shas_relpath": f"../chunks/chunk_{meta['chunk_id']:05d}/markov_shas.json",
                    "count": meta["markov_matrices"],
                })

    if [(row[0], row[1]) for row in corpus_meta_rows] != [(entry.index, entry.sha256) for entry in entries]:
        raise ValueError("bulk_final_identity")
    if len({entry.sha256 for entry in entries}) != len(entries):
        raise ValueError("bulk_duplicate_entry")
    if total_graphs + len(unavailable_records) != len(entries):
        raise ValueError("bulk_final_partition")
    graph_out_tmp.replace(final_dir / "hetero_graphs_v2.jsonl.gz")
    tab_out_tmp.replace(final_dir / "tabular_features_v2.jsonl.gz")

    unavailable_doc = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "planned_denominator": len(entries),
        "gnn_exported_graphs": total_graphs,
        "unavailable_empty_graphs": len(unavailable_records),
        "records": unavailable_records,
    }
    (final_dir / "unavailable_document_ledger.json").write_bytes(canonical_bytes(unavailable_doc) + b"\n")

    with (final_dir / "corpus_metadata.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["index", "sha256", "source", "label", "label_source", "split", "status", "gnn_eligible"])
        w.writerows(corpus_meta_rows)

    (final_dir / "markov_manifest.json").write_bytes(
        canonical_bytes({"schema_version": 1, "shape": [256, 256], "dtype": "float32", "shards": markov_shards}) + b"\n"
    )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "planned_denominator": len(entries),
        "gnn_exported_graphs": total_graphs,
        "unavailable_empty_graphs": len(unavailable_records),
        "primary_available_count": primary_available_total,
        "timeout_count": timeout_total,
        "peak_rss_bytes": peak_rss_max,
        "status_counts": dict(sorted(status_totals.items())),
        "manifest_stats": manifest_stats,
        "hardware": hw_info,
        "chunks_completed": len(chunk_metas),
        "markov_shard_count": len(markov_shards),
    }
    (final_dir / "summary.json").write_bytes(canonical_bytes(summary) + b"\n")

    tracked_files = [
        "hetero_graphs_v2.jsonl.gz",
        "tabular_features_v2.jsonl.gz",
        "unavailable_document_ledger.json",
        "corpus_metadata.csv",
        "markov_manifest.json",
        "summary.json",
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "files": {name: _sha256_file(final_dir / name) for name in tracked_files},
    }
    (final_dir / "manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
    return summary


def run_hybrid_bulk_extraction(
    entries: list[CleanCorpusEntry],
    *,
    base_dir: Path,
    output_dir: Path,
    workers: int | None = None,
    chunk_size: int = 500,
    limits: CodeInspectionLimits | None = None,
    device: str = "auto",
    arlington_catalog: object | None = None,
    include_markov: bool = True,
    prune_raw_after_chunk: bool = False,
    manifest_stats: dict | None = None,
    extractor_fn: Callable[..., object] | None = None,
    progress: Callable[[dict], None] | None = None,
    producer: dict | None = None,
    adopted_checkpoints: tuple[str, ...] = (),
    replaced_checkpoints: dict[int, str] | None = None,
) -> dict:
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    effective_limits = limits or default_bulk_limits()
    effective_workers = available_cpus() if workers is None else max(1, min(workers, available_cpus()))
    chunks_root = output_dir / "chunks"
    chunk_metas: list[dict] = []
    total_chunks = (len(entries) + chunk_size - 1) // chunk_size if entries else 0
    replacements = replaced_checkpoints or {}
    if replacements and (producer is None or any(not len(adopted_checkpoints) <= index < total_chunks for index in replacements)):
        raise ValueError("bulk_checkpoint_replacement_scope")
    with output_lock(output_dir):
        if chunks_root.is_symlink():
            raise ValueError("bulk_chunks_symlink")
        chunks_root.mkdir(exist_ok=True)
        for chunk_id in range(total_chunks):
            start = chunk_id * chunk_size
            chunk_entries = entries[start:start + chunk_size]
            chunk_dir = chunks_root / f"chunk_{chunk_id:05d}"
            if chunk_dir.is_symlink() or (chunk_dir / "chunk_done.json").is_symlink():
                raise ValueError("bulk_checkpoint_symlink")
            old_hash = replacements.get(chunk_id)
            replaced = old_hash is not None and matches_checkpoint(chunk_dir, old_hash)
            if old_hash is not None:
                archive = replacement_archive(chunk_dir, old_hash)
                original = chunk_dir if replaced else archive
                if not matches_checkpoint(original, old_hash):
                    raise ValueError("bulk_checkpoint_replacement_missing")
                if replaced and (archive.exists() or archive.is_symlink()):
                    raise ValueError("bulk_checkpoint_replacement_conflict")
                read_chunk(original, chunk_entries, chunk_id=chunk_id, include_markov=include_markov)
            if (chunk_dir / "chunk_done.json").exists() and not replaced:
                if (chunk_id < len(adopted_checkpoints)
                        and not matches_checkpoint(chunk_dir, adopted_checkpoints[chunk_id])):
                    raise ValueError("bulk_adopted_checkpoint_changed")
                meta = read_chunk(chunk_dir, chunk_entries, chunk_id=chunk_id, include_markov=include_markov).meta
                if producer is not None and chunk_id >= len(adopted_checkpoints) and meta.get("producer") != producer:
                    raise ValueError("bulk_checkpoint_producer")
                meta["resumed_from_checkpoint"] = True
            else:
                if chunk_id < len(adopted_checkpoints):
                    raise ValueError("bulk_adopted_checkpoint_missing")
                with publication(chunk_dir, replace_checkpoint=old_hash) as staging:
                    meta = _process_chunk(
                        chunk_id, chunk_entries, boundary=base_dir, chunk_dir=staging,
                        workers=effective_workers, limits=effective_limits, device=device,
                        arlington_catalog=arlington_catalog, include_markov=include_markov,
                        extractor_fn=extractor_fn,
                    )
                    if producer is not None:
                        meta["producer"] = producer
                        (staging / "chunk_done.json").write_bytes(canonical_bytes(meta) + b"\n")
                    read_chunk(staging, chunk_entries, chunk_id=chunk_id, include_markov=include_markov)
                if prune_raw_after_chunk:
                    for entry in chunk_entries:
                        entry.pdf_path.unlink(missing_ok=True)
            chunk_metas.append(meta)
            if progress is not None:
                progress({"event": "chunk_completed", "chunk_id": chunk_id, "total_chunks": total_chunks, **meta})

        final_dir = output_dir / "final"
        if (final_dir / "manifest.json").is_file():
            verify_manifest(final_dir, "manifest.json", allowed=(FINAL_FILES,))
        with publication(final_dir) as staging:
            summary = merge_bulk_chunks(
                output_dir, entries, chunk_metas, hw_info=hardware_profile(device),
                manifest_stats=manifest_stats or {"unique_clean_pdfs": len(entries)}, final_dir=staging,
            )
            verify_manifest(staging, "manifest.json", allowed=(FINAL_FILES,))
        return summary
