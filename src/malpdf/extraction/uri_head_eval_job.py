"""Sealed air-gapped LAB evaluation job for PDFURILexicalHead v4 across 624 real PDFs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

try:
    import resource
except ImportError:
    resource = None  # type: ignore[assignment]
import sys
import tempfile
import time
from typing import TYPE_CHECKING, Any

from malpdf.extraction import benign_ood_expanded_job, benign_ood_job, uri_review_job
from malpdf.extraction.holdout_fingerprint_job import HEX256, pinned
from malpdf.static.safety import read_bounded_bytes

if TYPE_CHECKING:
    from malpdf.scanner.ingestion import InstantPDFIngestion
    from malpdf.scanner.uri_head import URILexicalHeadScorer

KIND = "pdf-uri-head-eval"
URI_CONTRACT_RELPATH = "configs/uri_lexical_head_v4_contract.json"
URI_CONTRACT_SHA256 = "84bf5da1108ef0061adf28e3cd6acdb18b263c7e99892bb0612ddec84ea5e714"
URI_NPZ_RELPATH = Path("data/processed/uri_head_v4/uri_lexical_head_v4.npz")
URI_NPZ_SHA256 = "497e63c62de27ea1e7df1e6c9ec3e3b72139220cd8631b3e00653e630edc8e97"
COHORT_ORDER: tuple[str, ...] = (
    "benign_ood_v1",
    "benign_ood_expanded_v1",
    "uri_safedocs_review",
    "uri_review_v1",
)
COHORT_COUNTS: dict[str, int] = {
    "benign_ood_v1": benign_ood_job.SAMPLES,
    "benign_ood_expanded_v1": benign_ood_expanded_job.SAMPLES,
    "uri_safedocs_review": uri_review_job.SAFEDOCS_SAMPLES,
    "uri_review_v1": uri_review_job.SAMPLES,
}
SAMPLES = sum(COHORT_COUNTS.values())
MAX_FILE_BYTES = 12 * 1024**2
TIERS = frozenset({"benign", "gated_fusion", "or_gate"})
EVAL_STATUSES = frozenset({"observed", "password_locked", "ingest_error", "missing", "invalid"})
VECTOR_NAMES = frozenset(
    {
        "annot_uri",
        "action_uri",
        "action_submitform",
        "action_gotor",
        "action_launch",
        "action_importdata",
        "submit_form",
        "gotor",
        "launch",
        "import_data",
        "javascript_url",
        "flate_text_stream",
        "qr_image",
        "pdf_action",
    }
)


def contract() -> dict[str, Any]:
    return {
        "samples": SAMPLES,
        "cohort_counts": dict(COHORT_COUNTS),
        "uri_contract_sha256": URI_CONTRACT_SHA256,
        "uri_npz_sha256": URI_NPZ_SHA256,
        "model_evaluation_in_lab": True,
        "purpose": "air-gapped static PDF URI extraction and PDFURILexicalHead v4 bounded scoring",
    }


def _normalize_row(cohort: str, boundary_relpath: str, row: dict[str, Any]) -> dict[str, Any]:
    sha = str(row["pdf_sha256"])
    size = int(row["bytes"])
    if not HEX256.fullmatch(sha) or not 0 < size <= MAX_FILE_BYTES:
        raise ValueError("manifest_unavailable")
    return {
        "cohort": cohort,
        "boundary_relpath": boundary_relpath,
        "pdf_sha256": sha,
        "pdf_relative_path": str(row["pdf_relative_path"]),
        "bytes": size,
    }


def load_rows(data_root: Path, *, source_root: Path | None = None) -> list[dict[str, Any]]:
    data_root = Path(data_root).absolute()
    src_root = Path(source_root).absolute() if source_root is not None else data_root
    groups: tuple[tuple[str, str, list[dict[str, Any]]], ...] = (
        ("benign_ood_v1", benign_ood_job.RAW_ROOT.as_posix(), benign_ood_job.load_rows(data_root)),
        (
            "benign_ood_expanded_v1",
            benign_ood_expanded_job.RAW_ROOT.as_posix(),
            benign_ood_expanded_job.load_rows(data_root),
        ),
        (
            "uri_safedocs_review",
            uri_review_job.SAFEDOCS_RAW_ROOT.as_posix(),
            uri_review_job.load_rows(data_root, uri_review_job.SAFEDOCS_KIND, source_root=src_root),
        ),
        (
            "uri_review_v1",
            uri_review_job.RAW_ROOT.as_posix(),
            uri_review_job.load_rows(data_root, uri_review_job.KIND, source_root=src_root),
        ),
    )
    rows: list[dict[str, Any]] = []
    for cohort, boundary, items in groups:
        if len(items) != COHORT_COUNTS[cohort]:
            raise ValueError("manifest_unavailable")
        rows.extend(_normalize_row(cohort, boundary, item) for item in items)
    if len(rows) != SAMPLES:
        raise ValueError("manifest_unavailable")
    return rows


def _verify_model_artifacts(data_root: Path, source_root: Path) -> tuple[Path, Path]:
    contract_path = source_root / URI_CONTRACT_RELPATH
    raw_contract = read_bounded_bytes(contract_path, boundary=contract_path.parent, max_bytes=1024**2)
    if hashlib.sha256(raw_contract.replace(b"\r\n", b"\n")).hexdigest() != URI_CONTRACT_SHA256:
        raise ValueError("uri_lexical_contract_sha256_mismatch")
    npz_path = data_root / URI_NPZ_RELPATH
    pinned(npz_path, npz_path.parent, URI_NPZ_SHA256, 8 * 1024**2)
    return contract_path, npz_path


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> bytes:
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=".eval-", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return encoded


def _minimal_bundle(
    expected_sha256: str,
    size_bytes: int,
    bundle_status: str,
    peak_rss_bytes: int,
) -> dict[str, Any]:
    from malpdf.extraction.normalize import normalize_profile

    primary_status = "complete" if bundle_status == "observed" else bundle_status
    profile = {
        "status": primary_status,
        "errors": [] if bundle_status == "observed" else [bundle_status],
        "worker_cleanup_complete": True,
        "peak_rss_bytes": int(peak_rss_bytes),
        "static": {
            "input": {"sha256": expected_sha256, "size_bytes": int(size_bytes)},
            "features": {},
        },
    }
    return normalize_profile(profile, expected_sha256, "fast-static")


def evaluate_pdf_row(
    pdf_path: Path,
    *,
    boundary: Path,
    expected_sha256: str,
    cohort: str,
    index: int,
    ingestion: InstantPDFIngestion,
    scorer: URILexicalHeadScorer,
) -> tuple[dict[str, Any], dict[str, Any]]:
    t0 = time.perf_counter()
    raw_bytes = pinned(pdf_path, boundary, expected_sha256, MAX_FILE_BYTES)
    if len(raw_bytes) > MAX_FILE_BYTES:
        raise ValueError("manifest_unavailable")

    eval_status = "observed"
    bundle_status = "observed"
    max_prob = 0.0
    tier = "benign"
    scored_cnt = 0
    allow_cnt = 0
    xml_cnt = 0
    vec_counts: dict[str, int] = {}
    top_vec: str | None = None
    heuristic_phishing = False
    password_locked = False

    try:
        ingest_data = ingestion.ingest(raw_bytes, max_bytes=MAX_FILE_BYTES)
        password_locked = bool((ingest_data.get("encryption_analysis") or {}).get("password_locked"))
        heuristic_phishing = bool((ingest_data.get("phishing_analysis") or {}).get("has_phishing_threat"))
        if password_locked:
            eval_status = "password_locked"
            bundle_status = "encrypted"
        else:
            scored = scorer.score_pdf_uris(
                ingest_data.get("extracted_uris") or (),
                qr_uris=(ingest_data.get("qr_analysis") or {}).get("decoded_uris") or (),
            )
            max_prob = round(float(scored.get("max_prob") or 0.0), 6)
            tier = str(scored.get("tier") or "benign")
            scored_cnt = int(scored.get("scored_url_count") or 0)
            allow_cnt = int(scored.get("allowlisted_url_count") or 0)
            xml_cnt = int(scored.get("filtered_xml_xmp_count") or 0)
            vec_counts = {
                str(k): int(v)
                for k, v in (scored.get("vector_counts") or {}).items()
                if str(k) in VECTOR_NAMES and int(v) > 0
            }
            raw_top = scored.get("top_url_vector")
            top_vec = str(raw_top) if raw_top and str(raw_top) in VECTOR_NAMES else None
    except Exception:
        eval_status = "ingest_error"
        bundle_status = "decode_error"

    peak_rss = (
        int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        if (sys.platform == "linux" and resource is not None)
        else 0
    )
    record = {
        "index": int(index),
        "sha256": expected_sha256,
        "cohort": cohort,
        "status": bundle_status,
        "eval_status": eval_status,
        "max_prob": max_prob,
        "tier": tier,
        "scored_url_count": scored_cnt,
        "allowlisted_url_count": allow_cnt,
        "filtered_xml_xmp_count": xml_cnt,
        "vector_counts": vec_counts,
        "top_url_vector": top_vec,
        "heuristic_phishing": heuristic_phishing,
        "password_locked": password_locked,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }
    bundle = _minimal_bundle(expected_sha256, len(raw_bytes), bundle_status, peak_rss)
    return record, bundle


def run_shard(
    *,
    job: dict[str, Any],
    directory: Path,
    data_root: Path,
    source_root: Path,
    rows: list[tuple[int, dict[str, Any]]],
    shard: int,
    count: int,
    jobs_mod: Any,
) -> dict[str, Any]:
    from malpdf.extraction.jobs import require_extraction_lab
    from malpdf.scanner.ingestion import InstantPDFIngestion
    from malpdf.scanner.uri_head import URILexicalHeadScorer

    require_extraction_lab(True, repository_root=data_root)
    os.environ["MALPDF_LAB_ISOLATED"] = "1"
    contract_path, npz_path = _verify_model_artifacts(data_root, source_root)
    ingestion = InstantPDFIngestion(
        scaler_path=source_root / "configs" / "tabular_scaler.json",
        v4_contract_path=source_root / "configs" / "transgraph_v4_contract.json",
        as_numpy=True,
    )
    scorer = URILexicalHeadScorer(contract_path=contract_path, npz_path=npz_path, prefer_onnx=False)
    if not scorer.model_loaded:
        raise ValueError("uri_lexical_head_unavailable")

    eval_dir = jobs_mod.trusted_path(directory / "uri_eval")
    eval_dir.mkdir(mode=0o700, exist_ok=True)
    outputs = jobs_mod.trusted_path(directory / "private_bundles")
    outputs.mkdir(mode=0o700, exist_ok=True)

    started = time.monotonic()
    summary = dict.fromkeys(
        (
            "planned",
            "completed",
            "observed",
            "bounded_complete",
            "partial",
            "failed",
            "primary_available",
            "timeout",
            "elapsed_ms",
            "peak_rss_bytes",
        ),
        0,
    )
    summary["planned"] = job["limits"]["samples"]
    summary["shard"] = shard
    summary["shards"] = count
    statuses: dict[str, int] = {}
    total_bundle_bytes = 0

    for index, row in rows:
        if time.monotonic() - started > job["limits"]["wall_seconds"] - 25:
            jobs_mod.write_pdf_halt(job, directory, shard=shard, index=index, reason="wall_limit")
            break
        require_extraction_lab(True, repository_root=data_root)
        eval_file = eval_dir / f"{index:04d}.json"
        bundle_file = outputs / f"{index:04d}.json"
        reused = False
        if eval_file.is_file() and bundle_file.is_file():
            try:
                existing_eval = json.loads(
                    read_bounded_bytes(eval_file, boundary=eval_dir, max_bytes=65536).decode("utf-8")
                )
                existing_bundle = json.loads(
                    read_bounded_bytes(bundle_file, boundary=outputs, max_bytes=16 * 1024**2).decode("utf-8")
                )
                if (
                    existing_eval.get("sha256") == row["pdf_sha256"]
                    and existing_bundle.get("sample_sha256") == row["pdf_sha256"]
                    and existing_bundle.get("status") in jobs_mod.PDF_STATUSES
                ):
                    b_status = str(existing_bundle["status"])
                    summary["completed"] += 1
                    summary["bounded_complete"] += int(b_status == "bounded_complete")
                    summary[jobs_mod.status_bucket(b_status)] += 1
                    statuses[b_status] = statuses.get(b_status, 0) + 1
                    summary["primary_available"] += 1
                    reused = True
            except Exception:
                reused = False
        if reused:
            continue

        record, bundle = evaluate_pdf_row(
            data_root / row["pdf_relative_path"],
            boundary=data_root / row["boundary_relpath"],
            expected_sha256=row["pdf_sha256"],
            cohort=row["cohort"],
            index=index,
            ingestion=ingestion,
            scorer=scorer,
        )
        encoded_bundle = jobs_mod.encoded(bundle)
        if total_bundle_bytes + len(encoded_bundle) > job["limits"]["output_bytes"]:
            jobs_mod.write_pdf_halt(job, directory, shard=shard, index=index, reason="output_limit")
            break
        total_bundle_bytes += len(encoded_bundle)
        _atomic_write_json(eval_file, record)
        _atomic_write_json(bundle_file, bundle)
        b_status = str(bundle["status"])
        summary["completed"] += 1
        summary["bounded_complete"] += int(b_status == "bounded_complete")
        summary[jobs_mod.status_bucket(b_status)] += 1
        statuses[b_status] = statuses.get(b_status, 0) + 1
        summary["primary_available"] += 1
        worker_rss = int((bundle.get("coverage_report") or {}).get("worker", {}).get("peak_rss_bytes") or 0)
        summary["peak_rss_bytes"] = max(summary["peak_rss_bytes"], worker_rss)

    summary["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return {**summary, "status_counts": statuses}
