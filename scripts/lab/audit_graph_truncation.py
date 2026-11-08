from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(1, str(Path(__file__).resolve().parent))

from lab_contract import parse_json
from lab_jobs import encoded, validate_job, validate_result
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.graph_audit import canonical_bytes
from malpdf.extraction.graph_truncation_audit import (
    CONTRACT_VERSION,
    QUALITY_CONTRACT_VERSION,
    audit_truncation_bundle,
    summarize_truncation_cases,
    validate_truncation_case,
)


MAX_BUNDLE = 8 * 1024**2 + 1024
INDEX_FIELDS = {"index", "sha256", "split", "label", "source_bundle_sha256", "availability"}
ROW_FIELDS = {
    "index",
    "sha256",
    "split",
    "label",
    "expected_bundle_sha256",
    "source_bundle_sha256",
    "availability",
    "bundle_schema_valid",
    "truncation",
}
AVAILABILITIES = {
    "present",
    "missing",
    "checksum_mismatch",
    "invalid_json",
    "identity_mismatch",
    "invalid_schema",
    "unsafe_or_oversize",
}
SOURCE_PATHS = (
    "src/malpdf/static/pdf_parser.py",
    "src/malpdf/extraction/normalize.py",
    "src/malpdf/extraction/numeric_export.py",
    "src/malpdf/extraction/parser_views.py",
    "src/malpdf/extraction/mupdf_adapter.py",
    "src/malpdf/extraction/qpdf_adapter.py",
    "src/malpdf/extraction/graph_exports.py",
    "src/malpdf/extraction/raw_forensic.py",
    "scripts/lab/extract_hetero_graphs.py",
    "src/malpdf/static/profile_worker.py",
    "src/malpdf/static/worker_diagnostics.py",
)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def safe_path(path):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("truncation_audit_symlink_refused")
    return path


def read_bounded(path, limit):
    path = safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("truncation_audit_file_limit")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("truncation_audit_file_limit")
    return value


def validate_row(row):
    if not isinstance(row, dict) or set(row) != ROW_FIELDS:
        raise ValueError("truncation_audit_row_shape")
    if (type(row["index"]) is not int or not 0 <= row["index"] < 10000
            or not isinstance(row["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
            or row["split"] not in {"train", "validation", "test"}
            or type(row["label"]) is not int or row["label"] not in (0, 1)
            or not isinstance(row["expected_bundle_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", row["expected_bundle_sha256"])
            or (row["source_bundle_sha256"] is not None
                and (not isinstance(row["source_bundle_sha256"], str)
                     or not re.fullmatch(r"[a-f0-9]{64}", row["source_bundle_sha256"])))
            or row["availability"] not in AVAILABILITIES
            or type(row["bundle_schema_valid"]) is not bool):
        raise ValueError("truncation_audit_row_metadata")
    if row["availability"] == "present":
        if (row["truncation"] is None or row["bundle_schema_valid"] is not True
                or row["source_bundle_sha256"] is None
                or row["source_bundle_sha256"] != row["expected_bundle_sha256"]):
            raise ValueError("truncation_audit_row_present_unverified")
    else:
        if row["truncation"] is not None or row["bundle_schema_valid"] is not False:
            raise ValueError("truncation_audit_row_invalid_contradiction")
        if row["availability"] == "missing" and row["source_bundle_sha256"] is not None:
            raise ValueError("truncation_audit_row_missing_contradiction")
    if row["truncation"] is not None:
        validate_truncation_case(row["truncation"])
        if row["truncation"]["sample_sha256"] != row["sha256"]:
            raise ValueError("truncation_audit_row_identity")
    return row


def render_report(summary):
    cohort = summary["cohort"]
    capped = summary["capped_cohort"]
    sizes = summary["node_size_producers_and_provenance"]["totals_across_retained_projected_nodes"]
    lines = [
        "# BUG-007B2 — Graph Truncation & Node-Size Provenance Audit",
        "",
        f"Contract: `{summary['contract_version']}` | Quality view: `{summary['quality_contract_version']}` | Node cap: `{summary['node_cap']}`",
        "",
        "## 1. Cohort Overview",
        "",
        f"- Planned / Audited: `{cohort['planned']}` / `{cohort['audited']}` (`raw_pdf_processing=false`, `model_input_ready=false`).",
        f"- Non-empty projected graphs: `{cohort['nonempty_graphs']}` (`uncapped={cohort['uncapped_nonempty_graphs']}`, `capped={cohort['capped_graphs']}`).",
        f"- Empty projected graphs: `{cohort['empty_graphs']}` (`projection_filter_confirmed={summary['empty_projection_separation']['projection_filter_confirmed_indices']}`).",
        "",
        "## 2. Stratified Summary by Split and Label",
        "",
        "| Partition | Planned | Non-empty | Empty | Capped (`>200`) | Valid under v1 contract |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for split in ("train", "validation", "test"):
        entry = summary["by_split"][split]
        lines.append(
            f"| `{split}` | {entry['planned']} | {entry['nonempty_graphs']} | {entry['empty_graphs']} | {entry['capped_graphs']} | {entry['valid_under_contract']} |"
        )
    for lbl in ("0", "1"):
        entry = summary["by_label"][lbl]
        lines.append(
            f"| `label={lbl}` | {entry['planned']} | {entry['nonempty_graphs']} | {entry['empty_graphs']} | {entry['capped_graphs']} | {entry['valid_under_contract']} |"
        )
    lines.extend([
        "",
        "## 3. Capped Cohort (`excluded_nodes_cap > 0`)",
        "",
        f"- Capped sample count: `{capped['count']}`.",
        f"- Dropped nodes by cap total: `{capped['dropped_nodes_cap']['total']}` (median `{capped['dropped_nodes_cap']['median']}`, p95 `{capped['dropped_nodes_cap']['p95']}`, max `{capped['dropped_nodes_cap']['max']}`).",
        f"- Dropped eligible edges by cap total: `{capped['dropped_edges_cap']['total']}` (`one_endpoint_capped={capped['dropped_edges_one_endpoint_capped_total']}`, `both_endpoints_capped={capped['dropped_edges_both_endpoints_capped_total']}`); non-eligible endpoint edges kept separate: `{capped['excluded_edges_non_eligible_endpoint_total']}`.",
        f"- Samples dropping security-sensitive nodes (`action`/`script`/`annotation`/`filespec`/`stream`): `{capped['samples_dropping_security_sensitive_nodes']}` (`{capped['security_sensitive_nodes_dropped_total']}` nodes).",
        f"- Structural distortion on retained nodes: newly isolated `{capped['structural_impact']['newly_isolated_kept_nodes_total']}`, newly orphaned `{capped['structural_impact']['newly_orphaned_kept_nodes_total']}`, disconnected from `catalog` `{capped['structural_impact']['kept_disconnected_from_catalog_total']}`, retained WCC fragmentation gain `{capped['structural_impact']['kept_fragmentation_wcc_gain_total']}`.",
        "",
        "## 4. Node-Size Producers & Provenance Across Retained Nodes",
        "",
        "| Size Definition | Known | Null (`None`) | Total Bytes | Model Feature Producer |",
        "| --- | ---: | ---: | ---: | --- |",
        f"| `legacy_semantic_size_bytes` | {sizes['legacy_semantic_size_bytes']['known_count']} | {sizes['legacy_semantic_size_bytes']['null_count']} | {sizes['legacy_semantic_size_bytes']['total_bytes']} | `True` |",
        f"| `verified_physical_declaration_span_bytes` | {sizes['verified_physical_declaration_span_bytes']['known_count']} | {sizes['verified_physical_declaration_span_bytes']['null_count']} | {sizes['verified_physical_declaration_span_bytes']['total_bytes']} | `True` |",
        f"| `stream_raw_payload_bytes` | {sizes['stream_raw_payload_bytes']['known_count']} | {sizes['stream_raw_payload_bytes']['null_count']} | {sizes['stream_raw_payload_bytes']['total_bytes']} | `True` |",
        f"| `projected_json_storage_bytes` | {sizes['projected_json_storage_bytes']['known_count']} | {sizes['projected_json_storage_bytes']['null_count']} | {sizes['projected_json_storage_bytes']['total_bytes']} | `False` |",
        "",
    ])
    if "b1_replay_overlay" in summary:
        v_cohort = summary["b1_replay_overlay"]["virtual_post_b1_cohort"]
        lines.extend([
            "## 5. Read-Only Virtual Post-B1 Overlay (Baseline Unmodified)",
            "",
            f"- Replay job: `{summary['b1_replay_overlay']['replay_job_id']}`.",
            f"- Virtual post-B1 non-empty projected graphs: `{v_cohort['nonempty_graphs']}` / `{v_cohort['planned']}` (`uncapped={v_cohort['uncapped_nonempty_graphs']}`, `capped={v_cohort['capped_graphs']}`, `empty={v_cohort['empty_graphs']}`).",
            "",
        ])
    return "\n".join(lines)


def _audit_replay_overlay(replay_job_id, baseline_job_id, baseline_rows_by_index, *, job_root):
    if not isinstance(replay_job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", replay_job_id):
        raise ValueError("truncation_replay_job_identity")
    replay_dir = safe_path(Path(job_root) / replay_job_id)
    r_job_payload = read_bounded(replay_dir / "job.json", 65536)
    replay_job = validate_job(parse_json(r_job_payload))
    if replay_job["job_id"] != replay_job_id or replay_job["kind"] != "pdf-diagnostic-replay":
        raise ValueError("truncation_replay_job_identity")
    r_res_payload = read_bounded(replay_dir / "result.json", 32768)
    replay_res = validate_result(parse_json(r_res_payload), replay_job)
    if replay_res["status"] not in {"passed", "partial"}:
        raise ValueError("truncation_replay_not_completed")
    r_lock_payload = read_bounded(replay_dir / "locked_methodology.json", 256 * 1024)
    locked = parse_json(r_lock_payload)
    if (not isinstance(locked, dict) or locked.get("job_id") != replay_job_id
            or locked.get("baseline_job_id") != baseline_job_id
            or not isinstance(locked.get("records"), list)
            or len(locked["records"]) != replay_job["limits"]["samples"]):
        raise ValueError("truncation_replay_methodology_mismatch")

    overlay_rows = []
    seen_indices = set()
    for ordinal, rec in enumerate(locked["records"]):
        b_idx = rec.get("baseline_index")
        if type(b_idx) is not int or b_idx == 141 or b_idx in seen_indices or b_idx not in baseline_rows_by_index:
            raise ValueError("truncation_replay_index_invalid")
        seen_indices.add(b_idx)
        base_row = baseline_rows_by_index[b_idx]
        if rec.get("sha256") != base_row["sha256"] or rec.get("split") != base_row["split"] or rec.get("label") != base_row["label"]:
            raise ValueError("truncation_replay_baseline_mismatch")
        payload = read_bounded(replay_dir / "private_bundles" / f"{ordinal:04d}.json", MAX_BUNDLE)
        bundle = validate_bundle(parse_json(payload))
        if bundle.get("sample_sha256") != rec["sha256"]:
            raise ValueError("truncation_replay_bundle_identity")
        trunc = audit_truncation_bundle(bundle, rec["sha256"])
        digest = sha(payload)
        overlay_rows.append(validate_row({
            "index": b_idx,
            "sha256": rec["sha256"],
            "split": rec["split"],
            "label": rec["label"],
            "expected_bundle_sha256": digest,
            "source_bundle_sha256": digest,
            "availability": "present",
            "bundle_schema_valid": True,
            "truncation": trunc,
        }))
    provenance = {
        "replay_job_id": replay_job_id,
        "replay_job_sha256": sha(r_job_payload),
        "replay_result_sha256": sha(r_res_payload),
        "replay_methodology_sha256": sha(r_lock_payload),
    }
    return provenance, overlay_rows


def audit_truncation_job(
    job_id,
    expected_index_path,
    *,
    replay_job_id=None,
    job_root=Path("/var/lib/malpdf/jobs"),
    output_root=Path("/home/remnux/malpdf-graph-truncation-audits"),
    source_root=None,
):
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("truncation_audit_job_identity")
    directory = safe_path(Path(job_root) / job_id)
    job_payload = read_bounded(directory / "job.json", 65536)
    job = validate_job(parse_json(job_payload))
    if job["job_id"] != job_id:
        raise ValueError("truncation_audit_job_identity")
    selection_payload = read_bounded(directory / "selection.json", 4 * 1024**2)
    selection = parse_json(selection_payload)
    sel_rows = selection["rows"]
    if selection["job_id"] != job_id or sha(encoded(sel_rows)) != selection["selection_sha256"] or len(sel_rows) != job["limits"]["samples"]:
        raise ValueError("truncation_audit_selection_identity")
    result_payload = read_bounded(directory / "result.json", 32768)
    result = validate_result(parse_json(result_payload), job)
    if result["status"] not in {"passed", "partial", "failed", "interrupted", "blocked"}:
        raise ValueError("truncation_audit_result_not_final")
    index_payload = read_bounded(expected_index_path, 4 * 1024**2)
    expected = parse_json(index_payload)
    if not isinstance(expected, list) or len(expected) != len(sel_rows):
        raise ValueError("truncation_audit_expected_index")
    for idx, (s_row, pinned) in enumerate(zip(sel_rows, expected)):
        if (not isinstance(pinned, dict) or set(pinned) != INDEX_FIELDS
                or type(pinned["index"]) is not int or pinned["index"] != idx
                or pinned["sha256"] != s_row["pdf_sha256"] or pinned["split"] != s_row["split"]
                or type(pinned["label"]) is not int or pinned["label"] not in (0, 1)
                or str(pinned["label"]) != str(s_row["Label"])
                or pinned["availability"] != "present"
                or not isinstance(pinned["source_bundle_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", pinned["source_bundle_sha256"])):
            raise ValueError("truncation_audit_expected_index")

    output_root = safe_path(output_root)
    if output_root.is_relative_to(safe_path(job_root)):
        raise ValueError("truncation_audit_output_inside_input")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_root / f"run_{stamp}_{job_id[:12]}"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)

    rows = []
    with (output / "cases.jsonl").open("xb") as stream:
        for idx, pinned in enumerate(expected):
            row = {
                "index": idx,
                "sha256": pinned["sha256"],
                "split": pinned["split"],
                "label": pinned["label"],
                "expected_bundle_sha256": pinned["source_bundle_sha256"],
                "source_bundle_sha256": None,
                "availability": "missing",
                "bundle_schema_valid": False,
                "truncation": None,
            }
            try:
                payload = read_bounded(directory / "private_bundles" / f"{idx:04d}.json", MAX_BUNDLE)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                row["availability"] = "unsafe_or_oversize"
            else:
                row["source_bundle_sha256"] = sha(payload)
                if row["source_bundle_sha256"] != row["expected_bundle_sha256"]:
                    row["availability"] = "checksum_mismatch"
                else:
                    try:
                        bundle = parse_json(payload)
                    except (ValueError, TypeError, RecursionError):
                        row["availability"] = "invalid_json"
                    else:
                        if not isinstance(bundle, dict) or bundle.get("sample_sha256") != row["sha256"]:
                            row["availability"] = "identity_mismatch"
                        else:
                            try:
                                validate_bundle(bundle)
                            except (ValueError, TypeError, KeyError, RecursionError):
                                row["availability"] = "invalid_schema"
                            else:
                                row.update(availability="present", bundle_schema_valid=True)
                            if row["bundle_schema_valid"]:
                                try:
                                    row["truncation"] = audit_truncation_bundle(bundle, row["sha256"])
                                except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                                    row.update(availability="invalid_schema", bundle_schema_valid=False, truncation=None)
            validate_row(row)
            line = canonical_bytes(row) + b"\n"
            if len(line) > 1024**2 or stream.tell() + len(line) > 64 * 1024**2:
                raise ValueError("truncation_audit_output_limit")
            stream.write(line)
            rows.append(row)

    summary = summarize_truncation_cases(rows)
    summary["baseline_job_id"] = job_id
    summary["availability_counts"] = {
        k: sum(r["availability"] == k for r in rows)
        for k in sorted({r["availability"] for r in rows})
    }

    exported_files = ["locked_methodology.json", "cases.jsonl"]
    replay_provenance = None
    if replay_job_id is not None:
        by_idx = {r["index"]: r for r in rows}
        replay_provenance, overlay_rows = _audit_replay_overlay(replay_job_id, job_id, by_idx, job_root=job_root)
        with (output / "replay_overlay_cases.jsonl").open("xb") as rstream:
            for orow in overlay_rows:
                rline = canonical_bytes(orow) + b"\n"
                if len(rline) > 1024**2 or rstream.tell() + len(rline) > 32 * 1024**2:
                    raise ValueError("truncation_audit_output_limit")
                rstream.write(rline)
        exported_files.append("replay_overlay_cases.jsonl")
        overlay_map = {r["index"]: r for r in overlay_rows}
        combined_virtual = [overlay_map.get(r["index"], r) for r in rows]
        virtual_summary = summarize_truncation_cases(combined_virtual)
        summary["b1_replay_overlay"] = {
            "replay_job_id": replay_job_id,
            "scope": "read_only_virtual_comparison_baseline_bundles_unmodified",
            "replay_subset_summary": summarize_truncation_cases(overlay_rows),
            "virtual_post_b1_cohort": virtual_summary["cohort"],
            "virtual_post_b1_capped_cohort": virtual_summary["capped_cohort"],
            "virtual_post_b1_by_split": virtual_summary["by_split"],
            "virtual_post_b1_by_label": virtual_summary["by_label"],
            "virtual_post_b1_by_split_and_label": virtual_summary["by_split_and_label"],
            "virtual_post_b1_empty_projection_separation": virtual_summary["empty_projection_separation"],
            "virtual_post_b1_node_size_producers_and_provenance": virtual_summary["node_size_producers_and_provenance"],
        }

    src_root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    extractor_hashes = {
        name: sha(read_bounded(src_root / name, 2 * 1024**2).replace(b"\r\n", b"\n"))
        for name in SOURCE_PATHS if (src_root / name).is_file()
    }
    from malpdf.extraction import graph_truncation_audit as gta
    methodology = {
        "schema_version": 1,
        "stage": "BUG-007B2",
        "contract_version": CONTRACT_VERSION,
        "quality_contract_version": QUALITY_CONTRACT_VERSION,
        "baseline_job_id": job_id,
        "baseline_job_sha256": sha(job_payload),
        "baseline_result_sha256": sha(result_payload),
        "selection_sha256": selection["selection_sha256"],
        "expected_index_sha256": sha(index_payload),
        "replay_overlay": replay_provenance,
        "audit_code_sha256": sha(read_bounded(Path(__file__), 2 * 1024**2) + read_bounded(Path(gta.__file__), 2 * 1024**2)),
        "extractor_source_hashes": extractor_hashes,
        "seed": 42,
        "node_cap": 200,
        "raw_pdf_processing": False,
        "baseline_bundles_modified": False,
        "node_cap_modified": False,
        "parser_modified": False,
        "training_executed": False,
        "model_input_ready": False,
    }
    (output / "locked_methodology.json").write_bytes(canonical_bytes(methodology) + b"\n")
    (output / "summary.json").write_bytes(canonical_bytes(summary) + b"\n")
    (output / "report.md").write_text(render_report(summary), encoding="utf-8")
    exported_files.extend(["summary.json", "report.md"])

    manifest = {
        "schema_version": 1,
        "stage": "BUG-007B2",
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "records": len(rows),
        "files": {
            name: sha(read_bounded(output / name, 64 * 1024**2))
            for name in exported_files
        },
    }
    (output / "manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
    return {
        "output": str(output),
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "records": len(rows),
        "capped_graphs": summary["capped_cohort"]["count"],
        "raw_pdf_processing": False,
        "model_input_ready": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-index", type=Path, required=True)
    parser.add_argument("--replay-job-id", default=None)
    parser.add_argument("--output-root", type=Path, default=Path("/home/remnux/malpdf-graph-truncation-audits"))
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit(2)
    value = audit_truncation_job(
        args.job_id,
        args.expected_index,
        replay_job_id=args.replay_job_id,
        output_root=args.output_root,
    )
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
