from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
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
from malpdf.data.graph_contract import index_measured_graphs_v2
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.graph_audit import canonical_bytes
from malpdf.extraction.graph_projection_v2 import (
    NODE_FEATURE_DIM_V2,
    PROJECTION_CONTRACT_VERSION,
    SCHEMA_VERSION,
    project_graph_bundle_v2,
    to_measured_graph_record_v2,
    validate_graph_projection_v2,
)
from malpdf.extraction.quality_gate import (
    GATE_CONTRACT_VERSION_V2,
    evaluate_cohort_quality_gate_v2,
    evaluate_sample_quality_v2,
)


MAX_BUNDLE = 8 * 1024**2 + 1024
INDEX_FIELDS = {"index", "sha256", "split", "label", "source_bundle_sha256", "availability"}


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def safe_path(path: Path | str) -> Path:
    resolved = Path(path).absolute()
    if any(item.is_symlink() for item in (resolved, *resolved.parents)):
        raise ValueError("export_graphs_v2_symlink_refused")
    return resolved


def read_bounded(path: Path | str, limit: int) -> bytes:
    target = safe_path(path)
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("export_graphs_v2_file_limit")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("export_graphs_v2_file_limit")
    return value


def _load_overlay_bundles(
    replay_job_id: str,
    baseline_job_id: str,
    baseline_by_idx: dict[int, dict],
    *,
    job_root: Path,
) -> tuple[dict, dict[int, tuple[str, dict]]]:
    if not isinstance(replay_job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", replay_job_id):
        raise ValueError("export_graphs_v2_replay_identity")
    replay_dir = safe_path(Path(job_root) / replay_job_id)
    r_job_payload = read_bounded(replay_dir / "job.json", 65536)
    replay_job = validate_job(parse_json(r_job_payload))
    if replay_job["job_id"] != replay_job_id or replay_job["kind"] != "pdf-diagnostic-replay":
        raise ValueError("export_graphs_v2_replay_identity")
    r_res_payload = read_bounded(replay_dir / "result.json", 32768)
    replay_res = validate_result(parse_json(r_res_payload), replay_job)
    if replay_res["status"] not in {"passed", "partial"}:
        raise ValueError("export_graphs_v2_replay_not_completed")
    r_lock_payload = read_bounded(replay_dir / "locked_methodology.json", 256 * 1024)
    locked = parse_json(r_lock_payload)
    if (
        not isinstance(locked, dict)
        or locked.get("job_id") != replay_job_id
        or locked.get("baseline_job_id") != baseline_job_id
        or not isinstance(locked.get("records"), list)
        or len(locked["records"]) != replay_job["limits"]["samples"]
    ):
        raise ValueError("export_graphs_v2_replay_methodology_mismatch")

    overlay_bundles: dict[int, tuple[str, dict]] = {}
    for ordinal, rec in enumerate(locked["records"]):
        b_idx = rec.get("baseline_index")
        if type(b_idx) is not int or b_idx == 141 or b_idx in overlay_bundles or b_idx not in baseline_by_idx:
            raise ValueError("export_graphs_v2_replay_index_invalid")
        base_entry = baseline_by_idx[b_idx]
        if (
            rec.get("sha256") != base_entry["sha256"]
            or rec.get("split") != base_entry["split"]
            or rec.get("label") != base_entry["label"]
        ):
            raise ValueError("export_graphs_v2_replay_baseline_mismatch")
        payload = read_bounded(replay_dir / "private_bundles" / f"{ordinal:04d}.json", MAX_BUNDLE)
        bundle = validate_bundle(parse_json(payload))
        if bundle.get("sample_sha256") != rec["sha256"]:
            raise ValueError("export_graphs_v2_replay_bundle_identity")
        overlay_bundles[b_idx] = (sha(payload), bundle)

    provenance = {
        "replay_job_id": replay_job_id,
        "replay_job_sha256": sha(r_job_payload),
        "replay_result_sha256": sha(r_res_payload),
        "replay_methodology_sha256": sha(r_lock_payload),
    }
    return provenance, overlay_bundles


def export_graphs_v2_job(
    job_id: str,
    expected_index_path: Path | str,
    *,
    replay_job_id: str | None = None,
    allow_virtual_overlay: bool = False,
    job_root: Path | str = Path("/var/lib/malpdf/jobs"),
    output_root: Path | str = Path("/home/remnux/malpdf-graph-exports-v2"),
    source_root: Path | str | None = None,
) -> dict:
    if replay_job_id is not None and not allow_virtual_overlay:
        raise ValueError("quality_gate_not_ready_for_export")
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("export_graphs_v2_job_identity")

    job_root_path = safe_path(job_root)
    output_root_path = safe_path(output_root)
    if output_root_path.is_relative_to(job_root_path):
        raise ValueError("export_graphs_v2_output_inside_input")

    directory = safe_path(job_root_path / job_id)
    job_payload = read_bounded(directory / "job.json", 65536)
    job = validate_job(parse_json(job_payload))
    if job["job_id"] != job_id:
        raise ValueError("export_graphs_v2_job_identity")
    selection_payload = read_bounded(directory / "selection.json", 4 * 1024**2)
    selection = parse_json(selection_payload)
    sel_rows = selection["rows"]
    if (
        selection["job_id"] != job_id
        or sha(encoded(sel_rows)) != selection["selection_sha256"]
        or len(sel_rows) != job["limits"]["samples"]
    ):
        raise ValueError("export_graphs_v2_selection_identity")
    result_payload = read_bounded(directory / "result.json", 32768)
    result = validate_result(parse_json(result_payload), job)
    if result["status"] not in {"passed", "partial", "failed", "interrupted", "blocked"}:
        raise ValueError("export_graphs_v2_result_not_final")

    index_payload = read_bounded(expected_index_path, 4 * 1024**2)
    expected = parse_json(index_payload)
    if not isinstance(expected, list) or len(expected) != len(sel_rows):
        raise ValueError("export_graphs_v2_expected_index")
    for idx, (s_row, pinned) in enumerate(zip(sel_rows, expected)):
        if (
            not isinstance(pinned, dict)
            or set(pinned) != INDEX_FIELDS
            or type(pinned["index"]) is not int
            or pinned["index"] != idx
            or pinned["sha256"] != s_row["pdf_sha256"]
            or pinned["split"] != s_row["split"]
            or type(pinned["label"]) is not int
            or pinned["label"] not in (0, 1)
            or str(pinned["label"]) != str(s_row["Label"])
            or pinned["availability"] != "present"
            or not isinstance(pinned["source_bundle_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", pinned["source_bundle_sha256"])
        ):
            raise ValueError("export_graphs_v2_expected_index")

    baseline_by_idx = {item["index"]: item for item in expected}
    replay_provenance = None
    overlay_bundles: dict[int, tuple[str, dict]] = {}
    if replay_job_id is not None:
        replay_provenance, overlay_bundles = _load_overlay_bundles(
            replay_job_id,
            job_id,
            baseline_by_idx,
            job_root=job_root_path,
        )

    gate_rows = []
    projected_by_idx: dict[int, dict] = {}
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
            "gate": None,
        }
        if idx in overlay_bundles:
            digest, bundle = overlay_bundles[idx]
            row["expected_bundle_sha256"] = digest
            row["source_bundle_sha256"] = digest
            row["availability"] = "present"
            row["bundle_schema_valid"] = True
            row["gate"] = evaluate_sample_quality_v2(bundle, row["sha256"])
            if row["gate"]["tabular_features_valid"]:
                projected_by_idx[idx] = validate_graph_projection_v2(
                    project_graph_bundle_v2(bundle, row["sha256"]),
                    row["sha256"],
                )
        else:
            try:
                payload = read_bounded(directory / "private_bundles" / f"{idx:04d}.json", MAX_BUNDLE)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                row["availability"] = "unsafe_or_oversize"
            else:
                digest = sha(payload)
                row["source_bundle_sha256"] = digest
                if digest != row["expected_bundle_sha256"]:
                    row["availability"] = "checksum_mismatch"
                else:
                    try:
                        bundle = validate_bundle(parse_json(payload))
                    except (ValueError, TypeError, KeyError, RecursionError):
                        row["availability"] = "invalid_schema"
                    else:
                        if bundle.get("sample_sha256") != row["sha256"]:
                            row["availability"] = "identity_mismatch"
                        else:
                            row["availability"] = "present"
                            row["bundle_schema_valid"] = True
                            row["gate"] = evaluate_sample_quality_v2(bundle, row["sha256"])
                            if row["gate"]["tabular_features_valid"]:
                                projected_by_idx[idx] = validate_graph_projection_v2(
                                    project_graph_bundle_v2(bundle, row["sha256"]),
                                    row["sha256"],
                                )
        gate_rows.append(row)

    gate_summary = evaluate_cohort_quality_gate_v2(gate_rows)
    if gate_summary["cohort_gate_verdict"] != "ready_for_locked_export":
        raise ValueError("quality_gate_not_ready_for_export")

    graph_records = []
    expected_gnn_shas: set[str] = set()
    tabular_records = []
    unavailable_entries = []

    for row in gate_rows:
        idx = row["index"]
        gate = row["gate"]
        proj = projected_by_idx[idx]
        tabular_records.append({
            "schema_version": SCHEMA_VERSION,
            "projection_contract_version": PROJECTION_CONTRACT_VERSION,
            "index": idx,
            "sha256": row["sha256"],
            "split": row["split"],
            "label": row["label"],
            "status": proj["status"],
            "sample_disposition": gate["sample_disposition"],
            "gnn_message_passing_eligible": gate["gnn_message_passing_eligible"],
            "evaluation_handling": gate["evaluation_handling"],
            "excluded_feature_count": proj["excluded_feature_count"],
            "features": proj["features"],
        })
        if gate["gnn_message_passing_eligible"]:
            graph_rec = to_measured_graph_record_v2(
                proj,
                index=idx,
                split=row["split"],
                label=row["label"],
            )
            graph_records.append(graph_rec)
            expected_gnn_shas.add(row["sha256"])
        else:
            unavailable_entries.append({
                "index": idx,
                "sha256": row["sha256"],
                "split": row["split"],
                "label": row["label"],
                "sample_disposition": gate["sample_disposition"],
                "evaluation_handling": gate["evaluation_handling"],
                "placeholder_nodes_inserted": False,
            })

    index_measured_graphs_v2(graph_records, expected_gnn_shas)

    export_scope = "virtual_post_b1_dry_run" if replay_job_id is not None else "canonical_single_job"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_root_path / f"export_{stamp}_{job_id[:12]}"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)

    from malpdf.extraction import graph_projection_v2 as gp2_mod
    from malpdf.extraction import quality_gate as qg_mod

    methodology = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "export_scope": export_scope,
        "baseline_job_id": job_id,
        "baseline_job_sha256": sha(job_payload),
        "baseline_result_sha256": sha(result_payload),
        "selection_sha256": selection["selection_sha256"],
        "expected_index_sha256": sha(index_payload),
        "replay_overlay": replay_provenance,
        "exporter_code_sha256": sha(
            read_bounded(Path(__file__), 2 * 1024**2)
            + read_bounded(Path(gp2_mod.__file__), 2 * 1024**2)
            + read_bounded(Path(qg_mod.__file__), 2 * 1024**2)
        ),
        "node_cap": 200,
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "seed": 42,
        "raw_pdf_processing": False,
        "baseline_bundles_modified": False,
        "training_executed": False,
    }
    unavailable_doc = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "export_scope": export_scope,
        "planned_denominator": len(gate_rows),
        "gnn_exported_graphs": len(graph_records),
        "unavailable_empty_graphs": len(unavailable_entries),
        "records": unavailable_entries,
    }

    (output / "locked_methodology.json").write_bytes(canonical_bytes(methodology) + b"\n")
    (output / "quality_gate_summary.json").write_bytes(canonical_bytes(gate_summary) + b"\n")
    (output / "unavailable_document_ledger.json").write_bytes(canonical_bytes(unavailable_doc) + b"\n")

    with gzip.open(output / "hetero_graphs_v2.jsonl.gz", "wb", compresslevel=6) as g_out:
        for rec in graph_records:
            g_out.write(canonical_bytes(rec) + b"\n")

    with gzip.open(output / "tabular_features_v2.jsonl.gz", "wb", compresslevel=6) as t_out:
        for rec in tabular_records:
            t_out.write(canonical_bytes(rec) + b"\n")

    exported_files = [
        "locked_methodology.json",
        "quality_gate_summary.json",
        "unavailable_document_ledger.json",
        "hetero_graphs_v2.jsonl.gz",
        "tabular_features_v2.jsonl.gz",
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "projection_contract_version": PROJECTION_CONTRACT_VERSION,
        "gate_contract_version": GATE_CONTRACT_VERSION_V2,
        "export_scope": export_scope,
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "cohort_gate_verdict": gate_summary["cohort_gate_verdict"],
        "planned_denominator": len(gate_rows),
        "gnn_exported_graphs": len(graph_records),
        "unavailable_empty_graphs": len(unavailable_entries),
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "files": {
            name: sha(read_bounded(output / name, 128 * 1024**2))
            for name in exported_files
        },
    }
    (output / "manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")

    return {
        "output": str(output),
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "export_scope": export_scope,
        "cohort_gate_verdict": gate_summary["cohort_gate_verdict"],
        "planned_denominator": len(gate_rows),
        "gnn_exported_graphs": len(graph_records),
        "unavailable_empty_graphs": len(unavailable_entries),
        "node_feature_dim": NODE_FEATURE_DIM_V2,
        "raw_pdf_processing": False,
        "training_executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-index", type=Path, required=True)
    parser.add_argument("--replay-job-id", default=None)
    parser.add_argument("--allow-virtual-overlay", action="store_true")
    parser.add_argument("--output-root", type=Path, default=Path("/home/remnux/malpdf-graph-exports-v2"))
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit(2)
    receipt = export_graphs_v2_job(
        args.job_id,
        args.expected_index,
        replay_job_id=args.replay_job_id,
        allow_virtual_overlay=args.allow_virtual_overlay,
        output_root=args.output_root,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

