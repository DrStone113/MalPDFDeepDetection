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
from malpdf.extraction.quality_gate import (
    GATE_CONTRACT_VERSION,
    GATE_CONTRACT_VERSION_V2,
    evaluate_cohort_quality_gate,
    evaluate_cohort_quality_gate_v2,
    evaluate_sample_quality,
    evaluate_sample_quality_v2,
    validate_sample_gate_case,
    validate_sample_gate_case_v2,
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
    "gate",
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
        raise ValueError("quality_gate_symlink_refused")
    return path


def read_bounded(path, limit):
    path = safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("quality_gate_file_limit")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("quality_gate_file_limit")
    return value


def validate_row(row, *, projection_version="v1"):
    if not isinstance(row, dict) or set(row) != ROW_FIELDS:
        raise ValueError("quality_gate_row_shape")
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
        raise ValueError("quality_gate_row_metadata")
    if row["availability"] == "present":
        if (row["gate"] is None or row["bundle_schema_valid"] is not True
                or row["source_bundle_sha256"] is None
                or row["source_bundle_sha256"] != row["expected_bundle_sha256"]):
            raise ValueError("quality_gate_row_present_unverified")
    else:
        if row["gate"] is not None or row["bundle_schema_valid"] is not False:
            raise ValueError("quality_gate_row_invalid_contradiction")
        if row["availability"] == "missing" and row["source_bundle_sha256"] is not None:
            raise ValueError("quality_gate_row_missing_contradiction")
    if row["gate"] is not None:
        if projection_version == "v2":
            validate_sample_gate_case_v2(row["gate"])
        else:
            validate_sample_gate_case(row["gate"])
        if row["gate"]["sample_sha256"] != row["sha256"]:
            raise ValueError("quality_gate_row_identity")
    return row


def _render_checks_table(checks):
    lines = [
        "| Gate Check | Passed | Summary |",
        "| --- | --- | --- |",
    ]
    for name, item in checks.items():
        details = ", ".join(f"`{k}={v}`" for k, v in item.items() if k != "passed")
        lines.append(f"| `{name}` | `{item['passed']}` | {details} |")
    return lines


def render_report(summary):
    cohort = summary["cohort"]
    ledger = summary["unavailable_document_ledger"]
    title = (
        "# Graph Projection v2 — Extraction Quality Gate Evaluation"
        if summary["gate_contract_version"] == GATE_CONTRACT_VERSION_V2
        else "# BUG-007B3 — Extraction Quality Gate Evaluation"
    )
    readiness_line = (
        f"- Model readiness flags: `v2_graph_model_input_ready={summary['v2_graph_model_input_ready']}`, "
        f"`legacy_19d_model_input_ready={summary['legacy_19d_model_input_ready']}`, "
        f"`training_unlocked={summary['training_unlocked']}`, `training_executed={summary['training_executed']}`, "
        f"`raw_pdf_processing={summary['raw_pdf_processing']}`."
        if summary["gate_contract_version"] == GATE_CONTRACT_VERSION_V2
        else f"- Model readiness flags: `legacy_19d_model_input_ready={summary['legacy_19d_model_input_ready']}`, "
             f"`training_unlocked={summary['training_unlocked']}`, `training_executed={summary['training_executed']}`, "
             f"`raw_pdf_processing={summary['raw_pdf_processing']}`."
    )
    lines = [
        title,
        "",
        f"Contract: `{summary['gate_contract_version']}` | Policy: `{summary['policy']['policy_version']}` | Node cap: `{summary['node_cap']}`",
        "",
        "## 1. Baseline Cohort Verdict",
        "",
        f"- Baseline verdict: **`{summary['cohort_gate_verdict']}`** (`{summary['checks_passed_count']} / {summary['checks_total_count']}` checks passed).",
        f"- Planned / Preserved evaluation denominator: `{cohort['planned_denominator']}` / `{cohort['evaluation_denominator_preserved']}` (`placeholder_nodes_inserted=false`).",
        f"- GNN message-passing eligible: `{cohort['gnn_message_passing_eligible']}` | Tabular static valid: `{cohort['tabular_features_valid']}` | Unavailable empty projections: `{cohort['unavailable_empty_projection']}` | Rejected: `{cohort['rejected']}`.",
        readiness_line,
        "",
        "## 2. Baseline Gate Checks (8-Point Contract)",
        "",
        *_render_checks_table(summary["checks"]),
        "",
        "## 3. Stratified Dispositions by Split and Label",
        "",
        "| Partition | Planned | Eval Denominator | GNN Eligible | Tabular Valid | Unavailable Empty | Rejected | `v2_provenance_graph_ready` |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for sp in ("train", "validation", "test"):
        st = summary["by_split"][sp]
        lines.append(
            f"| `{sp}` | {st['planned_denominator']} | {st['evaluation_denominator_preserved']} | {st['gnn_message_passing_eligible']} | {st['tabular_features_valid']} | {st['unavailable_empty_projection']} | {st['rejected']} | {st['v2_provenance_graph_ready']} |"
        )
    for lbl in ("0", "1"):
        st = summary["by_label"][lbl]
        lines.append(
            f"| `label={lbl}` | {st['planned_denominator']} | {st['evaluation_denominator_preserved']} | {st['gnn_message_passing_eligible']} | {st['tabular_features_valid']} | {st['unavailable_empty_projection']} | {st['rejected']} | {st['v2_provenance_graph_ready']} |"
        )
    lines.extend([
        "",
        "## 4. Unavailable-Document Ledger (Baseline)",
        "",
        f"- Total unavailable empty-graph documents: `{ledger['total_unavailable']}`.",
        f"- `unavailable_projection_filtered` indices: `{ledger['by_disposition_indices']['unavailable_projection_filtered']}`.",
        f"- `unavailable_timeout_no_graph` indices: `{ledger['by_disposition_indices']['unavailable_timeout_no_graph']}`.",
        f"- `unavailable_worker_failure` count: `{len(ledger['by_disposition_indices']['unavailable_worker_failure'])}`.",
        f"- Evaluation abstention / tabular-fallback indices: `validation={ledger['eval_abstention_or_tabular_fallback_indices']['validation']}`, `test={ledger['eval_abstention_or_tabular_fallback_indices']['test']}`.",
        "",
    ])
    if "b1_replay_overlay" in summary:
        overlay = summary["b1_replay_overlay"]
        v_eval = overlay["virtual_post_b1_evaluation"]
        v_cohort = v_eval["cohort"]
        v_ledger = v_eval["unavailable_document_ledger"]
        trans = overlay["verdict_transition"]
        lines.extend([
            "## 5. Read-Only Virtual Post-B1 Quality Gate (Baseline Bundles Unmodified)",
            "",
            f"- Replay job: `{overlay['replay_job_id']}` (`scope={overlay['scope']}`).",
            f"- Verdict transition: **`{trans['from_baseline']}` -> `{trans['to_virtual_post_b1']}`** (`{v_eval['checks_passed_count']} / {v_eval['checks_total_count']}` checks passed).",
            f"- Checks cleared by B1: `{trans['checks_cleared_by_b1']}`.",
            f"- Remaining failed checks blocking `ready_for_locked_export`: `{trans['remaining_failed_checks']}`.",
            f"- Virtual post-B1 GNN eligible: `{v_cohort['gnn_message_passing_eligible']}` / `{v_cohort['planned_denominator']}` (`unavailable_empty_projection={v_cohort['unavailable_empty_projection']}`, `rejected={v_cohort['rejected']}`).",
            f"- Virtual post-B1 unavailable ledger: `projection_filtered={v_ledger['by_disposition_indices']['unavailable_projection_filtered']}`, `timeout_no_graph={v_ledger['by_disposition_indices']['unavailable_timeout_no_graph']}`, `worker_failure={v_ledger['by_disposition_indices']['unavailable_worker_failure']}`.",
            f"- Virtual post-B1 evaluation abstention / tabular-fallback indices: `validation={v_ledger['eval_abstention_or_tabular_fallback_indices']['validation']}`, `test={v_ledger['eval_abstention_or_tabular_fallback_indices']['test']}`.",
            "",
            "### Virtual Post-B1 Gate Checks",
            "",
            *_render_checks_table(v_eval["checks"]),
            "",
        ])
    return "\n".join(lines)


def _evaluate_replay_overlay(
    replay_job_id,
    baseline_job_id,
    baseline_rows_by_index,
    *,
    job_root,
    projection_version="v1",
):
    if not isinstance(replay_job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", replay_job_id):
        raise ValueError("quality_gate_replay_job_identity")
    replay_dir = safe_path(Path(job_root) / replay_job_id)
    r_job_payload = read_bounded(replay_dir / "job.json", 65536)
    replay_job = validate_job(parse_json(r_job_payload))
    if replay_job["job_id"] != replay_job_id or replay_job["kind"] != "pdf-diagnostic-replay":
        raise ValueError("quality_gate_replay_job_identity")
    r_res_payload = read_bounded(replay_dir / "result.json", 32768)
    replay_res = validate_result(parse_json(r_res_payload), replay_job)
    if replay_res["status"] not in {"passed", "partial"}:
        raise ValueError("quality_gate_replay_not_completed")
    r_lock_payload = read_bounded(replay_dir / "locked_methodology.json", 256 * 1024)
    locked = parse_json(r_lock_payload)
    if (not isinstance(locked, dict) or locked.get("job_id") != replay_job_id
            or locked.get("baseline_job_id") != baseline_job_id
            or not isinstance(locked.get("records"), list)
            or len(locked["records"]) != replay_job["limits"]["samples"]):
        raise ValueError("quality_gate_replay_methodology_mismatch")

    sample_eval_fn = evaluate_sample_quality_v2 if projection_version == "v2" else evaluate_sample_quality
    overlay_rows = []
    seen_indices = set()
    for ordinal, rec in enumerate(locked["records"]):
        b_idx = rec.get("baseline_index")
        if type(b_idx) is not int or b_idx == 141 or b_idx in seen_indices or b_idx not in baseline_rows_by_index:
            raise ValueError("quality_gate_replay_index_invalid")
        seen_indices.add(b_idx)
        base_row = baseline_rows_by_index[b_idx]
        if rec.get("sha256") != base_row["sha256"] or rec.get("split") != base_row["split"] or rec.get("label") != base_row["label"]:
            raise ValueError("quality_gate_replay_baseline_mismatch")
        payload = read_bounded(replay_dir / "private_bundles" / f"{ordinal:04d}.json", MAX_BUNDLE)
        bundle = validate_bundle(parse_json(payload))
        if bundle.get("sample_sha256") != rec["sha256"]:
            raise ValueError("quality_gate_replay_bundle_identity")
        gate = sample_eval_fn(bundle, rec["sha256"])
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
            "gate": gate,
        }, projection_version=projection_version))
    provenance = {
        "replay_job_id": replay_job_id,
        "replay_job_sha256": sha(r_job_payload),
        "replay_result_sha256": sha(r_res_payload),
        "replay_methodology_sha256": sha(r_lock_payload),
    }
    return provenance, overlay_rows


def evaluate_quality_gate_job(
    job_id,
    expected_index_path,
    *,
    replay_job_id=None,
    projection_version="v1",
    job_root=Path("/var/lib/malpdf/jobs"),
    output_root=Path("/home/remnux/malpdf-extraction-quality-gates"),
    source_root=None,
):
    if projection_version not in {"v1", "v2"}:
        raise ValueError("quality_gate_projection_version")
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("quality_gate_job_identity")
    directory = safe_path(Path(job_root) / job_id)
    job_payload = read_bounded(directory / "job.json", 65536)
    job = validate_job(parse_json(job_payload))
    if job["job_id"] != job_id:
        raise ValueError("quality_gate_job_identity")
    selection_payload = read_bounded(directory / "selection.json", 4 * 1024**2)
    selection = parse_json(selection_payload)
    sel_rows = selection["rows"]
    if selection["job_id"] != job_id or sha(encoded(sel_rows)) != selection["selection_sha256"] or len(sel_rows) != job["limits"]["samples"]:
        raise ValueError("quality_gate_selection_identity")
    result_payload = read_bounded(directory / "result.json", 32768)
    result = validate_result(parse_json(result_payload), job)
    if result["status"] not in {"passed", "partial", "failed", "interrupted", "blocked"}:
        raise ValueError("quality_gate_result_not_final")
    index_payload = read_bounded(expected_index_path, 4 * 1024**2)
    expected = parse_json(index_payload)
    if not isinstance(expected, list) or len(expected) != len(sel_rows):
        raise ValueError("quality_gate_expected_index")
    for idx, (s_row, pinned) in enumerate(zip(sel_rows, expected)):
        if (not isinstance(pinned, dict) or set(pinned) != INDEX_FIELDS
                or type(pinned["index"]) is not int or pinned["index"] != idx
                or pinned["sha256"] != s_row["pdf_sha256"] or pinned["split"] != s_row["split"]
                or type(pinned["label"]) is not int or pinned["label"] not in (0, 1)
                or str(pinned["label"]) != str(s_row["Label"])
                or pinned["availability"] != "present"
                or not isinstance(pinned["source_bundle_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", pinned["source_bundle_sha256"])):
            raise ValueError("quality_gate_expected_index")

    output_root = safe_path(output_root)
    if output_root.is_relative_to(safe_path(job_root)):
        raise ValueError("quality_gate_output_inside_input")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_root / f"run_{stamp}_{job_id[:12]}"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)

    sample_eval_fn = evaluate_sample_quality_v2 if projection_version == "v2" else evaluate_sample_quality
    cohort_eval_fn = evaluate_cohort_quality_gate_v2 if projection_version == "v2" else evaluate_cohort_quality_gate

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
                "gate": None,
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
                                    row["gate"] = sample_eval_fn(bundle, row["sha256"])
                                except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                                    row.update(availability="invalid_schema", bundle_schema_valid=False, gate=None)
            validate_row(row, projection_version=projection_version)
            line = canonical_bytes(row) + b"\n"
            if len(line) > 1024**2 or stream.tell() + len(line) > 64 * 1024**2:
                raise ValueError("quality_gate_output_limit")
            stream.write(line)
            rows.append(row)

    summary = cohort_eval_fn(rows)
    summary["baseline_job_id"] = job_id
    summary["availability_counts"] = {
        k: sum(r["availability"] == k for r in rows)
        for k in sorted({r["availability"] for r in rows})
    }

    exported_files = ["locked_methodology.json", "cases.jsonl"]
    replay_provenance = None
    virtual_verdict = None
    if replay_job_id is not None:
        by_idx = {r["index"]: r for r in rows}
        replay_provenance, overlay_rows = _evaluate_replay_overlay(
            replay_job_id,
            job_id,
            by_idx,
            job_root=job_root,
            projection_version=projection_version,
        )
        with (output / "replay_overlay_cases.jsonl").open("xb") as rstream:
            for orow in overlay_rows:
                rline = canonical_bytes(orow) + b"\n"
                if len(rline) > 1024**2 or rstream.tell() + len(rline) > 32 * 1024**2:
                    raise ValueError("quality_gate_output_limit")
                rstream.write(rline)
        exported_files.append("replay_overlay_cases.jsonl")
        overlay_map = {r["index"]: r for r in overlay_rows}
        combined_virtual = [overlay_map.get(r["index"], r) for r in rows]
        virtual_eval = cohort_eval_fn(combined_virtual)
        virtual_verdict = virtual_eval["cohort_gate_verdict"]
        cleared_checks = [
            chk for chk, val in virtual_eval["checks"].items()
            if val["passed"] and not summary["checks"][chk]["passed"]
        ]
        remaining_failed = [
            chk for chk, val in virtual_eval["checks"].items()
            if not val["passed"]
        ]
        summary["b1_replay_overlay"] = {
            "replay_job_id": replay_job_id,
            "scope": "read_only_virtual_comparison_baseline_bundles_unmodified",
            "replay_subset_evaluation": cohort_eval_fn(overlay_rows),
            "virtual_post_b1_evaluation": virtual_eval,
            "verdict_transition": {
                "from_baseline": summary["cohort_gate_verdict"],
                "to_virtual_post_b1": virtual_verdict,
                "checks_cleared_by_b1": cleared_checks,
                "remaining_failed_checks": remaining_failed,
            },
        }

    src_root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    extractor_hashes = {
        name: sha(read_bounded(src_root / name, 2 * 1024**2).replace(b"\r\n", b"\n"))
        for name in SOURCE_PATHS if (src_root / name).is_file()
    }
    from malpdf.extraction import quality_gate as qg_mod
    contract_ver = GATE_CONTRACT_VERSION_V2 if projection_version == "v2" else GATE_CONTRACT_VERSION
    stage_name = "GRAPH-PROJECTION-V2" if projection_version == "v2" else "BUG-007B3"
    methodology = {
        "schema_version": 1,
        "stage": stage_name,
        "projection_version": projection_version,
        "gate_contract_version": contract_ver,
        "baseline_job_id": job_id,
        "baseline_job_sha256": sha(job_payload),
        "baseline_result_sha256": sha(result_payload),
        "selection_sha256": selection["selection_sha256"],
        "expected_index_sha256": sha(index_payload),
        "replay_overlay": replay_provenance,
        "gate_code_sha256": sha(read_bounded(Path(__file__), 2 * 1024**2) + read_bounded(Path(qg_mod.__file__), 2 * 1024**2)),
        "extractor_source_hashes": extractor_hashes,
        "seed": 42,
        "node_cap": 200,
        "raw_pdf_processing": False,
        "baseline_bundles_modified": False,
        "node_cap_modified": False,
        "parser_modified": False,
        "training_executed": False,
    }
    (output / "locked_methodology.json").write_bytes(canonical_bytes(methodology) + b"\n")
    (output / "summary.json").write_bytes(canonical_bytes(summary) + b"\n")
    (output / "report.md").write_text(render_report(summary), encoding="utf-8")
    exported_files.extend(["summary.json", "report.md"])

    manifest = {
        "schema_version": 1,
        "stage": stage_name,
        "projection_version": projection_version,
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "records": len(rows),
        "files": {
            name: sha(read_bounded(output / name, 64 * 1024**2))
            for name in exported_files
        },
    }
    (output / "manifest.json").write_bytes(canonical_bytes(manifest) + b"\n")
    receipt = {
        "output": str(output),
        "baseline_job_id": job_id,
        "replay_overlay_job_id": replay_job_id,
        "projection_version": projection_version,
        "records": len(rows),
        "baseline_verdict": summary["cohort_gate_verdict"],
        "virtual_post_b1_verdict": virtual_verdict,
        "legacy_19d_model_input_ready": summary["legacy_19d_model_input_ready"],
        "training_unlocked": summary["training_unlocked"],
        "training_executed": False,
        "raw_pdf_processing": False,
    }
    if projection_version == "v2":
        receipt["v2_graph_model_input_ready"] = summary["v2_graph_model_input_ready"]
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-index", type=Path, required=True)
    parser.add_argument("--replay-job-id", default=None)
    parser.add_argument("--projection-version", choices=("v1", "v2"), default="v1")
    parser.add_argument("--output-root", type=Path, default=Path("/home/remnux/malpdf-extraction-quality-gates"))
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit(2)
    value = evaluate_quality_gate_job(
        args.job_id,
        args.expected_index,
        replay_job_id=args.replay_job_id,
        projection_version=args.projection_version,
        output_root=args.output_root,
    )
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
