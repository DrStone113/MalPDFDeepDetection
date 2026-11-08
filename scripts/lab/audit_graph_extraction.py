from __future__ import annotations

import argparse
from collections import Counter
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
from malpdf.extraction.graph_audit import audit_bundle, canonical_bytes, summarize_cases, validate_case


MAX_BUNDLE = 8 * 1024**2 + 1024
AVAILABILITIES = {"present", "missing", "checksum_mismatch", "invalid_json", "identity_mismatch", "invalid_schema", "unsafe_or_oversize"}
INDEX_FIELDS = {"index", "sha256", "split", "label", "source_bundle_sha256", "availability"}
ROW_FIELDS = {"index", "sha256", "split", "label", "expected_bundle_sha256", "source_bundle_sha256",
              "availability", "bundle_schema_valid", "focus_missing_graph", "audit"}
SOURCE_PATHS = (
    "scripts/lab/lab_runner.py", "src/malpdf/extraction/orchestrator.py", "src/malpdf/static/profile_worker.py",
    "src/malpdf/static/evidence_ipc.py", "src/malpdf/static/evidence_v9.py", "src/malpdf/extraction/parser_views.py",
    "src/malpdf/extraction/mupdf_adapter.py", "src/malpdf/extraction/qpdf_adapter.py",
    "src/malpdf/extraction/raw_forensic.py", "src/malpdf/extraction/forensic_exports.py",
    "src/malpdf/extraction/normalize.py", "src/malpdf/extraction/numeric_export.py",
    "src/malpdf/extraction/graph_exports.py", "scripts/lab/extract_hetero_graphs.py",
)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def safe_path(path):
    path = Path(path).absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("audit_symlink_refused")
    return path


def read_bounded(path, limit):
    path = safe_path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("audit_file_limit")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("audit_file_limit")
    return value


def validate_row(row):
    if not isinstance(row, dict) or set(row) != ROW_FIELDS:
        raise ValueError("audit_row_shape")
    if (type(row["index"]) is not int or not 0 <= row["index"] < 10000
            or not isinstance(row["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
            or row["split"] not in {"train", "validation", "test"}
            or type(row["label"]) is not int or row["label"] not in (0, 1)
            or row["availability"] not in AVAILABILITIES or type(row["bundle_schema_valid"]) is not bool
            or row["focus_missing_graph"] is not None and type(row["focus_missing_graph"]) is not bool):
        raise ValueError("audit_row_metadata")
    for key in ("expected_bundle_sha256", "source_bundle_sha256"):
        if row[key] is not None and (not isinstance(row[key], str) or not re.fullmatch(r"[a-f0-9]{64}", row[key])):
            raise ValueError("audit_row_hash")
    if row["audit"] is not None:
        validate_case(row["audit"])
        if row["audit"]["sample_sha256"] != row["sha256"] or row["focus_missing_graph"] is not (row["audit"]["graph"]["projected_nodes"] == 0):
            raise ValueError("audit_row_identity")
    if row["availability"] == "present" and (row["audit"] is None or row["bundle_schema_valid"] is not True
            or row["source_bundle_sha256"] is None or row["source_bundle_sha256"] != row["expected_bundle_sha256"]):
        raise ValueError("audit_row_present_unverified")
    if row["availability"] == "missing" and (row["audit"] is not None or row["bundle_schema_valid"] is not False
            or row["source_bundle_sha256"] is not None or row["focus_missing_graph"] is not None):
        raise ValueError("audit_row_missing_contradiction")
    return row


def audit_report(metrics, cases):
    families = "\n".join(f"| `{name}` | {count} |" for name, count in sorted(metrics["focus_failure_families"].items()))
    examples = "\n".join(
        f"| {row['index']} | {row['audit']['graph']['parser_object_candidates']} | {row['audit']['graph']['parser_objects_observed']} | {row['audit']['graph']['parser_objects_with_projection']} | `{row['audit']['classification']['failure_family']}` |"
        for row in cases if row["index"] in (126, 141, 496, 749) and row["audit"] is not None)
    spans = metrics["node_distributions"]["original_object_span_bytes"]
    unknown_projected = metrics["graph_distributions"]["projected_sizes_unknown"]["total"]
    return f'''# Audit PDF Extractor and graph quality

## Result and scope

Audited {metrics['audited']}/{metrics['planned']} saved JSON bundles. Existing projection has {metrics['projected_graphs']} graphs and {metrics['focus_missing_graph']} empty projections. Input availability: `{json.dumps(metrics['availability_counts'], sort_keys=True)}`. No raw PDF was read, parsed, executed, copied or queued by this audit. Classifier training/evaluation was not run. `model_input_ready=false`.

## Missing projection classifications

| Evidence family | Cases |
| --- | ---: |
{families}

Cause status for the missing-projection cohort: `{json.dumps(metrics['focus_root_cause_status'], sort_keys=True)}`. Confirmed means a specific represented-view mechanism is supported; it does not certify a whole PDF as corrupt, harmless, or intrinsically ungraphable. Generic `worker_admission_failed` remains unresolved because the source catches OSError/ValueError across the profile call. A timeout confirms a recorded timeout, not its underlying root cause. Parser errors alone cannot prove PDF corruption. This audit does not certify legitimately empty PDFs without a verified completed relevant scope.

| Index | Parser candidates | Observed objects with projection | Objects with any projection | Classification |
| --- | ---: | ---: | ---: | --- |
{examples}

Inventory candidates and failed reads are not successful graph nodes. Multigraph edges, separate backend observations, shared references and cycles are retained. The old nine-kind projection excludes parser/forensic inventory records; available evidence is not silently promoted into a replacement model graph.

## Measurements

The projection retains at most 200 eligible nodes. {metrics['graphs_hitting_node_cap']} samples excluded additional eligible nodes by this cap. Node and edge exclusions are counted separately by kind, observation status, cap and retained endpoint membership. Structural issue totals: `{json.dumps(metrics['structural_issue_totals'], sort_keys=True)}`.

`original_object_span_bytes` is the verified half-open original-byte interval from the indirect object header through the end of `endobj`. It requires a raw-forensic observed top-level declaration, matching record/producer boundaries and object identity. Measured declarations: {spans['count']}; other evidence records retain null with an explicit reason. Direct semantic nodes, decoded object-stream members and unverified spans do not inherit another object's byte length. Overlapping spans are not summed into document coverage.

These measurements apply only to their own raw-forensic declaration records. They do not backfill the legacy semantic projection: {unknown_projected} retained projection nodes still have unknown legacy size_bytes attributes. No object-number-only or cross-backend join is used.

`node_record_storage_bytes` and graph wire storage count canonical JSON UTF-8 bytes (sorted keys, compact separators, ensure_ascii=false, finite numbers, no newline). Graph wire data consists of nodes/edges only. These are serialization costs, not original PDF size, RSS, or proposed model predictors. Source bundle file bytes are recorded separately.

Distributions use min/median/nearest-rank p95/max with known and null counts. `feature_dim=null` because this audit does not materialize a feature tensor. Legacy target dimension 19 is metadata only. No null-to-zero conversion or placeholder node is performed.

## Source execution map

Runner selection/hash pins → isolation/admission → disposable worker and append-only IPC checkpoints → legacy pypdf/MuPDF graph → native pypdf/QPDF/MuPDF inventory → original-byte forensic evidence → normalization → full evidence graph versus nine-kind projection/export.

The graph fallback already exists and is distinct from native inventory. QPDF inventory is not proof that a QPDF semantic graph was built. Backend graph status and native-view status are reported separately. The profile parent restores saved primary/checkpoint evidence on known worker failures; the orchestrator's outer generic exception path can replace profile diagnostics with worker_admission_failed. The legacy graph builder reads details.size_bytes with a zero fallback; the current numeric projection keeps unknown sizes null. This audit changes none of those producer paths.

## Proposed work order, not implemented

1. Preserve bounded error enums, originating stage and verified checkpoints through admission/IPC/profile failures. Investigate the unresolved generic worker errors before changing parser behavior.
2. Review evidence excluded by projection, beginning with samples with observed native objects. Define a separate versioned graph view before extending node kinds or merging backends; retain backend/revision provenance.
3. Reuse verified saved spans for applicable physical declarations. Define producers for still-missing model attributes; do not substitute JSON storage length for PDF object length.
4. Reproduce supported parser/fallback failures on safe fixtures. Propose offline diagnostic runs only for cases whose next_action requires new information; preserve the 1452 denominator and labels/splits.
5. Validate the complete cohort and an explicit unavailable-document policy before a later training-readiness decision. No demand for 1452 nonempty graphs is imposed.

The proposed diagnostic candidate indices are in metrics.json and cases.jsonl. The indices are a proposal, not an armed or queued job. Any future real-PDF parser run retains the operator `lab run` gate. Original bundles and historical experiments remain unchanged.
'''


def validate_metrics(metrics, cases):
    expected = summarize_cases(cases)
    additions = {"job_id", "availability_counts", "source_bundle_bytes", "source_schema_invalid", "partition_counts",
                 "offline_diagnostic_candidate_indices", "saved_evidence_review_indices"}
    if not isinstance(metrics, dict) or set(metrics) != set(expected) | additions:
        raise ValueError("audit_metrics_shape")
    if not isinstance(metrics["job_id"], str) or not re.fullmatch(r"[a-f0-9]{64}", metrics["job_id"]):
        raise ValueError("audit_metrics_job")
    for key in expected.keys() - {"node_distributions"}:
        if metrics[key] != expected[key]:
            raise ValueError("audit_metrics_consistency")
    if (metrics["availability_counts"] != dict(Counter(row["availability"] for row in cases))
            or metrics["partition_counts"] != dict(Counter(row["split"] for row in cases))
            or metrics["source_schema_invalid"] != sum(not row["bundle_schema_valid"] for row in cases)
            or type(metrics["source_bundle_bytes"]) is not int or not 0 <= metrics["source_bundle_bytes"] <= len(cases) * MAX_BUNDLE):
        raise ValueError("audit_metrics_counts")
    for key, actions in (("offline_diagnostic_candidate_indices", {"offline_diagnostic_required", "propose_diagnostic_preservation"}),
                         ("saved_evidence_review_indices", {"inspect_saved_projection"})):
        indices = [row["index"] for row in cases if row["audit"] is not None and row["audit"]["classification"]["next_action"] in actions]
        if metrics[key] != indices:
            raise ValueError("audit_metrics_candidates")
    if set(metrics["node_distributions"]) != {"original_object_span_bytes", "node_record_storage_bytes"}:
        raise ValueError("audit_metrics_distribution")
    for name, stats in metrics["node_distributions"].items():
        entries = [row["audit"]["measurements"][name] for row in cases if row["audit"] is not None]
        if set(stats) != {"count", "null_count", "min", "median", "p95", "max", "total"}:
            raise ValueError("audit_metrics_distribution")
        for key in ("count", "null_count", "total"):
            if type(stats[key]) is not int or stats[key] != sum(entry[key] for entry in entries):
                raise ValueError("audit_metrics_distribution_count")
        measured = [entry for entry in entries if entry["count"]]
        if not measured:
            if any(stats[key] is not None for key in ("min", "median", "p95", "max")):
                raise ValueError("audit_metrics_distribution_empty")
        elif (stats["min"] != min(entry["min"] for entry in measured) or stats["max"] != max(entry["max"] for entry in measured)
                or any(type(stats[key]) not in (int, float) or not stats["min"] <= stats[key] <= stats["max"] for key in ("median", "p95"))):
            raise ValueError("audit_metrics_distribution_range")
    canonical_bytes(metrics)
    return metrics


def audit_job(job_id, expected_index_path, *, job_root=Path("/var/lib/malpdf/jobs"),
              output_root=Path("/home/remnux/malpdf-graph-audits"), source_root=None):
    if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("audit_job_identity")
    directory = safe_path(Path(job_root) / job_id)
    job_payload = read_bounded(directory / "job.json", 65536)
    job = validate_job(parse_json(job_payload))
    if job["job_id"] != job_id:
        raise ValueError("audit_job_identity")
    selection_payload = read_bounded(directory / "selection.json", 4 * 1024**2)
    selection = parse_json(selection_payload)
    rows = selection["rows"]
    if (selection["job_id"] != job_id or sha(encoded(rows)) != selection["selection_sha256"]
            or len(rows) != job["limits"]["samples"]):
        raise ValueError("audit_selection_identity")
    result_payload = read_bounded(directory / "result.json", 16384)
    result = validate_result(parse_json(result_payload), job)
    if result["status"] not in {"passed", "partial", "failed", "interrupted", "blocked"}:
        raise ValueError("audit_result_not_final")
    index_payload = read_bounded(expected_index_path, 4 * 1024**2)
    expected = parse_json(index_payload)
    if not isinstance(expected, list) or len(expected) != len(rows):
        raise ValueError("audit_expected_index")
    for index, (row, pinned) in enumerate(zip(rows, expected)):
        if (not isinstance(pinned, dict) or set(pinned) != INDEX_FIELDS or type(pinned["index"]) is not int or pinned["index"] != index
                or pinned["sha256"] != row["pdf_sha256"] or pinned["split"] != row["split"]
                or type(pinned["label"]) is not int or pinned["label"] not in (0, 1) or str(pinned["label"]) != str(row["Label"])
                or pinned["split"] not in {"train", "validation", "test"} or not re.fullmatch(r"[a-f0-9]{64}", pinned["sha256"])
                or pinned["availability"] != "present" or not isinstance(pinned["source_bundle_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", pinned["source_bundle_sha256"])):
            raise ValueError("audit_expected_index")
    output_root = safe_path(output_root)
    if output_root.is_relative_to(safe_path(job_root)):
        raise ValueError("audit_output_inside_input")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_root / ("run_" + stamp + "_" + job_id[:12])
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    source_root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    source_hashes = {name: sha(read_bounded(source_root / name, 2 * 1024**2)) for name in SOURCE_PATHS if (source_root / name).is_file()}
    from malpdf.extraction import graph_audit
    methodology = {"schema_version": 1, "audit_version": "pdf-graph-audit-v1", "job": job,
                   "source_job_sha256": sha(job_payload), "source_result_sha256": sha(result_payload),
                   "selection_sha256": selection["selection_sha256"], "expected_index_sha256": sha(index_payload),
                   "audit_code_sha256": sha(read_bounded(Path(__file__), 2 * 1024**2) + read_bounded(Path(graph_audit.__file__), 2 * 1024**2)),
                   "extractor_source_hashes": source_hashes, "seed": 42, "node_cap": 200,
                   "original_object_span_bytes": "verified original raw-forensic indirect object header through endobj; half-open interval; no backend identity merge",
                   "storage_encoding": "JSON UTF-8; sorted keys; compact separators; ensure_ascii=false; allow_nan=false; no newline",
                   "graph_wire_scope": "nodes and edges only; excludes bundle metadata and features",
                   "p95": "nearest rank ceil(0.95*n)", "feature_dim": None, "legacy_target_feature_dim": 19,
                   "unknown_values": None, "raw_pdf_processing": False, "classifier_evaluation_executed": False,
                   "extractor_modified": False, "rerun_queued": False}
    (output / "locked_methodology.json").write_bytes(canonical_bytes(methodology))
    cases, statistics, source_bytes = [], {}, 0
    with (output / "cases.jsonl").open("xb") as stream:
        for index, pinned in enumerate(expected):
            row = {"index": index, "sha256": pinned["sha256"], "split": pinned["split"], "label": pinned["label"],
                   "expected_bundle_sha256": pinned["source_bundle_sha256"], "source_bundle_sha256": None,
                   "availability": "missing", "bundle_schema_valid": False, "focus_missing_graph": None, "audit": None}
            try:
                payload = read_bounded(directory / "private_bundles" / f"{index:04d}.json", MAX_BUNDLE)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                row["availability"] = "unsafe_or_oversize"
            else:
                source_bytes += len(payload)
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
                            try:
                                row["audit"] = audit_bundle(bundle, row["sha256"], statistics=statistics)
                                row["focus_missing_graph"] = row["audit"]["graph"]["projected_nodes"] == 0
                            except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                                row.update(availability="invalid_schema", bundle_schema_valid=False, audit=None)
            validate_row(row)
            line = canonical_bytes(row) + b"\n"
            if len(line) > 1024**2 or stream.tell() + len(line) > 64 * 1024**2:
                raise ValueError("audit_output_limit")
            stream.write(line)
            cases.append(row)
            if (index + 1) % 25 == 0 or index + 1 == len(expected):
                temporary = output / "progress.json.tmp"
                temporary.write_bytes(canonical_bytes({"processed": index + 1, "planned": len(expected)}))
                os.replace(temporary, output / "progress.json")
    metrics = summarize_cases(cases, statistics=statistics)
    metrics.update(job_id=job_id, availability_counts=dict(Counter(row["availability"] for row in cases)),
                   source_bundle_bytes=source_bytes, source_schema_invalid=sum(not row["bundle_schema_valid"] for row in cases),
                   partition_counts=dict(Counter(row["split"] for row in cases)),
                   offline_diagnostic_candidate_indices=[row["index"] for row in cases if row["audit"] is not None and row["audit"]["classification"]["next_action"] in {"offline_diagnostic_required", "propose_diagnostic_preservation"}],
                   saved_evidence_review_indices=[row["index"] for row in cases if row["audit"] is not None and row["audit"]["classification"]["next_action"] == "inspect_saved_projection"])
    validate_metrics(metrics, cases)
    (output / "metrics.json").write_bytes(canonical_bytes(metrics))
    (output / "audit_report.md").write_text(audit_report(metrics, cases), encoding="utf-8")
    manifest = {"schema_version": 1, "job_id": job_id, "records": len(cases),
                "files": [{"name": name, "bytes": (output / name).stat().st_size,
                           "sha256": sha(read_bounded(output / name, 64 * 1024**2))}
                          for name in ("locked_methodology.json", "cases.jsonl", "metrics.json", "audit_report.md")]}
    (output / "manifest.json").write_bytes(canonical_bytes(manifest))
    return {"output": str(output), "job_id": job_id, "records": len(cases),
            "focus_missing_graph": metrics["focus_missing_graph"], "model_input_ready": False, "raw_pdf_processing": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-index", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("/home/remnux/malpdf-graph-audits"))
    args = parser.parse_args()
    try:
        if sys.platform != "linux":
            raise ValueError("audit_lab_only")
        import lab_jobs as jobs
        import lab_side as side
        job = jobs.load_job(args.job_id)
        metadata = side.verify_release(job["commit"], job["manifest_sha256"])
        jobs.verify_helpers(metadata)
        value = audit_job(args.job_id, args.expected_index, output_root=args.output_root, source_root=side.RELEASES / job["commit"])
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"status": "failed", "reason": "audit_failed"}))
        return 2
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
