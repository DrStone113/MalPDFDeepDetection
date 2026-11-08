from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(1, str(Path(__file__).resolve().parent))

from lab_jobs import validate_result
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.numeric_export import project_numeric_bundle, validate_numeric_projection


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def read_bounded(path, limit):
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("symlink_refused")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("size_limit")
    return value


def save_progress(directory, value):
    temporary = directory / "progress.json.tmp"
    temporary.write_bytes(encoded(value))
    os.replace(temporary, directory / "progress.json")


def export_job(job_id, *, job_root=Path("/var/lib/malpdf/jobs"), export_root=Path("/var/lib/malpdf/exports")):
    if sys.platform != "linux" or not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("job_identity")
    directory = job_root / job_id
    job_payload = read_bounded(directory / "job.json", 65536)
    job = json.loads(job_payload)
    if job.get("job_id") != job_id or digest(encoded({key: value for key, value in job.items() if key != "job_id"})) != job_id:
        raise ValueError("job_identity")
    selection_payload = read_bounded(directory / "selection.json", 4 * 1024**2)
    selection = json.loads(selection_payload)
    rows = selection["rows"]
    if (selection["job_id"] != job_id or digest(encoded(rows)) != selection["selection_sha256"]
            or len(rows) != job["limits"]["samples"]):
        raise ValueError("selection_identity")
    result_payload = read_bounded(directory / "result.json", 1024**2)
    result = validate_result(json.loads(result_payload), job)
    if result["status"] not in {"passed", "partial", "failed", "blocked", "interrupted"}:
        raise ValueError("result_identity")
    from malpdf.extraction import numeric_export
    code_id = digest(read_bounded(Path(__file__), 1024**2) + read_bounded(Path(numeric_export.__file__), 1024**2)
                     + read_bounded(Path(numeric_export.__file__).with_name("numeric_feature_names.py"), 1024**2))
    output = export_root / job_id / code_id
    if any(item.is_symlink() for item in (output, *output.parents)):
        raise ValueError("symlink_refused")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    statuses, availability, partitions = Counter(), Counter(), Counter()
    features_present, features_nonnull = Counter(), Counter()
    missing, invalid, cleanup_incomplete = [], [], []
    graphs = graph_nodes = graphs_unknown_sizes = total_bytes = source_bytes = 0
    started = time.monotonic()
    target = output / "numeric.jsonl.gz"
    with gzip.open(target, "wb") as stream:
        for index, row in enumerate(rows):
            sha256, split, raw_label = row["pdf_sha256"], row["split"], row["Label"]
            if not (type(raw_label) is int and raw_label in (0, 1) or type(raw_label) is str and raw_label in ("0", "1")):
                raise ValueError("selection_metadata")
            label = int(raw_label)
            if (not re.fullmatch(r"[a-f0-9]{64}", sha256) or split not in {"train", "validation", "test"}
                    or label not in (0, 1)):
                raise ValueError("selection_metadata")
            record = {"index": index, "sha256": sha256, "split": split, "label": label,
                      "source_bundle_sha256": None, "availability": "missing", "numeric": None}
            path = directory / "private_bundles" / f"{index:04d}.json"
            if path.exists():
                payload = read_bounded(path, 8 * 1024**2 + 1024)
                source_bytes += len(payload)
                record["source_bundle_sha256"] = digest(payload)
                try:
                    bundle = json.loads(payload)
                    validate_bundle(bundle)
                    value = project_numeric_bundle(bundle, sha256)
                    validate_numeric_projection(value, sha256)
                except (ValueError, TypeError, KeyError, OverflowError):
                    record["availability"] = "invalid"
                    invalid.append(index)
                else:
                    record.update(availability="present", numeric=value)
                    statuses[value["status"]] += 1
                    if value["worker"]["worker_cleanup_complete"] is not True:
                        cleanup_incomplete.append(index)
                    graph = value["graph"]
                    graphs += bool(graph["node_types"])
                    graph_nodes += len(graph["node_types"])
                    graphs_unknown_sizes += bool(graph["node_types"]) and not graph["observed_attributes_complete"]
                    for name, observation in value["features"].items():
                        features_present[name] += 1
                        features_nonnull[name] += observation["value"] is not None
                del payload
            else:
                missing.append(index)
            availability[record["availability"]] += 1
            partitions[f"{split}/{record['availability']}"] += 1
            line = encoded(record) + b"\n"
            if len(line) > 2 * 1024**2 or total_bytes + len(line) > 512 * 1024**2:
                raise ValueError("export_size_limit")
            stream.write(line)
            total_bytes += len(line)
            if (index + 1) % 25 == 0 or index + 1 == len(rows):
                stream.flush()
                save_progress(output, {"schema_version": 1, "processed": index + 1, "planned": len(rows),
                                       "availability": dict(availability), "elapsed_seconds": round(time.monotonic() - started, 3)})
    metrics = {"schema_version": 1, "job_id": job_id, "planned": len(rows), "availability": dict(availability),
               "status_counts": dict(statuses), "partition_coverage": dict(partitions),
               "missing_indices": missing, "invalid_indices": invalid, "cleanup_incomplete_indices": cleanup_incomplete,
               "graphs_with_observed_nodes": graphs, "observed_graph_nodes": graph_nodes,
               "graphs_with_unknown_node_sizes": graphs_unknown_sizes,
               "features_present": dict(features_present), "features_nonnull": dict(features_nonnull),
               "source_bundle_bytes": source_bytes, "uncompressed_export_bytes": total_bytes,
               "elapsed_seconds": round(time.monotonic() - started, 3), "model_input_ready": False,
               "raw_pdf_processing": False, "classifier_inference_executed": False}
    (output / "coverage.json").write_bytes(encoded(metrics))
    manifest = {"schema_version": 1, "job_id": job_id, "export_code_sha256": code_id,
                "selection_sha256": selection["selection_sha256"], "source_result_sha256": digest(result_payload),
                "generated_utc": datetime.now(timezone.utc).isoformat(), "records": len(rows),
                "files": [{"name": name, "sha256": digest((output / name).read_bytes()), "bytes": (output / name).stat().st_size}
                          for name in ("numeric.jsonl.gz", "coverage.json")]}
    (output / "manifest.json").write_bytes(encoded(manifest))
    return {"output": str(output), "job_id": job_id, "records": len(rows), "availability": dict(availability),
            "model_input_ready": False, "raw_pdf_processing": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export_job(args.job_id), sort_keys=True), flush=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        allowed = {"job_identity", "selection_identity", "selection_metadata", "result_identity", "symlink_refused", "size_limit", "export_size_limit"}
        print(json.dumps({"status": "failed", "reason": str(error) if str(error) in allowed else "export_failed"}), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
