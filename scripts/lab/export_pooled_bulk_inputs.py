from collections import Counter
import gzip
import json
from pathlib import Path
import re
import sys

from scripts.lab.export_vapd_retrospective_inputs import (
    FINAL, INPUT_HASHES, TABULAR_FEATURES, csv_rows, digest, finite_number, graph_arrays, json_rows,
)


COUNTS = {"benign": 9638, "malicious": 11785, "unlabeled": 20304}
CLASSES = {0: "benign", 1: "malicious", None: "unlabeled"}
METADATA_SHA256 = "0801db2a5243b18a5194bee2229dba0b5f45e56d88d1ddf4cd192614fc0208dd"
GRAPH_COUNT = 41447
REJECTED = "rejected_unverified_cleanup"


def pooled_table(row):
    if row["sample_disposition"] == REJECTED:
        return [None] * len(TABULAR_FEATURES)
    fields = [row["features"].get(name, {}) for name in TABULAR_FEATURES]
    return [field["value"] if field.get("status") in ("observed", "absent_within_scope")
            and finite_number(field.get("value")) else None for field in fields]


def emit(data_root, out):
    final = data_root / FINAL
    manifest_path = final / "manifest.json"
    manifest_sha = digest(manifest_path)
    if manifest_sha != INPUT_HASHES[f"{FINAL}/manifest.json"]:
        raise ValueError("bulk_manifest_changed")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    table_path = final / "tabular_features_v2.jsonl.gz"
    graph_path = final / "hetero_graphs_v2.jsonl.gz"
    metadata_path = final / "corpus_metadata.csv"
    locked = {metadata_path.name: METADATA_SHA256,
              **{path.name: manifest["files"][path.name] for path in (table_path, graph_path)}}
    if any(digest(final / name) != expected for name, expected in locked.items()):
        raise ValueError("bulk_artifact_changed")

    metadata = {}
    for row in csv_rows(metadata_path):
        sha = row["sha256"]
        label = {"": None, "0": 0, "1": 1}[row["label"]]
        if (sha in metadata or not re.fullmatch(r"[0-9a-f]{64}", sha)
                or not re.fullmatch(r"[a-z0-9_]{1,80}", row["label_source"])):
            raise ValueError("invalid_bulk_identity_or_source")
        metadata[sha] = (label, row["label_source"], row["status"], row["gnn_eligible"] == "True")
    if Counter(CLASSES[row[0]] for row in metadata.values()) != COUNTS:
        raise ValueError("bulk_class_counts_changed")

    pending = {}
    expected_graphs = set()
    for row in json_rows(table_path):
        sha = row["sha256"]
        label, source, status, graph = metadata[sha]
        if sha in pending or (row.get("label"), row["label_source"], row["status"],
                              row["gnn_message_passing_eligible"]) != (label, source, status, graph):
            raise ValueError("inconsistent_bulk_table_metadata")
        pending[sha] = [sha, label, source, status, pooled_table(row)]
        if graph:
            if row["sample_disposition"] == REJECTED:
                raise ValueError("unexpected_graph_for_rejected_record")
            expected_graphs.add(sha)
    if pending.keys() != metadata.keys() or len(expected_graphs) != GRAPH_COUNT:
        raise ValueError("bulk_feature_membership_changed")

    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=4, mtime=0) as stream:
        def write(value):
            stream.write(json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n")

        write({"schema_version": 1, "features": TABULAR_FEATURES, "counts": COUNTS, "graphs": GRAPH_COUNT,
               "source_sha256": {manifest_path.name: manifest_sha, **locked}})
        for row in json_rows(graph_path):
            sha = row["sha256"]
            expected_graphs.remove(sha)
            sample = pending.pop(sha)
            if (row.get("label"), row["status"]) != (sample[1], sample[3]):
                raise ValueError("inconsistent_bulk_graph_metadata")
            write([*sample, graph_arrays(row)])
        if expected_graphs:
            raise ValueError("bulk_graph_membership_changed")
        for sample in pending.values():
            write([*sample, None])


if __name__ == "__main__":
    config = json.loads(Path("/etc/malpdf/runner.json").read_text(encoding="utf-8"))
    emit(Path(config["data_root"]), sys.stdout.buffer)
