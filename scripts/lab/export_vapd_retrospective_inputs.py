from collections import Counter
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import sys


FINAL = "data/processed/bulk_extract/final"
PRIOR = "data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732"
INPUT_HASHES = {
    f"{FINAL}/manifest.json": "1648e1e4f5bcc3b50bdec53e05d2d67132fb424159cc1ce64a0ed1b891661568",
    f"{PRIOR}/source_manifest.csv": "d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b",
    f"{PRIOR}/split_manifest.csv": "e939a676c51c7a98b9dc4bb843e846f546e1ada2bfb576b41416c406415c0643",
}
TABULAR_FEATURES = (
    "lexical_AA", "lexical_Acroform", "lexical_EmbeddedFile", "lexical_Encrypt",
    "lexical_JBIG2Decode", "lexical_JS", "lexical_JavaScript", "lexical_Launch",
    "lexical_ObjStm", "lexical_OpenAction", "lexical_Resources", "lexical_RichMedia",
    "lexical_Root", "lexical_URI", "lexical_XFA", "lexical_endobj", "lexical_endstream",
    "lexical_obj", "lexical_page_command", "lexical_stream", "lexical_trailer",
    "lexical_xref", "raw_size_bytes", "raw_entropy", "raw_prefix_entropy",
)
SPLITS = ("train", "validation", "test")
STATUSES = ("bounded_complete", "decode_error", "partial", "unsupported")
GRAPH_KEYS = ("node_features", "node_types", "edge_src", "edge_dst", "edge_rel")
LABELS = {"vapd_v5_d1_benign": 0, "vapd_v5_d1_malicious": 1}
EXPECTED_COUNTS = dict(zip(SPLITS, (11314, 3900, 4049), strict=True))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def csv_rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        yield from csv.DictReader(stream)


def json_rows(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        yield from map(json.loads, stream)


def all_ints(values, ceiling):
    return all(type(value) is int and 0 <= value < ceiling for value in values)


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e30


def graph_arrays(row):
    features, types, edge_src, edge_dst, edge_rel = (row[key] for key in GRAPH_KEYS)
    count = len(features)
    if not (
        0 < count <= 200
        and row["node_feature_dim"] == 23
        and len(types) == count
        and all(len(node) == 23 and all(map(finite_number, node)) for node in features)
        and all_ints(types, 9)
        and len(edge_src) == len(edge_dst) == len(edge_rel)
        and len(edge_src) <= 40000
        and all_ints(edge_src, count)
        and all_ints(edge_dst, count)
        and all_ints(edge_rel, 8)
    ):
        raise ValueError("invalid_graph_arrays")
    return [features, types, edge_src, edge_dst, edge_rel]


def emit(root, out):
    manifest = json.loads((root / FINAL / "manifest.json").read_text(encoding="utf-8"))
    tabular = "tabular_features_v2.jsonl.gz"
    graphs = "hetero_graphs_v2.jsonl.gz"
    locked = {
        **INPUT_HASHES,
        **{f"{FINAL}/{name}": manifest["files"][name] for name in (tabular, graphs)},
    }
    if any(digest(root / rel) != expected for rel, expected in locked.items()):
        raise ValueError("pinned_artifact_hash_mismatch")

    splits = {row["sample_id"]: row for row in csv_rows(root / PRIOR / "split_manifest.csv")}
    historical = {
        row["pdf_sha256"]: splits[row["sample_id"]]
        for row in csv_rows(root / PRIOR / "source_manifest.csv")
        if row["sample_id"] in splits and splits[row["sample_id"]]["cohort"] == "source_raw"
    }
    pending = {}
    counts = Counter()
    for row in json_rows(root / FINAL / tabular):
        identity = row["sha256"]
        role = historical.get(identity)
        source_label = LABELS.get(row["label_source"])
        if role is None or source_label is None:
            continue
        if (
            not re.fullmatch(r"[0-9a-f]{64}", identity)
            or identity in pending
            or row["label"] != source_label
            or int(role["Label"]) != source_label
            or row["evaluation_handling"] != "graph_and_tabular"
            or row["gnn_message_passing_eligible"] is not True
        ):
            raise ValueError("historical_identity_label_or_eligibility_mismatch")
        feature_rows = [row["features"].get(name, {}) for name in TABULAR_FEATURES]
        values = [record.get("value") for record in feature_rows]
        if not all(
            record.get("status") in ("observed", "absent_within_scope") and finite_number(value)
            for record, value in zip(feature_rows, values, strict=True)
        ):
            raise ValueError("unmeasured_tabular_input")
        split = role["split"]
        pending[identity] = [identity, SPLITS.index(split), source_label, STATUSES.index(row["status"]), values]
        counts[split] += 1
    if counts != EXPECTED_COUNTS:
        raise ValueError(f"historical_denominator_mismatch {counts}")

    header = {"schema_version": 1, "features": TABULAR_FEATURES, "inputs": locked,
              "counts": EXPECTED_COUNTS, "splits": SPLITS, "statuses": STATUSES}
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=4, mtime=0) as stream:
        stream.write(json.dumps(header, separators=(",", ":")).encode("ascii") + b"\n")
        for row in json_rows(root / FINAL / graphs):
            sample = pending.pop(row["sha256"], None)
            if sample is None:
                continue
            if row["label"] != sample[2] or row["status"] != STATUSES[sample[3]]:
                raise ValueError("graph_label_or_status_mismatch")
            numeric = sample + graph_arrays(row)
            stream.write(json.dumps(numeric, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n")
        if pending:
            raise ValueError("missing_graph_rows")


if __name__ == "__main__":
    config = json.loads(Path("/etc/malpdf/runner.json").read_text(encoding="utf-8"))
    emit(Path(config["data_root"]), sys.stdout.buffer)
