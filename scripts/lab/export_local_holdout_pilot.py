from __future__ import annotations

from collections import Counter, defaultdict
from functools import partial
import gzip
import json
from pathlib import Path
import sys

from export_vapd_retrospective_inputs import FINAL, INPUT_HASHES, csv_rows, digest, graph_arrays, json_rows
from malpdf.extraction import holdout_fingerprint_job as verifier
from malpdf.extraction.tlsh import DISTANCE_LIMIT, nearest_distances, screen

JOB_ID = "ab9d14ec6add09511bc99dde9d191781793b9d5fc1b52610912f01485674c7da"
REPORT_SHA256 = "30d1ce3f32bc34cdc1e2d4bc0c7a13d6bf442111810d5588f00f49b868476bb1"
METADATA_SHA256 = "0801db2a5243b18a5194bee2229dba0b5f45e56d88d1ddf4cd192614fc0208dd"
TLSH_MIN_BYTES = 50
EXPECTED_GROUPS = {"govdocs1_review": 132, "vapd_d1_positive": 13}
BOOKKEEPING = {"govdocs1_review": ("", "unverified_govdocs1_sample"),
               "vapd_d1_positive": ("1", "vapd_v5_d1_malicious")}


def group_near_duplicates(candidates, compare):
    neighbors = defaultdict(set)
    items = sorted(candidates.items())
    for pos, (left, fingerprint) in enumerate(items[:-1]):
        right_side = items[pos + 1:]
        distances = compare([fingerprint], [value for _, value in right_side])
        for (right, _), distance in zip(right_side, distances, strict=True):
            if distance <= DISTANCE_LIMIT:
                neighbors[left].add(right)
                neighbors[right].add(left)
    grouped = {}
    for sha, _ in items:
        if sha in grouped:
            continue
        pending = [sha]
        while pending:
            current = pending.pop()
            if current in grouped:
                continue
            grouped[current] = sha
            pending.extend(neighbors[current] - grouped.keys())
    return grouped


def emit(root, out):
    stage = root / verifier.INPUT_DIRECTORY
    report_path = Path("/var/lib/malpdf/jobs") / JOB_ID / "holdout_fingerprints.json"
    report = json.loads(verifier.pinned(report_path, report_path.parent, REPORT_SHA256, 16 * 1024**2))
    plan = json.loads(verifier.pinned(stage / "fingerprint_plan.json", stage, verifier.PLAN_SHA256, 8 * 1024**2))
    engine = verifier.pinned(stage / "tlsh_holdout_audit", stage, verifier.ENGINE_SHA256, 2 * 1024**2)
    reference, candidates, exact_only, groups = {}, {}, set(), {}
    for entry, row in zip(plan["entries"], report["fingerprints"], strict=True):
        sha = entry["sha256"]
        if sha != row["sha256"] or row["status"] not in ("measured", "tlsh_unavailable"):
            raise ValueError("unverified_pilot_input")
        if entry["group"] == "historical_v4":
            reference[sha] = row["tlsh"]
            if row["tlsh"] is None and entry["bytes"] < TLSH_MIN_BYTES:
                exact_only.add(sha)
        else:
            if row["tlsh"] is None:
                raise ValueError("pilot_candidate_without_fingerprint")
            candidates[sha] = row["tlsh"]
            groups[sha] = entry["group"]
    if (len(reference) != 21414 or len(exact_only) != 1 or candidates.keys() & reference.keys()
            or Counter(groups.values()) != EXPECTED_GROUPS or report["publisher_sha1_matches"] != 132):
        raise ValueError("unexpected_pilot_membership")

    with verifier.sealed_engine(engine) as descriptor:
        compare = partial(nearest_distances, f"/proc/self/fd/{descriptor}", pass_fds=(descriptor,))
        comparison = screen({key: val for key, val in reference.items() if key not in exact_only}, candidates, compare)
        clusters = group_near_duplicates(candidates, compare)
    if any(item["disposition"] != "no_near_duplicate_in_reference" for item in comparison.values()):
        raise ValueError("pilot_scope_has_overlap_or_missing_fingerprints")
    if len(set(clusters.values())) != 142 or any(groups[sha] != groups[rep] for sha, rep in clusters.items()):
        raise ValueError("unexpected_pilot_clusters")

    manifest_path = root / FINAL / "manifest.json"
    metadata_path = root / FINAL / "corpus_metadata.csv"
    graphs_path = root / FINAL / "hetero_graphs_v2.jsonl.gz"
    if digest(manifest_path) != INPUT_HASHES[f"{FINAL}/manifest.json"] or digest(metadata_path) != METADATA_SHA256:
        raise ValueError("unexpected_bulk_export")
    graph_hash = json.loads(manifest_path.read_text(encoding="utf-8"))["files"][graphs_path.name]
    if digest(graphs_path) != graph_hash:
        raise ValueError("changed_bulk_graphs")

    metadata = {}
    for row in csv_rows(metadata_path):
        sha = row["sha256"]
        if sha in groups:
            if (sha in metadata or (row["label"], row["label_source"]) != BOOKKEEPING[groups[sha]]
                    or row["gnn_eligible"].lower() != "true"):
                raise ValueError("pilot_label_or_eligibility_mismatch")
            metadata[sha] = row
    if metadata.keys() != groups.keys():
        raise ValueError("pilot_metadata_population_changed")
    seen = set()
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=4, mtime=0) as compressed:
        def write(value):
            compressed.write(json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n")

        write({"schema_version": 1, "fingerprint_report_sha256": REPORT_SHA256, "graphs_sha256": graph_hash,
               "reference_exact_sha256_count": len(reference), "reference_tlsh_count": len(reference) - len(exact_only),
               "under_minimum_reference_exact_only": len(exact_only), "tlsh_minimum_bytes": TLSH_MIN_BYTES,
               "distance_threshold_inclusive": DISTANCE_LIMIT, "candidate_counts": EXPECTED_GROUPS,
               "cluster_counts": dict(Counter(groups[rep] for rep in set(clusters.values())))})
        for row in json_rows(graphs_path):
            sha = row["sha256"]
            if sha not in metadata:
                continue
            info = metadata[sha]
            label = 1 if groups[sha] == "vapd_d1_positive" else None
            if sha in seen or row.get("label") != label or row["status"] != info["status"]:
                raise ValueError("pilot_graph_identity_mismatch")
            seen.add(sha)
            write([sha, clusters[sha], groups[sha], label, row["status"], comparison[sha]["distance"], *graph_arrays(row)])
        if seen != groups.keys():
            raise ValueError("missing_pilot_graphs")


if __name__ == "__main__":
    emit(Path.cwd(), sys.stdout.buffer)
