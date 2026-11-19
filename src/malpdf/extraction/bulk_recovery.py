"""Offline adoption and parity checks against sealed, previously saved chunks."""

import json
import tempfile
from pathlib import Path

from malpdf.extraction.bulk_checkpoint import (
    SHA, comparable_rows, different_artifacts, file_sha256, matches_checkpoint, read_chunk, replacement_archive,
)
from malpdf.extraction.graph_audit import canonical_bytes


LIFECYCLE_DISPOSITIONS = {"rejected_unverified_cleanup", "unavailable_worker_failure", "unavailable_timeout_no_graph"}


def checkpoint_partition(contract):
    hashes = contract["checkpoint_sha256"]
    count = contract["adopted_checkpoint_count"]
    replacements = contract["replaced_checkpoints"]
    if (not isinstance(hashes, list) or any(not isinstance(h, str) or not SHA.fullmatch(h) for h in hashes)
            or type(count) is not int or not 0 <= count <= len(hashes)
            or replacements != {str(i): hashes[i] for i in range(count, len(hashes))}):
        raise ValueError("bulk_recovery_checkpoint_partition")
    return tuple(hashes[:count]), {int(i): h for i, h in replacements.items()}


def load_baseline(output, entries, contract, selected=()):
    _, replacements = checkpoint_partition(contract)
    rows = []
    selected = set(selected)
    comparable = {}
    for index, expected in enumerate(contract["checkpoint_sha256"]):
        path = output / "chunks" / f"chunk_{index:05d}"
        if index in replacements and not matches_checkpoint(path, expected):
            path = replacement_archive(path, expected)
        if not matches_checkpoint(path, expected):
            raise ValueError("bulk_recovery_baseline_hash")
        chunk = read_chunk(path, entries[index * 500:(index + 1) * 500], chunk_id=index, include_markov=True)
        by_sha = {row["sha256"]: {"dropped_nodes_cap": row["dropped_nodes_cap"]} for row in chunk.graphs}
        rows.extend(({
            "index": row["index"], "sha256": row["sha256"], "sample_disposition": row["sample_disposition"],
            "features": {"raw_size_bytes": row["features"].get("raw_size_bytes", {})},
        }, by_sha.get(row["sha256"])) for row in chunk.tabular)
        if selected:
            comparable.update(comparable_rows(chunk, selected))
        del chunk, by_sha
    if selected and set(comparable) != selected:
        raise ValueError("bulk_recovery_baseline_pilot")
    return rows, comparable


def select_pilot(rows):
    selected = {}

    def take(candidates, count, stratum):
        available = [(row, graph) for row, graph in candidates if row["sha256"] not in selected]
        if len(available) < count:
            raise ValueError("bulk_recovery_pilot_stratum")
        for row, _ in available[:count]:
            selected[row["sha256"]] = (row["index"], stratum)

    ordered = sorted(rows, key=lambda pair: pair[0]["sha256"])
    unavailable = [(row, graph) for row, graph in ordered if graph is None]
    take((pair for pair in unavailable if pair[0]["sample_disposition"] in LIFECYCLE_DISPOSITIONS), 16, "worker")
    take((pair for pair in unavailable if pair[0]["sample_disposition"] not in LIFECYCLE_DISPOSITIONS), 16, "unavailable")
    take((pair for pair in ordered if pair[1] is not None and pair[1]["dropped_nodes_cap"] > 0), 16, "cap")
    sized = [(row["features"].get("raw_size_bytes", {}).get("value"), row, graph) for row, graph in ordered]
    large = sorted((item for item in sized if type(item[0]) in (int, float)),
                   key=lambda item: (-item[0], item[1]["sha256"]))
    take(((row, graph) for _, row, graph in large), 16, "large")
    take((pair for pair in ordered if pair[1] is not None), 64, "graph")
    return sorted(({"sha256": sha, "index": index, "stratum": stratum}
                   for sha, (index, stratum) in selected.items()), key=lambda row: row["index"])


def compare_pilot(selection, baseline, candidate, diagnostics):
    counts = {"matched": 0, "recovered": 0, "unexplained": 0}
    details = []
    if set(baseline) != set(candidate) or set(baseline) != {row["sha256"] for row in selection}:
        raise ValueError("bulk_recovery_pilot_identities")
    for item in selection:
        sha = item["sha256"]
        old, new = baseline[sha], candidate[sha]
        changes = different_artifacts(old, new)
        if not changes:
            counts["matched"] += 1
            continue
        prev, current = old["tabular"], new["tabular"]
        diagnostic = diagnostics.get(sha, {})
        identity_ok = all(prev[key] == current[key] for key in ("index", "sha256", "source", "label", "label_source", "split"))
        measured_ok = all(current["features"].get(key) == value
                          for key, value in prev["features"].items() if value["value"] is not None)
        recovered = (
            item["stratum"] == "worker" and prev["sample_disposition"] in LIFECYCLE_DISPOSITIONS
            and old["graph"] is None and new["graph"] is not None and identity_ok and measured_ok
            and "markov" not in changes and diagnostic.get("cleanup_complete") is True
            and diagnostic.get("result_verified") is True
        )
        outcome = "recovered" if recovered else "unexplained"
        counts[outcome] += 1
        details.append({**item, "artifacts": changes, "outcome": outcome,
                        "before": prev["sample_disposition"], "after": current["sample_disposition"],
                        "cleanup_confirmed": diagnostic.get("cleanup_complete")})
    return {"counts": counts, "differences": details}


def run_pilot(directory, output, entries, plan, run, diagnostics, *, commit):
    selected = plan["pilot"]
    pilot_entries = [entries[row["index"]] for row in selected]
    marker = directory / "bulk_pilot_passed.json"
    report = directory / "bulk_pilot_report.json"
    identity = {"commit": commit, "plan_sha256": file_sha256(directory / "bulk_plan.json")}
    if marker.is_file():
        if json.loads(marker.read_bytes()) != dict(identity, report_sha256=file_sha256(report)):
            raise ValueError("bulk_recovery_pilot_marker")
        return
    _, baseline = load_baseline(output, entries, plan["baseline"], (row["sha256"] for row in selected))
    pilot_dir = Path(tempfile.mkdtemp(prefix="bulk_pilot-", dir=directory))
    timing = run(pilot_entries, pilot_dir, len(selected))
    chunk = read_chunk(pilot_dir / "chunks/chunk_00000", pilot_entries, chunk_id=0, include_markov=True)
    result = compare_pilot(selected, baseline, comparable_rows(chunk, baseline), diagnostics)
    result.update(identity, timing=timing)
    report.write_bytes(canonical_bytes(result) + b"\n")
    if result["counts"]["unexplained"]:
        raise ValueError("bulk_recovery_pilot_mismatch")
    temporary = marker.with_suffix(".tmp")
    temporary.write_bytes(canonical_bytes(dict(identity, report_sha256=file_sha256(report))) + b"\n")
    temporary.replace(marker)
