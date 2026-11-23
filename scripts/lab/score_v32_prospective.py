"""Locked prospective scorer for v3.2 Subset B (Track B-v2 diverse publishers + Track C1-v2 hard-benign)."""

from __future__ import annotations

import argparse
from functools import partial
import json
from pathlib import Path
from typing import Any

import torch

from malpdf.extraction.tlsh import TLSH_RE, nearest_distances
from malpdf.features.contract_v3 import FEATURES
from scripts.lab.build_clean_splits import native
from scripts.lab.score_benign_ood import admit, digest, evaluation, read_json, references, score_rows
from scripts.lab.score_diverse_benign_ood import active_feature_slices

IDX = {n: i for i, n in enumerate(FEATURES)}


def partition_subset_b(
    entries: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    assignments: dict[str, str],
) -> dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    """Select only prospective Subset B rows and split into Track B-v2 and Track C1-v2."""
    tracks = ("prospective_diverse_publishers_v2", "prospective_hard_benign_v2")
    entry_by_id = {e["id"]: e for e in entries}
    row_by_id = {r["id"]: r for r in rows}
    if set(entry_by_id) != set(row_by_id):
        raise ValueError("subset_b_membership_mismatch")
    out: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
    for tname in tracks:
        t_ids = sorted(i for i, sub in assignments.items() if sub == tname and i in entry_by_id)
        out[tname] = ([entry_by_id[i] for i in t_ids], [row_by_id[i] for i in t_ids])
    return out


def compute_hard_benign_slices(
    export_rows: list[dict[str, Any]],
    eval_rows: list[dict[str, Any]],
    prospective_thr: float,
) -> dict[str, dict[str, Any]]:
    """Compute standard active-feature slices plus tiny-PDF (<= 10 KB) and 0.50 alerts."""
    slices = active_feature_slices(export_rows, eval_rows, prospective_thr)
    feat_by_id = {r["id"]: r.get("features") for r in export_rows}
    scored = [r for r in eval_rows if r.get("score_status") == "scored"]
    small = [
        r for r in scored
        if feat_by_id.get(r["id"]) is not None
        and feat_by_id[r["id"]][IDX["raw_size_bytes"]] is not None
        and feat_by_id[r["id"]][IDX["raw_size_bytes"]] <= 10240
    ]
    s_probs = [r["probability"] for r in small]
    slices["small_le_10kb"] = {
        "count": len(small),
        "fp_prospective": sum(p >= prospective_thr for p in s_probs),
        "fp_050": sum(p >= 0.50 for p in s_probs),
        "max_prob": max(s_probs) if s_probs else None,
    }
    return slices


def score_v32_subset_b(
    *,
    export_doc: dict[str, Any],
    membership: dict[str, Any],
    assignments: dict[str, str],
    train_refs: dict[str, str],
    study_refs: dict[str, str],
    exact_pool: set[str],
    thresholds: dict[str, float],
    decision_target_fpr: float,
    distance_exec: Path,
    component_exec: Path,
    model_config: Path,
    scaler: Path,
    weights: Path,
    temperature: float,
) -> dict[str, Any]:
    nearest = partial(nearest_distances, distance_exec)
    comp = lambda hashes: native(component_exec, ["--components"], str(len(hashes)), hashes)
    scorer = partial(score_rows, cfg=model_config, scaler=scaler, weights=weights, temperature=temperature)
    partitioned = partition_subset_b(membership["entries"], export_doc["rows"], assignments)

    tracks: dict[str, Any] = {}
    for track_name, (t_entries, t_rows) in partitioned.items():
        decisions = admit(t_rows, train_refs, study_refs, exact_pool, nearest, comp)
        report = evaluation({**export_doc, "rows": t_rows}, {**membership, "entries": t_entries}, decisions, thresholds, scorer)
        report["active_feature_slices"] = compute_hard_benign_slices(t_rows, report["rows"], thresholds["prospective"])
        tracks[track_name] = report

    pub = tracks["prospective_diverse_publishers_v2"]
    ind = pub["metrics"].get("independent_representatives", {})
    prim = ind.get("thresholds", {}).get("prospective", {})
    upper = prim.get("one_sided_95_upper")
    complete = bool(ind) and prim.get("evaluated") == ind["denominator_before_admission"]
    qualified = complete and upper is not None and upper <= decision_target_fpr
    return {
        "representative_scoring_complete": complete,
        "primary_threshold_qualified": qualified,
        "tracks": tracks,
    }


def _collect_refs(paths: list[Path]) -> tuple[dict[str, str], set[str]]:
    tls: dict[str, str] = {}
    shas: set[str] = set()
    for p in paths:
        for row in read_json(p)["rows"]:
            shas.add(row["sha256"])
            if row.get("tlsh") and TLSH_RE.fullmatch(row["tlsh"]):
                tls[row["sha256"]] = row["tlsh"]
    return tls, shas


def main() -> None:
    parser = argparse.ArgumentParser(description="Score locked v3.2 checkpoint on untouched Subset B holdouts")
    for name in (
        "lock", "export", "membership", "assignments", "split", "holdout", "pooled",
        "pilot", "expanded", "diverse", "weights", "model-config", "scaler",
        "distance-engine", "component-engine", "out",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()

    lock = read_json(args.lock)
    for name, expected in lock["input_sha256"].items():
        if digest(getattr(args, name)) != expected:
            raise ValueError(f"locked_input_changed:{name}")
    repository = Path(__file__).resolve().parents[2]
    for name, expected in lock["source_sha256"].items():
        if digest(repository / name) != expected:
            raise ValueError(f"locked_scoring_source_changed:{name}")

    result = read_json(args.export)
    runner = result["runner"]
    if (
        result["job_id"] != lock["job_id"]
        or result["manifest_sha256"] != lock["acquisition_manifest_sha256"]
        or runner["job"]["job_id"] != lock["job_id"]
        or runner["job"]["kind"] != "pdf-benign-v32-cohort"
        or runner["status"] not in ("passed", "partial")
        or not all(runner["preflight"][k] for k in ("guest_network_checked", "hypervisor_controls_attested"))
    ):
        raise ValueError("offline_v32_export_not_verified")

    torch.set_num_threads(4)
    train, study, pool = references(args.split, [read_json(args.holdout), read_json(args.pooled)])
    retired_tls, retired_shas = _collect_refs([args.pilot, args.expanded, args.diverse])
    assignments = read_json(args.assignments)["assignments"]
    membership = read_json(args.membership)
    subset_a_tls, subset_a_shas = {}, set()
    for row in result["rows"]:
        if assignments[row["id"]] == "train_val_benign_supplement":
            subset_a_shas.add(row["sha256"])
            if row.get("tlsh") and TLSH_RE.fullmatch(row["tlsh"]):
                subset_a_tls[row["sha256"]] = row["tlsh"]

    scored = score_v32_subset_b(
        export_doc=result,
        membership=membership,
        assignments=assignments,
        train_refs=train,
        study_refs=study | retired_tls | subset_a_tls,
        exact_pool=set(pool) | retired_shas | subset_a_shas,
        thresholds=lock["thresholds"],
        decision_target_fpr=lock["decision_target_fpr"],
        distance_exec=args.distance_engine,
        component_exec=args.component_engine,
        model_config=args.model_config,
        scaler=args.scaler,
        weights=args.weights,
        temperature=lock["temperature"],
    )
    payload = {
        "job_id": lock["job_id"],
        "locked_methodology_sha256": digest(args.lock),
        "export_sha256": digest(args.export),
        "train_references": len(train),
        "study_references": len(study),
        "prior_and_supplement_references": len(retired_tls) + len(subset_a_tls),
        **scored,
    }
    with args.out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, indent=2, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
