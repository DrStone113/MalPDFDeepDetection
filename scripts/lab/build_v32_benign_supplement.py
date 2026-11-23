"""Build a TLSH-disjoint multi-source verified benign supplement (train/val_select/val_calib only)."""

from __future__ import annotations

import argparse
from collections import Counter
from functools import partial
import json
from pathlib import Path
import sys
from typing import Any

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from malpdf.extraction.tlsh import DISTANCE_LIMIT, TLSH_RE, nearest_distances  # noqa: E402
from malpdf.features.contract_v3 import FEATURES  # noqa: E402
from scripts.lab.build_clean_splits import native  # noqa: E402
from scripts.lab.score_benign_ood import digest, read_json, references  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import REGIME_B_INDICES  # noqa: E402

HARD_SOURCES = frozenset({"verapdf", "pdfjs"})


def split_supplement_clusters(
    candidates: list[dict[str, Any]],
    cluster_ids: list[str],
    *,
    seed: int = 42,
) -> dict[str, str]:
    """Assign each cluster deterministically to train (~80%), val_select (~10%), val_calib (~10%)."""
    if len(candidates) != len(cluster_ids):
        raise ValueError("cluster_length_mismatch")
    strat = np.asarray([1 if c["source"] in HARD_SOURCES else 0 for c in candidates], dtype=np.int64)
    groups = np.asarray(cluster_ids)
    n_clusters = len(set(cluster_ids))
    if n_clusters < 10:
        return {c["sha256"]: "train" for c in candidates}

    splitter = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed)
    role_by_cluster: dict[str, str] = {}
    for fold, (_, val_idx) in enumerate(splitter.split(strat, strat, groups)):
        role = "val_select" if fold == 0 else "val_calib" if fold == 1 else "train"
        for idx in val_idx:
            g = cluster_ids[idx]
            if role_by_cluster.setdefault(g, role) != role:
                raise ValueError("supplement_cluster_crossed_roles")
    return {c["sha256"]: role_by_cluster[g] for c, g in zip(candidates, cluster_ids, strict=True)}


def build_supplement(
    *,
    candidates: list[dict[str, Any]],
    test_refs: dict[str, str],
    subset_b_refs: dict[str, str],
    existing_shas: set[str],
    distance_exec: Path,
    component_exec: Path,
    seed: int = 42,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter candidates against Test_Internal and Subset B by SHA-256 and TLSH > 30, then cluster-split."""
    nearest = partial(nearest_distances, distance_exec)
    protected_shas = set(existing_shas) | set(subset_b_refs) | set(test_refs)
    protected_tlsh = {**test_refs, **subset_b_refs}

    valid: list[dict[str, Any]] = []
    skipped = Counter()
    seen_local: set[str] = set()
    for row in candidates:
        sha = row["sha256"]
        if sha in protected_shas or sha in seen_local:
            skipped["duplicate_or_protected_sha"] += 1
            continue
        if (
            not row.get("tlsh")
            or not TLSH_RE.fullmatch(row["tlsh"])
            or row.get("features") is None
            or row.get("graph") is None
            or len(row["graph"][0]) == 0
            or any(row["features"][i] is None for i in REGIME_B_INDICES)
        ):
            skipped["incomplete_features_graph_or_tlsh"] += 1
            continue
        seen_local.add(sha)
        valid.append(row)

    cand_tlsh = {r["sha256"]: r["tlsh"] for r in valid}
    test_dists = nearest(list(test_refs.values()), [cand_tlsh[r["sha256"]] for r in valid]) if (valid and test_refs) else [999] * len(valid)
    subb_dists = nearest(list(subset_b_refs.values()), [cand_tlsh[r["sha256"]] for r in valid]) if (valid and subset_b_refs) else [999] * len(valid)

    admitted: list[dict[str, Any]] = []
    min_test_d, min_subb_d = 999, 999
    for row, td, sd in zip(valid, test_dists, subb_dists, strict=True):
        if td <= DISTANCE_LIMIT or sd <= DISTANCE_LIMIT:
            skipped["near_duplicate_protected"] += 1
            continue
        min_test_d = min(min_test_d, td)
        min_subb_d = min(min_subb_d, sd)
        admitted.append(row)

    if not admitted:
        raise ValueError("no_admitted_supplement_rows")

    parents = native(component_exec, ["--components"], str(len(admitted)), [r["tlsh"] for r in admitted])
    if len(parents) != len(admitted):
        raise ValueError("invalid_supplement_components")
    cluster_ids = [f"bsupp_c_{p:05d}" for p in parents]
    roles = split_supplement_clusters(admitted, cluster_ids, seed=seed)

    out_rows: list[dict[str, Any]] = []
    for row, cid in zip(admitted, cluster_ids, strict=True):
        role = roles[row["sha256"]]
        if role not in {"train", "val_select", "val_calib"}:
            raise ValueError(f"forbidden_supplement_role:{role}")
        out_rows.append({
            "id": row["id"],
            "sha256": row["sha256"],
            "tlsh": row["tlsh"],
            "source": row["source"],
            "status": row["status"],
            "cohort": row["cohort"],
            "role": role,
            "group": cid,
            "features": row["features"],
            "graph": row["graph"],
        })

    audit = {
        "input_candidates": len(candidates),
        "retained": len(out_rows),
        "unique_clusters": len(set(cluster_ids)),
        "skipped": dict(skipped),
        "min_tlsh_vs_test_internal": min_test_d if protected_tlsh else None,
        "min_tlsh_vs_subset_b": min_subb_d if subset_b_refs else None,
        "role_counts": dict(Counter(r["role"] for r in out_rows)),
        "source_counts": dict(Counter(r["source"] for r in out_rows)),
        "by_role_and_source": {
            role: dict(Counter(r["source"] for r in out_rows if r["role"] == role))
            for role in ("train", "val_select", "val_calib")
        },
    }
    return out_rows, audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble TLSH-disjoint verified benign supplement for v3.2")
    parser.add_argument("--retired-exports", type=Path, nargs="+", required=True)
    parser.add_argument("--v32-export", type=Path, required=True)
    parser.add_argument("--assignments", type=Path, required=True)
    parser.add_argument("--split", type=Path, required=True)
    parser.add_argument("--holdout", type=Path, required=True)
    parser.add_argument("--pooled", type=Path, required=True)
    parser.add_argument("--distance-engine", type=Path, required=True)
    parser.add_argument("--component-engine", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--audit-out", type=Path, required=True)
    args = parser.parse_args()

    _, study_refs, pool_shas = references(args.split, [read_json(args.holdout), read_json(args.pooled)])
    test_shas = set()
    with args.split.open(encoding="ascii") as stream:
        next(stream)
        for line in stream:
            rec = json.loads(line)
            if rec["role"] == "test_internal":
                test_shas.add(rec["sha256"])
    test_refs = {sha: study_refs[sha] for sha in test_shas if sha in study_refs}

    candidates: list[dict[str, Any]] = []
    for p in args.retired_exports:
        exp = read_json(p)
        if exp["feature_order"] != list(FEATURES):
            raise ValueError(f"unexpected_feature_order:{p}")
        for r in exp["rows"]:
            candidates.append({**r, "cohort": p.parent.name})

    assign_doc = read_json(args.assignments)["assignments"]
    v32_exp = read_json(args.v32_export)
    if v32_exp["feature_order"] != list(FEATURES):
        raise ValueError("unexpected_v32_feature_order")
    subset_b_refs: dict[str, str] = {}
    for r in v32_exp["rows"]:
        sub = assign_doc[r["id"]]
        if sub == "train_val_benign_supplement":
            candidates.append({**r, "cohort": "v32_subset_a"})
        elif r.get("tlsh") and TLSH_RE.fullmatch(r["tlsh"]):
            subset_b_refs[r["sha256"]] = r["tlsh"]

    rows, audit = build_supplement(
        candidates=candidates,
        test_refs=test_refs,
        subset_b_refs=subset_b_refs,
        existing_shas=set(pool_shas),
        distance_exec=args.distance_engine,
        component_exec=args.component_engine,
        seed=args.seed,
    )
    payload = {
        "schema_version": 1,
        "feature_order": list(FEATURES),
        "input_sha256": {
            "split": digest(args.split),
            "v32_export": digest(args.v32_export),
            "assignments": digest(args.assignments),
            "retired_exports": [digest(p) for p in args.retired_exports],
        },
        "audit": audit,
        "rows": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, separators=(",", ":"), allow_nan=False), encoding="utf-8")
    args.audit_out.parent.mkdir(parents=True, exist_ok=True)
    args.audit_out.write_text(json.dumps(audit, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
