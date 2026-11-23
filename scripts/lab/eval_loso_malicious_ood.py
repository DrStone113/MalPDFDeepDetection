"""Zero-shot Leave-One-Source-Out (LOSO) malicious recall across held-out cohorts."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from functools import partial
import gzip
from hashlib import file_digest
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import numpy as np
import torch

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from malpdf.evaluation.operating_point import midpoint_macro_f1  # noqa: E402
from malpdf.extraction.tlsh import TLSH_RE, nearest_distances, screen  # noqa: E402
from malpdf.features.contract_v3 import FEATURES, RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v3 import (  # noqa: E402
    GRAPH_SUMMARY_DIM,
    TransGraphV3Config,
    extract_graph_summary_features,
)
from scripts.lab.build_clean_splits import connected_groups, native, vector_key  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    REGIME_B_INDICES,
    REGIME_B_NAMES,
    SUPPLEMENT_PREFIX,
    _load_controls,
    _pretrain_ssl,
    _train_gbdt_variants,
    _train_neural_variant,
    apply_temperature,
    compute_slice_metrics,
    fit_temperature,
    gather_graph_list_batch,
    predict_neural_logits,
    prob_to_logits,
    slice_regime_inputs,
)
from scripts.lab.train_eval_transgraph_v3 import CSRGraphCorpus  # noqa: E402

HELD_OUT_OOD_SOURCES = (
    "zenodo2017_exact_historical_consensus",
    "publisher_reported_malicious_2011",
    "user_requested_malicious",
)
EXCLUDED_SSL_SOURCES = ("unverified_zenodo_2017",)


def screen_partition_against_holdouts(
    candidate_shas: list[str],
    candidate_tlsh: dict[str, str | None],
    candidate_vec_keys: dict[str, bytes | None],
    holdout_shas: list[str],
    holdout_tlsh: dict[str, str | None],
    holdout_vec_keys: dict[str, bytes | None],
    measure_distances,
) -> dict[str, Any]:
    """Exclude any candidate that matches a held-out sample by SHA, TLSH <= 30, or exact vector."""
    holdout_ref = {sha: holdout_tlsh[sha] for sha in holdout_shas if holdout_tlsh.get(sha) is not None}
    holdout_sha_set = set(holdout_shas)
    holdout_vkey_set = {holdout_vec_keys[sha] for sha in holdout_shas if holdout_vec_keys.get(sha) is not None}

    cand_queries = {sha: candidate_tlsh[sha] for sha in candidate_shas if candidate_tlsh.get(sha) is not None}
    tlsh_res = screen(holdout_ref, cand_queries, measure_distances) if holdout_ref and cand_queries else {}

    retained, excluded = [], []
    min_retained_dist: int | None = None
    for sha in candidate_shas:
        reason = None
        if sha in holdout_sha_set:
            reason = "exact_sha256"
        elif candidate_vec_keys.get(sha) is not None and candidate_vec_keys[sha] in holdout_vkey_set:
            reason = "exact_vector"
        elif sha in tlsh_res and tlsh_res[sha]["disposition"] in ("near_duplicate", "exact_duplicate"):
            reason = f"tlsh_le_30({tlsh_res[sha]['distance']})"
        if reason is not None:
            excluded.append((sha, reason))
        else:
            retained.append(sha)
            dist = tlsh_res[sha]["distance"] if sha in tlsh_res else None
            if dist is not None and (min_retained_dist is None or dist < min_retained_dist):
                min_retained_dist = dist

    return {
        "retained_shas": retained,
        "excluded_reasons": Counter(r.split("(")[0] for _, r in excluded),
        "excluded_count": len(excluded),
        "min_retained_tlsh": min_retained_dist,
    }


def compute_ood_cohort_metrics(
    probs: np.ndarray,
    is_bc: np.ndarray,
    graph_present: np.ndarray,
    cluster_ids: list[int],
    thr_primary: float,
    thr_secondary: float = 0.50,
) -> dict[str, Any]:
    """Compute overall, stratum, and TLSH cluster-representative recall for malicious-only OOD cohorts."""
    p = np.asarray(probs, dtype=np.float64)
    n = len(p)

    def _recall(mask: np.ndarray, thr: float) -> float | None:
        return float(np.mean(p[mask] >= thr)) if mask.any() else None

    rep_seen: set[int] = set()
    rep_indices: list[int] = []
    for idx, cid in enumerate(cluster_ids):
        if cid not in rep_seen:
            rep_seen.add(cid)
            rep_indices.append(idx)
    rep_mask = np.zeros(n, dtype=bool)
    rep_mask[rep_indices] = True

    def _at_thr(thr: float) -> dict[str, Any]:
        return {
            "threshold": float(thr),
            "overall_recall": _recall(np.ones(n, dtype=bool), thr),
            "flagged": int((p >= thr).sum()),
            "bounded_complete_recall": _recall(is_bc, thr),
            "bounded_complete_count": int(is_bc.sum()),
            "degraded_recall": _recall(~is_bc, thr),
            "degraded_count": int((~is_bc).sum()),
            "graph_available_recall": _recall(graph_present, thr),
            "cluster_representative_recall": _recall(rep_mask, thr),
            "cluster_representatives_flagged": int((p[rep_mask] >= thr).sum()),
            "cluster_count": int(rep_mask.sum()),
        }

    return {
        "count": int(n),
        "cluster_count": int(rep_mask.sum()),
        "bounded_complete_count": int(is_bc.sum()),
        "degraded_count": int((~is_bc).sum()),
        "graph_available_count": int(graph_present.sum()),
        "prob_quantiles": {
            "min": float(np.min(p)),
            "p10": float(np.quantile(p, 0.10)),
            "median": float(np.median(p)),
            "mean": float(np.mean(p)),
            "max": float(np.max(p)),
        },
        "at_locked_midpoint": _at_thr(thr_primary),
        "at_050": _at_thr(thr_secondary),
    }


def _load_fingerprints_map(*paths: Path) -> dict[str, str | None]:
    fps: dict[str, str | None] = {}
    for p in paths:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
        for row in data["fingerprints"]:
            val = row["tlsh"]
            if val is not None and not TLSH_RE.fullmatch(val):
                raise ValueError(f"invalid_tlsh:{row['sha256']}")
            fps[row["sha256"]] = val
    return fps


def _load_all_pool_corpus(
    *,
    pool_path: Path,
    tabular_path: Path,
    label_view_path: Path,
    split_view_path: Path,
    benign_supplement_path: Path | None = None,
) -> tuple[CSRGraphCorpus, dict[str, int], list[list[float | None]], dict[str, str | None]]:
    label_meta: dict[str, tuple[int, str, bool]] = {}
    with label_view_path.open("r", encoding="utf-8") as f:
        next(f)
        for line in f:
            rec = json.loads(line)
            label_meta[rec["sha256"]] = (
                -1 if rec["label"] is None else int(rec["label"]),
                rec["label_source"],
                rec["status"] == "bounded_complete",
            )

    split_map: dict[str, tuple[str, str]] = {}
    with split_view_path.open("r", encoding="utf-8") as f:
        next(f)
        for line in f:
            rec = json.loads(line)
            role = rec["role"]
            src = label_meta[rec["sha256"]][1]
            if role in ("train", "val_select", "val_calib", "test_internal") or src in HELD_OUT_OOD_SOURCES:
                split_map[rec["sha256"]] = (role, rec["group"])

    ordered_shas = sorted(split_map.keys())
    sha_to_row = {sha: i for i, sha in enumerate(ordered_shas)}
    m = len(ordered_shas)
    roles = np.asarray([split_map[s][0] for s in ordered_shas])
    groups = np.asarray([split_map[s][1] for s in ordered_shas])
    labels = np.asarray([label_meta[s][0] for s in ordered_shas], dtype=np.int64)
    label_sources = np.asarray([label_meta[s][1] for s in ordered_shas], dtype=object)
    is_bc = np.asarray([label_meta[s][2] for s in ordered_shas], dtype=bool)

    raw_73 = np.full((m, len(FEATURES)), np.nan, dtype=np.float32)
    raw_vecs_py: list[list[float | None]] = [[None] * len(FEATURES)] * m
    with gzip.open(tabular_path, "rt", encoding="ascii") as f:
        next(f)
        for line in f:
            row = json.loads(line)
            if not isinstance(row, list):
                continue
            idx = sha_to_row.get(row[0])
            if idx is None:
                continue
            raw_vecs_py[idx] = row[1]
            raw_73[idx] = np.asarray([np.nan if v is None else float(v) for v in row[1]], dtype=np.float32)

    graph_blobs: list[Any] = [None] * m
    with gzip.open(pool_path, "rt", encoding="utf-8") as f:
        next(f)
        for line in f:
            row = json.loads(line)
            idx = sha_to_row.get(row[0])
            if idx is not None:
                graph_blobs[idx] = row[5]

    node_x_parts, node_t_parts = [], []
    edge_s_parts, edge_d_parts, edge_r_parts = [], [], []
    node_ptr = np.zeros(m + 1, dtype=np.int64)
    edge_ptr = np.zeros(m + 1, dtype=np.int64)
    graph_present = np.zeros(m, dtype=bool)
    graph_summary_12 = np.zeros((m, GRAPH_SUMMARY_DIM), dtype=np.float32)
    n_acc = e_acc = 0
    for i, g in enumerate(graph_blobs):
        if g is not None and len(g[0]) > 0:
            nx = np.asarray(g[0], dtype=np.float32)
            nt = np.asarray(g[1], dtype=np.int64)
            es = np.asarray(g[2], dtype=np.int64)
            ed = np.asarray(g[3], dtype=np.int64)
            er = np.asarray(g[4], dtype=np.int64)
            node_x_parts.append(nx)
            node_t_parts.append(nt)
            if len(es) > 0:
                edge_s_parts.append(es)
                edge_d_parts.append(ed)
                edge_r_parts.append(er)
            ei = torch.stack((torch.from_numpy(es), torch.from_numpy(ed)), dim=0) if len(es) > 0 else None
            graph_summary_12[i] = extract_graph_summary_features(
                torch.from_numpy(nt), ei, torch.zeros(len(nx), dtype=torch.long), batch_size=1
            )[0].numpy()
            graph_present[i] = True
            n_acc += len(nx)
            e_acc += len(es)
        node_ptr[i + 1] = n_acc
        edge_ptr[i + 1] = e_acc
    del graph_blobs

    supp_fps: dict[str, str | None] = {}
    if benign_supplement_path is not None:
        supp_doc = json.loads(benign_supplement_path.read_text(encoding="utf-8"))
        supp_rows = supp_doc["rows"] if isinstance(supp_doc, dict) else supp_doc
        seen_shas = set(ordered_shas)
        s_shas, s_roles, s_groups, s_srcs, s_bc, s_raw, s_raw_py = [], [], [], [], [], [], []
        s_nx, s_nt, s_es, s_ed, s_er, s_gp, s_gs = [], [], [], [], [], [], []
        for row in supp_rows:
            role = row["role"]
            if role == "test_internal" or role not in ("train", "val_select", "val_calib"):
                raise ValueError(f"forbidden_supplement_role:{role}")
            sha = row["sha256"]
            if sha in seen_shas:
                raise ValueError(f"duplicate_supplement_sha256:{sha}")
            seen_shas.add(sha)
            tlsh_val = row.get("tlsh")
            if tlsh_val is not None and not TLSH_RE.fullmatch(tlsh_val):
                raise ValueError(f"invalid_supplement_tlsh:{sha}")
            supp_fps[sha] = tlsh_val
            s_shas.append(sha)
            s_roles.append(role)
            s_groups.append(row["group"])
            s_srcs.append(f"{SUPPLEMENT_PREFIX}{row['source']}")
            s_bc.append(row["status"] == "bounded_complete")
            feats = list(row["features"])
            s_raw_py.append(feats)
            s_raw.append([np.nan if v is None else float(v) for v in feats])
            g = row.get("graph")
            if g is not None and len(g[0]) > 0:
                nx = np.asarray(g[0], dtype=np.float32)
                nt = np.asarray(g[1], dtype=np.int64)
                es = np.asarray(g[2], dtype=np.int64)
                ed = np.asarray(g[3], dtype=np.int64)
                er = np.asarray(g[4], dtype=np.int64)
                s_nx.append(nx)
                s_nt.append(nt)
                if len(es) > 0:
                    s_es.append(es)
                    s_ed.append(ed)
                    s_er.append(er)
                ei = torch.stack((torch.from_numpy(es), torch.from_numpy(ed)), dim=0) if len(es) > 0 else None
                s_gs.append(
                    extract_graph_summary_features(
                        torch.from_numpy(nt), ei, torch.zeros(len(nx), dtype=torch.long), batch_size=1
                    )[0].numpy()
                )
                s_gp.append(True)
                n_acc += len(nx)
                e_acc += len(es)
            else:
                s_gs.append(np.zeros((GRAPH_SUMMARY_DIM,), dtype=np.float32))
                s_gp.append(False)
            node_ptr = np.append(node_ptr, n_acc)
            edge_ptr = np.append(edge_ptr, e_acc)

        if s_shas:
            base_m = len(ordered_shas)
            for k, sha in enumerate(s_shas):
                sha_to_row[sha] = base_m + k
            ordered_shas.extend(s_shas)
            raw_vecs_py.extend(s_raw_py)
            roles = np.concatenate((roles, np.asarray(s_roles)))
            groups = np.concatenate((groups, np.asarray(s_groups)))
            labels = np.concatenate((labels, np.zeros(len(s_shas), dtype=np.int64)))
            label_sources = np.concatenate((label_sources, np.asarray(s_srcs, dtype=object)))
            is_bc = np.concatenate((is_bc, np.asarray(s_bc, dtype=bool)))
            raw_73 = np.concatenate((raw_73, np.asarray(s_raw, dtype=np.float32)), axis=0)
            node_x_parts.extend(s_nx)
            node_t_parts.extend(s_nt)
            edge_s_parts.extend(s_es)
            edge_d_parts.extend(s_ed)
            edge_r_parts.extend(s_er)
            graph_present = np.concatenate((graph_present, np.asarray(s_gp, dtype=bool)))
            graph_summary_12 = np.concatenate((graph_summary_12, np.asarray(s_gs, dtype=np.float32)), axis=0)

    corpus = CSRGraphCorpus(
        shas=tuple(ordered_shas),
        roles=roles,
        groups=groups,
        labels=labels,
        label_sources=label_sources,
        is_bc=is_bc,
        raw_73=raw_73,
        node_x=np.concatenate(node_x_parts, axis=0) if node_x_parts else np.zeros((0, 23), dtype=np.float32),
        node_type=np.concatenate(node_t_parts, axis=0) if node_t_parts else np.zeros((0,), dtype=np.int64),
        edge_src=np.concatenate(edge_s_parts, axis=0) if edge_s_parts else np.zeros((0,), dtype=np.int64),
        edge_dst=np.concatenate(edge_d_parts, axis=0) if edge_d_parts else np.zeros((0,), dtype=np.int64),
        edge_rel=np.concatenate(edge_r_parts, axis=0) if edge_r_parts else np.zeros((0,), dtype=np.int64),
        node_ptr=node_ptr,
        edge_ptr=edge_ptr,
        graph_present=graph_present,
        graph_summary_12=graph_summary_12,
    )
    return corpus, sha_to_row, raw_vecs_py, supp_fps


def _cluster_holdout_cohort(
    indices: np.ndarray,
    corpus: CSRGraphCorpus,
    raw_vecs_py: list[list[float | None]],
    fps: dict[str, str | None],
    comp_engine: Path,
) -> list[int]:
    vecs = [raw_vecs_py[i] for i in indices]
    hashes_measured_pos = [pos for pos, idx in enumerate(indices) if fps.get(corpus.shas[idx]) is not None]
    hashes = [fps[corpus.shas[indices[pos]]] for pos in hashes_measured_pos]
    reps = native(comp_engine, ["--components"], str(len(hashes)), hashes) if hashes else []
    return connected_groups(vecs, hashes_measured_pos, reps)


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-shot LOSO cross-source & temporal OOD malicious evaluation")
    parser.add_argument("--pool", type=Path, default=REPO / "data/processed/pooled_bulk/pooled.jsonl.gz")
    parser.add_argument("--tabular", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/tabular_v3.jsonl.gz")
    parser.add_argument("--label-view", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/training_labels_20261122T055618Z.jsonl")
    parser.add_argument("--split-view", type=Path, default=None)
    parser.add_argument("--fp-existing", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/existing_fingerprints.json")
    parser.add_argument("--fp-pooled", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/pooled_fingerprints_c02d9196/holdout_fingerprints.json")
    parser.add_argument("--distance-engine", type=Path, default=REPO / "data/processed/scanner_feature_audit/tlsh_cross_partition.exe")
    parser.add_argument("--component-engine", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/tlsh_components.exe")
    parser.add_argument("--controls", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/reviewed_controls_v3.json")
    parser.add_argument("--benign-supplement", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.split_view is None:
        cur = (REPO / "data/processed/pooled_bulk/offline_provenance/current_split_view.txt").read_text(encoding="utf-8").strip()
        args.split_view = REPO / cur

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exp_dir = REPO / f"reports/experiments/loso_malicious_ood_v3/run_{ts}_{git_rev}"
    exp_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    corpus, sha_to_row, raw_vecs_py, supp_fps = _load_all_pool_corpus(
        pool_path=args.pool,
        tabular_path=args.tabular,
        label_view_path=args.label_view,
        split_view_path=args.split_view,
        benign_supplement_path=args.benign_supplement,
    )
    fps = _load_fingerprints_map(args.fp_existing, args.fp_pooled)
    fps.update(supp_fps)
    vec_keys = {corpus.shas[i]: vector_key(raw_vecs_py[i]) for i in range(len(corpus.shas))}

    holdout_indices = {
        src: np.flatnonzero(corpus.label_sources == src)
        for src in HELD_OUT_OOD_SOURCES
    }
    all_holdout_shas = [corpus.shas[i] for src in HELD_OUT_OOD_SOURCES for i in holdout_indices[src]]
    all_holdout_set = set(all_holdout_shas)
    excluded_set = set(HELD_OUT_OOD_SOURCES) | set(EXCLUDED_SSL_SOURCES)

    # Raw role candidates excluding held-out OOD malware & unverified Zenodo 2017.
    cand_train_idx = [
        i for i, r in enumerate(corpus.roles)
        if r == "train" and corpus.label_sources[i] not in excluded_set and corpus.shas[i] not in all_holdout_set
    ]
    cand_val_sel_idx = [
        i for i, r in enumerate(corpus.roles)
        if r == "val_select" and str(corpus.label_sources[i]).startswith(("vapd_v5_d1_", SUPPLEMENT_PREFIX))
    ]
    cand_val_cal_idx = [
        i for i, r in enumerate(corpus.roles)
        if r == "val_calib" and str(corpus.label_sources[i]).startswith(("vapd_v5_d1_", SUPPLEMENT_PREFIX))
    ]
    test_vapd_ben_idx = np.flatnonzero(
        (corpus.roles == "test_internal") & (corpus.label_sources == "vapd_v5_d1_benign")
    )

    measure = partial(nearest_distances, args.distance_engine)
    train_screen = screen_partition_against_holdouts(
        [corpus.shas[i] for i in cand_train_idx], fps, vec_keys,
        all_holdout_shas, fps, vec_keys, measure,
    )
    val_sel_screen = screen_partition_against_holdouts(
        [corpus.shas[i] for i in cand_val_sel_idx], fps, vec_keys,
        all_holdout_shas, fps, vec_keys, measure,
    )
    val_cal_screen = screen_partition_against_holdouts(
        [corpus.shas[i] for i in cand_val_cal_idx], fps, vec_keys,
        all_holdout_shas, fps, vec_keys, measure,
    )

    if any(s["min_retained_tlsh"] is not None and s["min_retained_tlsh"] <= 30 for s in (train_screen, val_sel_screen, val_cal_screen)):
        raise ValueError("loso_tlsh_leakage_detected")

    train_all_idx = np.asarray([sha_to_row[s] for s in train_screen["retained_shas"]], dtype=np.int64)
    train_lab_idx = train_all_idx[corpus.labels[train_all_idx] >= 0]
    val_sel_idx = np.asarray([sha_to_row[s] for s in val_sel_screen["retained_shas"]], dtype=np.int64)
    val_cal_idx = np.asarray([sha_to_row[s] for s in val_cal_screen["retained_shas"]], dtype=np.int64)

    holdout_clusters = {
        src: _cluster_holdout_cohort(holdout_indices[src], corpus, raw_vecs_py, fps, args.component_engine)
        for src in HELD_OUT_OOD_SOURCES
    }

    transform = RobustTransform.fit(corpus.raw_73[train_all_idx], roles=["train"] * len(train_all_idx))
    scaled_all, miss_all = transform.transform(corpus.raw_73)
    tab_all, tab_miss_all, ast_all, ast_miss_all = slice_regime_inputs(scaled_all, miss_all, "regime_b")
    ctrl_names, ctrl_raw_73, ctrl_graphs, ctrl_summary_12 = _load_controls(args.controls)
    ctrl_sc, ctrl_ms = transform.transform(ctrl_raw_73)
    ctrl_tx, ctrl_tm, ctrl_ax, ctrl_am = slice_regime_inputs(ctrl_sc, ctrl_ms, "regime_b")

    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revision": git_rev,
        "seed": args.seed,
        "device": str(device),
        "held_out_ood_sources": list(HELD_OUT_OOD_SOURCES),
        "excluded_ssl_sources": list(EXCLUDED_SSL_SOURCES),
        "regime_b_features": list(REGIME_B_NAMES),
        "screening": {
            "train_before": len(cand_train_idx),
            "train_retained_all": len(train_all_idx),
            "train_retained_labeled": int(len(train_lab_idx)),
            "train_retained_unlabeled": int((corpus.labels[train_all_idx] < 0).sum()),
            "train_excluded": dict(train_screen["excluded_reasons"]),
            "train_min_tlsh_vs_holdouts": train_screen["min_retained_tlsh"],
            "val_select_retained": len(val_sel_idx),
            "val_select_excluded": val_sel_screen["excluded_count"],
            "val_select_min_tlsh_vs_holdouts": val_sel_screen["min_retained_tlsh"],
            "val_calib_retained": len(val_cal_idx),
            "val_calib_excluded": val_cal_screen["excluded_count"],
            "val_calib_min_tlsh_vs_holdouts": val_cal_screen["min_retained_tlsh"],
        },
        "held_out_counts": {src: {"rows": int(len(holdout_indices[src])), "clusters": int(len(set(holdout_clusters[src])))} for src in HELD_OUT_OOD_SOURCES},
    }
    if args.benign_supplement is not None:
        with args.benign_supplement.open("rb") as fh:
            locked["benign_supplement_sha256"] = file_digest(fh, "sha256").hexdigest()
    (exp_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")

    cfg = TransGraphV3Config(tab_dim=len(REGIME_B_NAMES), use_missing_mask=False)
    ssl_inv_cfg = TransGraphV3Config(tab_dim=len(REGIME_B_NAMES), use_missing_mask=False, modality_drop_prob=0.15)
    ssl_state, ssl_hist = _pretrain_ssl(ssl_inv_cfg, corpus, train_all_idx, "regime_b", transform, args.seed, device)
    sup_tr = _train_neural_variant(
        "loso_v3_tab_graph_supervised", cfg, None, corpus, train_lab_idx, train_all_idx,
        "regime_b", transform, scaled_all, miss_all, val_sel_idx, use_inv_loss=False, seed=args.seed, device=device,
    )
    ssl_tr = _train_neural_variant(
        "loso_v3_tab_graph_ssl_inv", ssl_inv_cfg, ssl_state, corpus, train_lab_idx, train_all_idx,
        "regime_b", transform, scaled_all, miss_all, val_sel_idx, use_inv_loss=True, seed=args.seed, device=device,
    )
    gbdt = _train_gbdt_variants("regime_b", corpus, train_lab_idx, val_sel_idx, args.seed)
    x_gbdt = gbdt["x_gbdt"]
    x_ctrl_gbdt = np.concatenate((ctrl_raw_73[:, REGIME_B_INDICES], ctrl_summary_12), axis=1)

    model_logits: dict[str, dict[str, Any]] = {}
    for m_name, mdl in (("loso_v3_tab_graph_supervised", sup_tr["model"]), ("loso_v3_tab_graph_ssl_inv", ssl_tr["model"])):
        mdl.eval()
        cal_l, _ = predict_neural_logits(mdl, corpus, val_cal_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
        ben_l, _ = predict_neural_logits(mdl, corpus, test_vapd_ben_idx, tab_all, tab_miss_all, ast_all, ast_miss_all, device)
        with torch.no_grad():
            nx_c, nt_c, ei_c, er_c, gb_c = gather_graph_list_batch(ctrl_graphs, device)
            ctl_l = mdl(
                torch.from_numpy(ctrl_tx).to(device=device, dtype=torch.float32), None,
                torch.from_numpy(ctrl_ax).to(device=device, dtype=torch.float32),
                torch.from_numpy(ctrl_am).to(device=device, dtype=torch.float32),
                nx_c, nt_c, ei_c, er_c, gb_c,
            )["logits"].cpu().numpy()
        hold_l = {
            src: predict_neural_logits(mdl, corpus, holdout_indices[src], tab_all, tab_miss_all, ast_all, ast_miss_all, device)[0]
            for src in HELD_OUT_OOD_SOURCES
        }
        model_logits[m_name] = {"val_calib": cal_l, "vapd_ben": ben_l, "controls": ctl_l, "holdouts": hold_l}

    for g_name, src_key in (("loso_xgboost_v3", "xgboost_v3"), ("loso_lightgbm_v3", "lightgbm_v3")):
        clf = gbdt[src_key]
        model_logits[g_name] = {
            "val_calib": prob_to_logits(clf.predict_proba(x_gbdt[val_cal_idx])[:, 1]),
            "vapd_ben": prob_to_logits(clf.predict_proba(x_gbdt[test_vapd_ben_idx])[:, 1]),
            "controls": prob_to_logits(clf.predict_proba(x_ctrl_gbdt)[:, 1]),
            "holdouts": {src: prob_to_logits(clf.predict_proba(x_gbdt[holdout_indices[src]])[:, 1]) for src in HELD_OUT_OOD_SOURCES},
        }

    # Lock temperature + midpoint optimal F1-macro threshold strictly on VAPD-only Val_Calib before scoring OOD malware.
    cal_y = corpus.labels[val_cal_idx]
    val_locks: dict[str, Any] = {}
    for m_name, d_log in model_logits.items():
        temp = fit_temperature(d_log["val_calib"], cal_y)
        cal_p = apply_temperature(d_log["val_calib"], temp)
        mid = midpoint_macro_f1(cal_y, cal_p)
        val_locks[m_name] = {
            "temperature": temp,
            "midpoint_f1_macro": mid,
            "val_calib_metrics": compute_slice_metrics(cal_y, cal_p, mid["threshold"], 0.50),
        }
    (exp_dir / "validation_lock.json").write_text(json.dumps(val_locks, indent=2) + "\n", encoding="utf-8")

    results: dict[str, Any] = {}
    for m_name, d_log in model_logits.items():
        temp = val_locks[m_name]["temperature"]
        thr = val_locks[m_name]["midpoint_f1_macro"]["threshold"]
        cohorts = {}
        for src in HELD_OUT_OOD_SOURCES:
            idx = holdout_indices[src]
            p = apply_temperature(d_log["holdouts"][src], temp)
            cohorts[src] = compute_ood_cohort_metrics(
                p, corpus.is_bc[idx], corpus.graph_present[idx], holdout_clusters[src], thr, 0.50
            )
            if src == "user_requested_malicious":
                cohorts[src]["per_sample"] = [
                    {
                        "sha256": corpus.shas[i],
                        "status": "bounded_complete" if corpus.is_bc[i] else "degraded",
                        "graph": bool(corpus.graph_present[i]),
                        "probability": float(prob),
                    }
                    for i, prob in zip(idx, p, strict=True)
                ]
        ben_p = apply_temperature(d_log["vapd_ben"], temp)
        ctl_p = apply_temperature(d_log["controls"], temp)
        results[m_name] = {
            "temperature": temp,
            "locked_threshold_midpoint": thr,
            "vapd_test_benign": {
                "count": int(len(ben_p)),
                "fp_at_midpoint": int((ben_p >= thr).sum()),
                "fpr_at_midpoint": float(np.mean(ben_p >= thr)),
                "fp_at_050": int((ben_p >= 0.50).sum()),
            },
            "reviewed_controls": {
                "probs": {k: float(v) for k, v in zip(ctrl_names, ctl_p, strict=True)},
                "alerts_at_midpoint": int((ctl_p >= thr).sum()),
                "alerts_at_050": int((ctl_p >= 0.50).sum()),
            },
            "held_out_malicious_cohorts": cohorts,
        }

    out = {"locked_methodology": locked, "ssl_history": ssl_hist, "models": results}
    (exp_dir / "metrics.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Saved LOSO evaluation: {exp_dir / 'metrics.json'}")
    for m_name, m_val in results.items():
        print(f"MODEL={m_name} thr={m_val['locked_threshold_midpoint']:.4f} vapd_fpr={m_val['vapd_test_benign']['fpr_at_midpoint']:.4f} ctl_alerts={m_val['reviewed_controls']['alerts_at_midpoint']}")
        for src in HELD_OUT_OOD_SOURCES:
            c = m_val["held_out_malicious_cohorts"][src]["at_locked_midpoint"]
            print(f"  {src:36s}: rec={c['overall_recall']:.4f} rep_rec={c['cluster_representative_recall']:.4f} bc_rec={c['bounded_complete_recall']} (n={c['bounded_complete_count']}/{m_val['held_out_malicious_cohorts'][src]['count']}, cl={c['cluster_count']})")


if __name__ == "__main__":
    main()
