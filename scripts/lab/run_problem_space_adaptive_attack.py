"""Evaluate locked detectors under frozen-numeric adaptive subtree grafting (B=0..100) and Phase 2 Byte Stress."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from typing import Any

import lightgbm as lgb
import numpy as np
import torch
import xgboost as xgb

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.score_benign_ood import digest, read_json  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    IDX,
    REGIME_B_INDICES,
    apply_temperature,
    gather_graph_list_batch,
    load_pooled_corpus,
    predict_neural_logits,
    prob_to_logits,
    slice_regime_inputs,
)
from scripts.lab.train_eval_transgraph_v4 import (  # noqa: E402
    DEFAULT_LABEL_VIEW,
    DEFAULT_POOL,
    DEFAULT_SPLIT_VIEW,
    DEFAULT_SUPP,
    DEFAULT_TABULAR,
    POOL_ROOT,
    REGRESSION_DISCLOSURE,
    STRESS_SHA256,
    benign_fpr,
    load_checkpoint,
    load_run_seed42,
    load_stress,
    predict_v4_custom,
    stress_report,
    threshold_at_fpr,
    write_json,
)

from malpdf.evaluation.operating_point import midpoint_macro_f1  # noqa: E402
from malpdf.evaluation.problem_space_attack import (  # noqa: E402
    evaluate_budgeted_attack_curve,
    run_greedy_adaptive_graft_attack,
)
from malpdf.features.contract_v3 import RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v3 import (  # noqa: E402
    PDFTransGraphV3,
    TransGraphV3Config,
    extract_graph_summary_features,
    load_v3_weights_npz,
)

V3_CONTRACT = REPO / "configs/transgraph_v3_contract.json"
DEPLOYED = "deployed_operating_threshold"
MATCHED = "matched_val_calib_fpr_0_5pct"
BUDGETS = (0, 10, 25, 50, 100)


def raw_graphs(corpus, indices):
    graphs = []
    for i in indices:
        n0, n1 = corpus.node_ptr[i : i + 2]
        e0, e1 = corpus.edge_ptr[i : i + 2]
        graphs.append(
            (
                corpus.node_x[n0:n1],
                corpus.node_type[n0:n1],
                corpus.edge_src[e0:e1],
                corpus.edge_dst[e0:e1],
                corpus.edge_rel[e0:e1],
            )
            if corpus.graph_present[i]
            else None
        )
    return graphs


def _summary_from_graphs(graphs: list[Any]) -> np.ndarray:
    nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs, torch.device("cpu"))
    return extract_graph_summary_features(nt_t, ei_t, gb_t, batch_size=len(graphs)).numpy()


@torch.inference_mode()
def _score_v3_custom(
    model: PDFTransGraphV3,
    transform: RobustTransform,
    temperature: float,
    raw_m: np.ndarray,
    graphs_m: list[Any],
    device: torch.device,
    batch_size: int = 256,
) -> np.ndarray:
    sc, ms = transform.transform(raw_m)
    tx, _, ax, am = slice_regime_inputs(sc, ms, "regime_b")
    out_p = []
    for st in range(0, len(raw_m), batch_size):
        ed = st + batch_size
        nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs_m[st:ed], device)
        lo = (
            model(
                torch.from_numpy(tx[st:ed]).to(device),
                None,
                torch.from_numpy(ax[st:ed]).to(device),
                torch.from_numpy(am[st:ed].astype(np.float32)).to(device),
                nx_t,
                nt_t,
                ei_t,
                er_t,
                gb_t,
            )["logits"]
            .detach()
            .cpu()
            .numpy()
        )
        out_p.append(apply_temperature(lo, temperature))
    return np.concatenate(out_p, axis=0)


def regime_thresholds(
    cal_y: np.ndarray, cal_probs: np.ndarray, test_y: np.ndarray, test_probs: np.ndarray, deployed=None
):
    if deployed is None:
        deployed = midpoint_macro_f1(cal_y, cal_probs, max_threshold=0.50)["threshold"]
    matched = threshold_at_fpr(cal_y, cal_probs, 0.005)
    return {
        regime: {
            "threshold": float(threshold),
            "achieved_val_calib_fpr": benign_fpr(cal_y, cal_probs, threshold),
            "test_internal_benign_fpr": benign_fpr(test_y, test_probs, threshold),
            "test_internal_malicious_recall": float((test_probs[test_y == 1] >= threshold).mean()),
        }
        for regime, threshold in ((DEPLOYED, deployed), (MATCHED, matched))
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v4-run", type=Path)
    parser.add_argument("--v4-artifact-dir", type=Path)
    parser.add_argument("--pool", type=Path, default=DEFAULT_POOL)
    parser.add_argument("--max-malicious", type=int, default=250)
    parser.add_argument("--beam-candidates", type=int, default=16)
    args = parser.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.set_num_threads(min(torch.get_num_threads(), 4))
    run, v4_seed, v4, v4_transform, methodology = load_run_seed42(args.v4_run, device, args.v4_artifact_dir)
    v4_metrics = read_json(run / "metrics.json")
    v4_artifacts = args.v4_artifact_dir or REPO / v4_metrics["artifact_directory"]

    contract = read_json(V3_CONTRACT)
    v3_run = REPO / "reports/experiments/transgraph_v3" / contract["source_run"]
    v3_metrics_path = v3_run / "metrics.json"
    v3_metrics = read_json(v3_metrics_path)
    v3_lock = read_json(v3_run / "locked_methodology.json")
    v3_meta = v3_metrics["regime_b_primary"]
    if v3_meta["seed"] != contract["seed"] or contract["seed"] != 42:
        raise ValueError("invalid_v3_canonical_seed")
    v3_artifacts = REPO / v3_metrics["artifact_directory"] / "regime_b"
    pool = args.pool
    if pool == DEFAULT_POOL and not pool.is_file():
        pool = POOL_ROOT / "pooled.jsonl.gz"
    numeric_paths = {
        "pool": pool,
        "tabular": DEFAULT_TABULAR,
        "label_view": DEFAULT_LABEL_VIEW,
        "split_view": DEFAULT_SPLIT_VIEW,
        "benign_supplement": DEFAULT_SUPP,
    }
    hashes = {name: digest(path) for name, path in numeric_paths.items()}
    for name, value in hashes.items():
        if value != v3_lock["inputs_sha256"][name] or value != methodology["inputs_sha256"][name]:
            raise ValueError(f"frozen_input_changed:{name}")
    stress_rows, stress_raw, stress_graphs = load_stress()
    corpus = load_pooled_corpus(
        pool_path=pool,
        tabular_path=DEFAULT_TABULAR,
        label_view_path=DEFAULT_LABEL_VIEW,
        split_view_path=DEFAULT_SPLIT_VIEW,
        benign_supplement_path=DEFAULT_SUPP,
    )
    calib, test = (np.flatnonzero(corpus.roles == role) for role in ("val_calib", "test_internal"))
    cal_y, test_y = corpus.labels[calib], corpus.labels[test]
    indices = np.r_[calib, test]
    for idx in (calib, test):
        if set(corpus.labels[idx]) != {0, 1} or not np.isfinite(corpus.raw_73[idx][:, REGIME_B_INDICES]).all():
            raise ValueError("invalid_frozen_evaluation_cohort")

    mal_idx = np.flatnonzero(
        (corpus.roles == "test_internal") & (corpus.labels == 1) & corpus.is_bc & corpus.graph_present
    )[: args.max_malicious]
    donor_idx = np.flatnonzero((corpus.roles == "train") & (corpus.labels == 0) & corpus.is_bc & corpus.graph_present)[
        :250
    ]
    mal_raw, mal_graphs = corpus.raw_73[mal_idx], raw_graphs(corpus, mal_idx)
    donor_raw, donor_graphs = corpus.raw_73[donor_idx], raw_graphs(corpus, donor_idx)
    eval_graphs = raw_graphs(corpus, indices)
    eval_raw = corpus.raw_73[indices]

    scaler = v3_artifacts / "robust_transform.npz"
    with np.load(scaler, allow_pickle=False) as arrays:
        v3_transform = RobustTransform(arrays["center"], arrays["scale"], arrays["available"])
    if (
        contract["feature_indices_73"] != REGIME_B_INDICES.tolist()
        or not np.allclose(v3_transform.center[REGIME_B_INDICES], contract["center"], rtol=0, atol=1e-12)
        or not np.allclose(v3_transform.scale[REGIME_B_INDICES], contract["scale"], rtol=0, atol=1e-12)
    ):
        raise ValueError("locked_v3_scaler_mismatch")

    hashes.update(
        {
            "byte_stress": STRESS_SHA256,
            "v3_contract": digest(V3_CONTRACT),
            "v3_metrics": digest(v3_metrics_path),
            "v3_scaler": digest(scaler),
            "v4_methodology": v4_metrics["locked_methodology_sha256"],
            "v4_checkpoint_lock": v4_metrics["checkpoint_lock_sha256"],
            **v4_seed["artifacts"],
        }
    )

    detectors: dict[str, tuple[Any, np.ndarray, float | None, np.ndarray | None]] = {}
    v3_tab, v3_missing, v3_ast, v3_ast_missing = slice_regime_inputs(*v3_transform.transform(corpus.raw_73), "regime_b")
    for name in (contract["model_name"], "v3_tab_only"):
        cfg = v3_artifacts / f"{name}_config.json"
        weights = v3_artifacts / f"{name}.npz"
        config = read_json(cfg)
        model_hash = digest(weights)
        mdl = PDFTransGraphV3(TransGraphV3Config(**config)).to(device).eval()
        label = name
        temperature = float(v3_meta["models"][name]["temperature"])
        deployed_thr = None
        if name == contract["model_name"]:
            if model_hash != contract["weights_npz_sha256"] or config != contract["model_config"]:
                raise ValueError("locked_v3_checkpoint_mismatch")
            label = "pdf_transgraph_v3_2b"
            deployed_thr = float(contract["decision_threshold"])
            temperature = float(contract["temperature"])
        load_v3_weights_npz(mdl, weights, map_location=device)
        logits, _ = predict_neural_logits(
            mdl, corpus, indices, v3_tab, v3_missing, v3_ast, v3_ast_missing, device, batch_size=128
        )
        probs = apply_temperature(logits, temperature)
        hashes[weights.name], hashes[cfg.name] = model_hash, digest(cfg)
        st_probs = (
            _score_v3_custom(mdl, v3_transform, temperature, stress_raw, stress_graphs, device)
            if label == "pdf_transgraph_v3_2b"
            else None
        )
        detectors[label] = (
            lambda r_m, g_m, _m=mdl, _t=temperature: _score_v3_custom(_m, v3_transform, _t, r_m, g_m, device),
            probs,
            deployed_thr,
            st_probs,
        )

    tree_inputs = np.concatenate((eval_raw[:, REGIME_B_INDICES], corpus.graph_summary_12[indices]), axis=1)
    xgb_file, lgb_file = v3_artifacts / "xgboost_v3.json", v3_artifacts / "lightgbm_v3.txt"
    xgb_model = xgb.XGBClassifier(n_jobs=4)
    xgb_model.load_model(str(xgb_file))
    lgb_model = lgb.Booster(model_file=str(lgb_file))
    hashes[xgb_file.name], hashes[lgb_file.name] = digest(xgb_file), digest(lgb_file)
    xgb_temp = float(v3_meta["models"]["xgboost_v3"]["temperature"])
    lgb_temp = float(v3_meta["models"]["lightgbm_v3"]["temperature"])
    detectors["xgboost_v3"] = (
        lambda r_m, g_m: apply_temperature(
            prob_to_logits(
                xgb_model.predict_proba(np.concatenate((r_m[:, REGIME_B_INDICES], _summary_from_graphs(g_m)), axis=1))[
                    :, 1
                ]
            ),
            xgb_temp,
        ),
        apply_temperature(prob_to_logits(xgb_model.predict_proba(tree_inputs)[:, 1]), xgb_temp),
        None,
        None,
    )
    detectors["lightgbm_v3"] = (
        lambda r_m, g_m: apply_temperature(
            lgb_model.predict(
                np.concatenate((r_m[:, REGIME_B_INDICES], _summary_from_graphs(g_m)), axis=1),
                raw_score=True,
                num_threads=4,
            ),
            lgb_temp,
        ),
        apply_temperature(lgb_model.predict(tree_inputs, raw_score=True, num_threads=4), lgb_temp),
        None,
        None,
    )

    v4_temp = float(v4_seed["temperature"])
    detectors["pdf_transgraph_v4"] = (
        lambda r_m, g_m: apply_temperature(predict_v4_custom(v4, v4_transform, r_m, g_m, device)[0], v4_temp),
        apply_temperature(predict_v4_custom(v4, v4_transform, eval_raw, eval_graphs, device)[0], v4_temp),
        float(v4_seed["thresholds"]["thr_val_calib"]),
        apply_temperature(predict_v4_custom(v4, v4_transform, stress_raw, stress_graphs, device)[0], v4_temp),
    )

    gin_file = v4_artifacts / "gin_tab_baseline_seed42.npz"
    if gin_file.is_file():
        lock_doc = read_json(run / "checkpoint_lock.json", v4_metrics["checkpoint_lock_sha256"])
        gin_seed = next(row for row in lock_doc["arms"]["gin_tab_baseline"] if row["seed"] == 42)
        gin_mdl, gin_tf = load_checkpoint(v4_artifacts, gin_seed, device)
        gin_temp = float(gin_seed["temperature"])
        hashes.update(gin_seed["artifacts"])
        detectors["gin_tab_baseline"] = (
            lambda r_m, g_m: apply_temperature(predict_v4_custom(gin_mdl, gin_tf, r_m, g_m, device)[0], gin_temp),
            apply_temperature(predict_v4_custom(gin_mdl, gin_tf, eval_raw, eval_graphs, device)[0], gin_temp),
            float(gin_seed["thresholds"]["thr_val_calib"]),
            apply_temperature(predict_v4_custom(gin_mdl, gin_tf, stress_raw, stress_graphs, device)[0], gin_temp),
        )

    models_out: dict[str, Any] = {}
    for det_name, (score_fn, eval_probs, dep_thr, st_probs) in detectors.items():
        print(f"[AdaptiveAttack] Evaluating {det_name} across budgets {BUDGETS}...", flush=True)
        regimes = regime_thresholds(cal_y, eval_probs[: len(calib)], test_y, eval_probs[len(calib) :], dep_thr)
        attack_raw = run_greedy_adaptive_graft_attack(
            mal_raw,
            mal_graphs,
            donor_raw,
            donor_graphs,
            IDX,
            score_fn,
            decision_threshold=regimes[DEPLOYED]["threshold"],
            budgets=BUDGETS,
            beam_candidates=args.beam_candidates,
            max_nodes=320,
            seed=42,
        )
        probs_map = {int(k): np.asarray(v, dtype=np.float64) for k, v in attack_raw["probabilities_by_budget"].items()}
        for reg_name, reg_entry in regimes.items():
            thr_val = reg_entry["threshold"]
            curve_rows = evaluate_budgeted_attack_curve(probs_map, threshold=thr_val)
            reg_entry["attack_curve"] = curve_rows
            reg_entry["budgets"] = {str(r["budget"]): r for r in curve_rows}
            if st_probs is not None:
                reg_entry["phase_2_byte_stress"] = stress_report(stress_rows, st_probs, thr_val)
        models_out[det_name] = regimes

    revision = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    out = REPO / "reports/experiments/problem_space_adaptive_attack" / f"run_{now:%Y%m%dT%H%M%S%fZ}_{revision}"
    out.mkdir(parents=True, exist_ok=False)
    lock = out / "locked_methodology.json"
    write_json(
        lock,
        {
            "generated_utc": now.isoformat(),
            "revision": revision,
            "inputs_sha256": hashes,
            "pool_path": str(pool),
            "v4_run": str(run),
            "regression_provenance": REGRESSION_DISCLOSURE,
            "evaluation_boundary": "Frozen numeric/graph exports only on Windows DEV; zero raw PDF execution.",
            "val_calib_count": len(calib),
            "test_internal_count": len(test),
            "attack_malicious_cohort_count": len(mal_idx),
            "benign_donor_pool_count": len(donor_idx),
            "budgets": list(BUDGETS),
            "max_graft_nodes": 320,
            "beam_candidates": args.beam_candidates,
            "target_matched_fpr": 0.005,
        },
    )
    write_json(
        out / "metrics.json",
        {
            "locked_methodology_sha256": digest(lock),
            "n_malicious": len(mal_idx),
            "budgets": list(BUDGETS),
            "models": models_out,
        },
    )
    print("Saved adaptive attack metrics:", out / "metrics.json")


if __name__ == "__main__":
    main()
