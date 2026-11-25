"""Fit Mondrian Conformal v4 on Val_Calib, verify strict promotion gates vs v3.2b, and stage canonical v4 contract."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import file_digest
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import numpy as np
import torch

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.eval_loso_malicious_ood import HELD_OUT_OOD_SOURCES, _load_all_pool_corpus  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import REGIME_B_INDICES, REGIME_B_NAMES, apply_temperature  # noqa: E402
from scripts.lab.train_eval_transgraph_v4 import (  # noqa: E402
    DEFAULT_LABEL_VIEW,
    DEFAULT_POOL,
    DEFAULT_SPLIT_VIEW,
    DEFAULT_STRESS,
    DEFAULT_SUPP,
    DEFAULT_TABULAR,
    POOL_ROOT,
    REGRESSION_DISCLOSURE,
    load_run_seed42,
    load_stress,
    predict_v4_custom,
    predict_v4_logits,
    slice_regime_inputs,
)

from malpdf.scanner.conformal import MondrianConformalEvaluator  # noqa: E402

CALIBRATION_V4 = REPO / "configs/conformal_calibration_v4.json"
CONTRACT_V4 = REPO / "configs/transgraph_v4_contract.json"
CANONICAL_WEIGHTS_V4 = REPO / "artifacts/models/pdf_transgraph_v4/pdf_transgraph_v4_regime_b_seed42.npz"
LOCKED_V3_MULTISEED = REPO / "reports/experiments/transgraph_v3/run_20261123T095927Z_16abd6134688/metrics.json"


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return file_digest(handle, "sha256").hexdigest()


def sha256_lf(path: Path) -> str:
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def summarize_conformal(
    evaluator: MondrianConformalEvaluator, probabilities: np.ndarray, labels: np.ndarray
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    totals = Counter(map(int, labels))
    covered: Counter[int] = Counter()
    singleton_correct = 0
    for probability, label in zip(probabilities, labels, strict=True):
        result = evaluator.evaluate(float(probability))
        counts[result["conformal_state"]] += 1
        if ("MALICIOUS" if label else "BENIGN") in result["prediction_set"]:
            covered[int(label)] += 1
            singleton_correct += not result["reject_for_cdr"]
    n = len(labels)
    inclusion = sum(covered.values())
    rejected = counts["AMBIGUOUS_BOTH"] + counts["DRIFT_OOD_EMPTY"]
    return {
        "count": n,
        "benign_count": totals[0],
        "malicious_count": totals[1],
        "coverage": {
            "benign": ratio(covered[0], totals[0]),
            "malicious": ratio(covered[1], totals[1]),
            "overall": ratio(inclusion, n),
        },
        "covered_count": inclusion,
        "error_rate": ratio(n - inclusion, n),
        "singleton_count": n - rejected,
        "singleton_accuracy": ratio(singleton_correct, n - rejected),
        "ambiguous_both_rate": ratio(counts["AMBIGUOUS_BOTH"], n),
        "drift_ood_empty_rate": ratio(counts["DRIFT_OOD_EMPTY"], n),
        "reject_for_cdr_rate": ratio(rejected, n),
        "state_counts": dict(sorted(counts.items())),
    }


def malicious_ood_metrics(
    evaluator: MondrianConformalEvaluator, probabilities: np.ndarray, decision_threshold: float
) -> dict[str, Any]:
    states = [evaluator.evaluate(float(probability)) for probability in probabilities]
    metrics = summarize_conformal(evaluator, probabilities, np.ones(len(probabilities), dtype=int))
    misses = probabilities < decision_threshold
    rejected = np.asarray([state["reject_for_cdr"] for state in states], dtype=bool)
    return {
        **metrics,
        "recall": ratio(metrics["state_counts"].get("CERTIFIED_MALICIOUS", 0), len(probabilities)),
        "baseline_recall": ratio(int((~misses).sum()), len(probabilities)),
        "rejection_rate": metrics["reject_for_cdr_rate"],
        "ambiguity_drift_capture_rate": ratio(int((misses & rejected).sum()), int(misses.sum())),
        "baseline_miss_count": int(misses.sum()),
    }


def latest_run_dir(root: Path) -> Path:
    runs = sorted((p for p in root.glob("run_*") if (p / "metrics.json").is_file()), key=lambda p: p.name)
    if not runs:
        raise FileNotFoundError(f"No completed run found under {root}")
    return runs[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v4-run", type=Path)
    parser.add_argument("--subset-b-run", type=Path)
    parser.add_argument("--attack-run", type=Path)
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--skip-strict-gate", action="store_true")
    args = parser.parse_args()

    device = torch.device(("cuda" if torch.cuda.is_available() else "cpu") if args.device == "auto" else args.device)
    torch.set_num_threads(min(torch.get_num_threads(), 4))

    v4_run, v4_seed, model, transform, methodology = load_run_seed42(args.v4_run, device)
    v4_metrics = read_json(v4_run / "metrics.json")
    art_dir = REPO / v4_metrics["artifact_directory"]
    subset_run = args.subset_b_run or latest_run_dir(REPO / "reports/experiments/transgraph_v4_subset_b")
    subset_metrics = read_json(subset_run / "metrics.json")
    attack_run = args.attack_run or latest_run_dir(REPO / "reports/experiments/problem_space_adaptive_attack")
    attack_metrics = read_json(attack_run / "metrics.json")

    pool = DEFAULT_POOL if DEFAULT_POOL.is_file() else POOL_ROOT / "pooled.jsonl.gz"
    inputs = {
        "pool": pool,
        "tabular": DEFAULT_TABULAR,
        "label_view": DEFAULT_LABEL_VIEW,
        "split_view": DEFAULT_SPLIT_VIEW,
        "benign_supplement": DEFAULT_SUPP,
    }
    input_hashes = {name: sha256(path) for name, path in inputs.items()}
    for name, digest_val in input_hashes.items():
        if digest_val != methodology["inputs_sha256"][name]:
            raise ValueError(f"locked_v4_input_sha256_mismatch:{name}")

    corpus, _, _, _ = _load_all_pool_corpus(**{f"{name}_path": path for name, path in inputs.items()})
    scoreable = np.isfinite(corpus.raw_73[:, REGIME_B_INDICES]).all(axis=1)
    val = corpus.roles == "val_calib"
    test = corpus.roles == "test_internal"
    source_mask = np.isin(corpus.label_sources, HELD_OUT_OOD_SOURCES) & (corpus.labels == 1)
    selected = np.flatnonzero(val | test | (source_mask & scoreable))

    graphs_sub: list[Any] = [None] * len(corpus.labels)
    from scripts.lab.train_eval_transgraph_v4 import pack_graph, packed_action_ir

    for i in selected.tolist():
        if corpus.graph_present[i]:
            n0, n1 = corpus.node_ptr[i : i + 2]
            e0, e1 = corpus.edge_ptr[i : i + 2]
            graphs_sub[i] = pack_graph(
                (
                    corpus.node_x[n0:n1],
                    corpus.node_type[n0:n1],
                    corpus.edge_src[e0:e1],
                    corpus.edge_dst[e0:e1],
                    corpus.edge_rel[e0:e1],
                )
            )
    ir_sel, act_sel = packed_action_ir([graphs_sub[i] for i in selected.tolist()])
    ir_all = np.zeros((len(corpus.labels), 24), dtype=np.float32)
    act_all = np.zeros((len(corpus.labels),), dtype=bool)
    ir_all[selected] = ir_sel
    act_all[selected] = act_sel
    tab_all, _, _, _ = slice_regime_inputs(*transform.transform(corpus.raw_73), "regime_b")

    temperature = float(v4_seed["temperature"])
    decision_threshold = float(v4_seed["thresholds"]["thr_val_calib"])
    logits_sel, _ = predict_v4_logits(model, graphs_sub, ir_all, act_all, tab_all, selected, device, batch_size=128)
    probabilities = np.full(len(corpus.labels), np.nan)
    probabilities[selected] = apply_temperature(logits_sel, temperature)

    src_weights = art_dir / v4_seed["weights_file"]
    weight_hash = sha256(src_weights)
    scaler_path = art_dir / v4_seed["scaler_file"]
    metadata = {
        "model": "pdf_transgraph_v4",
        "training_run": v4_run.name,
        "role": "val_calib",
        "seed": 42,
        "temperature": temperature,
        "decision_threshold": decision_threshold,
        "weights_npz_sha256": weight_hash,
        "scaler_sha256": sha256(scaler_path),
        "inputs_sha256": input_hashes,
    }
    evaluator = MondrianConformalEvaluator.fit_from_calibration(
        probabilities[val], corpus.labels[val], metadata=metadata
    )

    ood_sources = {}
    for source in HELD_OUT_OOD_SOURCES:
        source_rows = source_mask & (corpus.label_sources == source)
        scored = source_rows & scoreable
        ood_sources[source] = {
            **malicious_ood_metrics(evaluator, probabilities[scored], decision_threshold),
            "input_count": int(source_rows.sum()),
            "excluded_missing_features": int((source_rows & ~scoreable).sum()),
            "by_split_role": {
                str(role): malicious_ood_metrics(
                    evaluator, probabilities[scored & (corpus.roles == role)], decision_threshold
                )
                for role in np.unique(corpus.roles[source_rows])
            },
        }

    stress_rows, stress_raw, stress_graphs = load_stress()
    stress_logits, _ = predict_v4_custom(model, transform, stress_raw, stress_graphs, device)
    stress_probs = apply_temperature(stress_logits, temperature)
    stress_conformal = [
        {
            "id": row["id"],
            "group": row["group"],
            "probability": float(prob),
            **evaluator.evaluate(float(prob)),
        }
        for row, prob in zip(stress_rows, stress_probs, strict=True)
    ]

    prospective_conformal = {}
    for name, track in subset_metrics["tracks"].items():
        scored = [row for row in track["rows"] if row.get("probability") is not None]
        scores = np.asarray([row["probability"] for row in scored], dtype=np.float64)
        reps = np.asarray([row["representative"] for row in scored], dtype=bool)
        prospective_conformal[name] = {
            "input_count": track["input_count"],
            "unscored_count": track["unscored_count"],
            "all_scored": summarize_conformal(evaluator, scores, np.zeros(len(scores), dtype=int)),
            "independent_representatives": summarize_conformal(
                evaluator, scores[reps], np.zeros(int(reps.sum()), dtype=int)
            ),
        }

    test_conformal = summarize_conformal(evaluator, probabilities[test], corpus.labels[test])
    conformal_metrics = {
        "calibration": {"benign_count": len(evaluator.ncm_benign), "malicious_count": len(evaluator.ncm_malicious)},
        "test_internal": test_conformal,
        "loso_malicious_ood": {
            "strict_loso_available": False,
            "reason": "Canonical checkpoint includes the requested sources in training; reported per split role.",
            "canonical_checkpoint_source_screen": ood_sources,
        },
        "phase_2_byte_stress": stress_conformal,
        "prospective_subset_b": prospective_conformal,
    }

    # Gate checks
    gate_checks: dict[str, Any] = {}
    summary = v4_metrics["summary"]
    seed42_row = next(r for r in v4_metrics["seeds"] if r["seed"] == 42)
    b_rep_dict = subset_metrics["tracks"]["prospective_diverse_publishers_v2"]["independent_representatives"]
    c_rep_dict = subset_metrics["tracks"]["prospective_hard_benign_v2"]["independent_representatives"]
    b_track_fp = int(b_rep_dict.get("false_positives", b_rep_dict.get("alerts", 0)))
    c_track_fp = int(c_rep_dict.get("false_positives", c_rep_dict.get("alerts", 0)))
    ir_weight_mean = float(np.mean([r["mean_modality_weights_test"][2] for r in v4_metrics["seeds"]]))
    non_js_fp_all = sum(r["byte_stress"]["non_js_benign_fp_of_11"] for r in v4_metrics["seeds"])
    controls_fp_all = sum(r["reviewed_controls_alerts_thr_f1"] for r in v4_metrics["seeds"])
    seed42_stress_tp = int(seed42_row["byte_stress"]["threat_tp_of_8"])

    v4_att_dep = attack_metrics["models"]["pdf_transgraph_v4"]["deployed_operating_threshold"]["budgets"]
    v3_att_dep = attack_metrics["models"]["pdf_transgraph_v3_2b"]["deployed_operating_threshold"]["budgets"]
    v4_att_mat = attack_metrics["models"]["pdf_transgraph_v4"]["matched_val_calib_fpr_0_5pct"]["budgets"]
    v3_att_mat = attack_metrics["models"]["pdf_transgraph_v3_2b"]["matched_val_calib_fpr_0_5pct"]["budgets"]

    gate_checks["test_all_pr_auc_mean_ge_099995"] = summary["test_all_pr_auc"]["mean"] >= 0.99995
    gate_checks["action_ir_weight_gt_010"] = ir_weight_mean > 0.10
    gate_checks["seed42_byte_stress_8_of_8"] = seed42_stress_tp == 8
    gate_checks["all_seeds_non_js_benign_0_fp"] = non_js_fp_all == 0
    gate_checks["all_seeds_controls_0_fp"] = controls_fp_all == 0
    gate_checks["subset_b_track_b_0_fp"] = b_track_fp == 0
    gate_checks["subset_b_track_c1_0_fp"] = c_track_fp == 0
    gate_checks["conformal_singleton_acc_ge_0999"] = (test_conformal["singleton_accuracy"] or 0.0) >= 0.999
    gate_checks["conformal_benign_cov_ge_0985"] = (test_conformal["coverage"]["benign"] or 0.0) >= 0.985
    gate_checks["conformal_malicious_cov_ge_0985"] = (test_conformal["coverage"]["malicious"] or 0.0) >= 0.985
    gate_checks["conformal_track_b_0_malicious"] = (
        prospective_conformal["prospective_diverse_publishers_v2"]["all_scored"]["state_counts"].get(
            "CERTIFIED_MALICIOUS", 0
        )
        == 0
    )
    gate_checks["attack_b100_deployed_recall_ge_v3"] = v4_att_dep["100"]["recall"] >= v3_att_dep["100"]["recall"]
    gate_checks["attack_b100_matched_recall_ge_v3"] = v4_att_mat["100"]["recall"] >= v3_att_mat["100"]["recall"]
    conformal_metrics["promotion_gates"] = gate_checks
    conformal_metrics["all_gates_passed"] = all(gate_checks.values())

    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    conf_out = REPO / "reports/experiments/mondrian_conformal_v4" / f"run_{now:%Y%m%dT%H%M%S%fZ}_{revision[:12]}"
    conf_out.mkdir(parents=True, exist_ok=False)

    evaluator.to_json_file(CALIBRATION_V4)
    cal_lf_sha = sha256_lf(CALIBRATION_V4)

    write_json(
        conf_out / "locked_methodology.json",
        {
            **metadata,
            "generated_utc": now.isoformat(),
            "revision": revision,
            "device": str(device),
            "alpha_benign": evaluator.alpha_benign,
            "alpha_malicious": evaluator.alpha_malicious,
            "calibration_sha256": sha256(CALIBRATION_V4),
            "calibration_lf_sha256": cal_lf_sha,
            "stress_export_sha256": sha256(DEFAULT_STRESS),
            "subset_b_metrics_sha256": sha256(subset_run / "metrics.json"),
            "attack_metrics_sha256": sha256(attack_run / "metrics.json"),
            "regression_provenance": REGRESSION_DISCLOSURE,
        },
    )
    write_json(conf_out / "metrics.json", conformal_metrics)
    print(json.dumps({"promotion_gates": gate_checks, "all_gates_passed": all(gate_checks.values())}, indent=2))

    if not args.skip_strict_gate and not all(gate_checks.values()):
        failed = [k for k, v in gate_checks.items() if not v]
        raise RuntimeError(f"v4_promotion_gate_failed:{failed}")

    CANONICAL_WEIGHTS_V4.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_weights, CANONICAL_WEIGHTS_V4)
    if sha256(CANONICAL_WEIGHTS_V4) != weight_hash:
        raise RuntimeError("copied_v4_weights_sha256_mismatch")

    contract_payload = {
        "contract_version": "pdf-transgraph-v4-regime-b",
        "fitted_on": "clean_split_20261122T064432Z+v32_benign_supplement_b",
        "source_run": v4_run.name,
        "conformal_run": conf_out.name,
        "subset_b_run": subset_run.name,
        "adaptive_attack_run": attack_run.name,
        "model_name": "pdf_transgraph_v4",
        "regime": "regime_b",
        "seed": 42,
        "temperature": temperature,
        "decision_threshold": decision_threshold,
        "weights_npz_sha256": weight_hash,
        "conformal_calibration_filename": CALIBRATION_V4.name,
        "conformal_calibration_sha256": cal_lf_sha,
        "model_config": model.config.to_dict(),
        "feature_names": list(REGIME_B_NAMES),
        "feature_indices_73": REGIME_B_INDICES.tolist(),
        "center": transform.center[REGIME_B_INDICES].tolist(),
        "scale": transform.scale[REGIME_B_INDICES].tolist(),
    }
    write_json(CONTRACT_V4, contract_payload)
    print(f"Promoted canonical v4 checkpoint: {CANONICAL_WEIGHTS_V4.relative_to(REPO)}")
    print(f"Wrote locked v4 contract: {CONTRACT_V4.relative_to(REPO)}")
    print(f"Wrote locked v4 conformal calibration: {CALIBRATION_V4.relative_to(REPO)}")


if __name__ == "__main__":
    main()
