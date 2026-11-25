from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import file_digest
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import numpy as np
import torch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO)]

from scripts.lab.eval_loso_malicious_ood import HELD_OUT_OOD_SOURCES, _load_all_pool_corpus  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    REGIME_B_INDICES,
    apply_temperature,
    gather_graph_list_batch,
    predict_neural_logits,
    slice_regime_inputs,
)

from malpdf.features.contract_v3 import RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v3 import PDFTransGraphV3, TransGraphV3Config, load_v3_weights_npz  # noqa: E402
from malpdf.scanner.conformal import MondrianConformalEvaluator  # noqa: E402

POOL_ROOT = REPO / "data/processed/pooled_bulk"
OFFLINE = POOL_ROOT / "offline_provenance"
TRAINING_RUN = "run_20261122T123421Z_16abd6134688"
TRAINING_REPORT = REPO / "reports/experiments/transgraph_v3" / TRAINING_RUN
REGIME = POOL_ROOT / "transgraph_v3" / TRAINING_RUN / "regime_b"
MODEL = "v3_tab_graph_ssl_inv"
TEMPERATURE = 0.88840063
CALIBRATION = REPO / "configs/conformal_calibration_v3.json"
PROSPECTIVE = REPO / "reports/experiments/benign_v32_cohort/run_20261122T141916Z_08a93e72f13e"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return file_digest(handle, "sha256").hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def summarize(evaluator: MondrianConformalEvaluator, probabilities: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
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
        "error_rate": ratio(n - inclusion, n),
        "singleton_count": n - rejected,
        "singleton_accuracy": ratio(singleton_correct, n - rejected),
        "ambiguous_both_rate": ratio(counts["AMBIGUOUS_BOTH"], n),
        "drift_ood_empty_rate": ratio(counts["DRIFT_OOD_EMPTY"], n),
        "reject_for_cdr_rate": ratio(rejected, n),
        "state_counts": dict(sorted(counts.items())),
    }


def malicious_metrics(
    evaluator: MondrianConformalEvaluator, probabilities: np.ndarray, decision_threshold: float
) -> dict[str, Any]:
    states = [evaluator.evaluate(float(probability)) for probability in probabilities]
    metrics = summarize(evaluator, probabilities, np.ones(len(probabilities), dtype=int))
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Fit and evaluate the locked v3.2b Mondrian calibration")
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    args = parser.parse_args()
    device = torch.device(("cuda" if torch.cuda.is_available() else "cpu") if args.device == "auto" else args.device)
    torch.set_num_threads(min(torch.get_num_threads(), 4))

    requested_pool = POOL_ROOT / "unlabeled/run_20261122T054134Z_16abd6134688/transgraph_pooled.json.gz"
    inputs = {
        "pool": requested_pool if requested_pool.is_file() else POOL_ROOT / "pooled.jsonl.gz",
        "tabular": OFFLINE / "tabular_v3.jsonl.gz",
        "label_view": OFFLINE / "training_labels_20261122T055618Z.jsonl",
        "split_view": OFFLINE / "clean_split_20261122T064432Z.jsonl",
        "benign_supplement": POOL_ROOT / "benign_v32_cohort/v32_benign_supplement.json",
    }
    input_hashes = {name: sha256(path) for name, path in inputs.items()}
    expected = read_json(TRAINING_REPORT / "locked_methodology.json")["inputs_sha256"]
    for name, digest in input_hashes.items():
        if digest != expected[name]:
            raise ValueError(f"locked_v3_input_sha256_mismatch:{name}")

    weights = REGIME / f"{MODEL}.npz"
    config = REGIME / f"{MODEL}_config.json"
    scaler = REGIME / "robust_transform.npz"
    weight_hash = sha256(weights)
    contract = read_json(REPO / "configs/transgraph_v3_contract.json")
    if weight_hash != contract["weights_npz_sha256"] or read_json(config) != contract["model_config"]:
        raise ValueError("locked_v3_checkpoint_mismatch")

    prospect_path = PROSPECTIVE / "metrics.json"
    prospect_lock_path = PROSPECTIVE / "locked_methodology.json"
    prospect_lock = read_json(prospect_lock_path)
    if (
        prospect_lock["input_sha256"]["weights"] != weight_hash
        or prospect_lock["input_sha256"]["scaler"] != sha256(scaler)
        or abs(prospect_lock["temperature"] - TEMPERATURE) > 1e-9
    ):
        raise ValueError("locked_prospective_model_mismatch")
    prospect = read_json(prospect_path)
    if prospect["locked_methodology_sha256"] != sha256(prospect_lock_path):
        raise ValueError("locked_prospective_report_mismatch")

    print(f"Loading locked numeric/graph corpus on {device}", flush=True)
    corpus, _, _, _ = _load_all_pool_corpus(**{f"{name}_path": path for name, path in inputs.items()})
    with np.load(scaler, allow_pickle=False) as arrays:
        transform = RobustTransform(arrays["center"], arrays["scale"], arrays["available"])
    model = PDFTransGraphV3(TransGraphV3Config(**contract["model_config"])).to(device).eval()
    load_v3_weights_npz(model, weights, map_location=device)
    scaled, missing = transform.transform(corpus.raw_73)
    scoreable = ~missing[:, REGIME_B_INDICES].any(axis=1)
    # Inference indexes full-size feature arrays, including unscored and incomplete rows.
    features = slice_regime_inputs(scaled, missing & scoreable[:, None], "regime_b")
    val = corpus.roles == "val_calib"
    test = corpus.roles == "test_internal"
    if int(test.sum()) != 2027 or not scoreable[val | test].all():
        raise ValueError("locked_calibration_or_test_rows_missing")
    source_mask = np.isin(corpus.label_sources, HELD_OUT_OOD_SOURCES) & (corpus.labels == 1)
    selected = np.flatnonzero(val | test | (source_mask & scoreable))
    logits, _ = predict_neural_logits(model, corpus, selected, *features, device, batch_size=64)
    probabilities = np.full(len(corpus.labels), np.nan)
    probabilities[selected] = apply_temperature(logits, TEMPERATURE)

    metadata = {
        "model": MODEL,
        "training_run": TRAINING_RUN,
        "role": "val_calib",
        "temperature": TEMPERATURE,
        "weights_npz_sha256": weight_hash,
        "scaler_sha256": sha256(scaler),
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
            **malicious_metrics(evaluator, probabilities[scored], contract["decision_threshold"]),
            "input_count": int(source_rows.sum()),
            "excluded_missing_features": int((source_rows & ~scoreable).sum()),
            "by_split_role": {
                str(role): malicious_metrics(
                    evaluator, probabilities[scored & (corpus.roles == role)], contract["decision_threshold"]
                )
                for role in np.unique(corpus.roles[source_rows])
            },
        }

    stress_path = OFFLINE / "byte_level_stress_v3.json"
    variants = read_json(stress_path)["variants"]
    stress_raw = np.asarray([row["vector_v3"] for row in variants], dtype=np.float32)
    tx, tm, ax, am = slice_regime_inputs(*transform.transform(stress_raw), "regime_b")
    graph_batch = gather_graph_list_batch([row["graph"] for row in variants], device)
    with torch.inference_mode():
        stress_logits = (
            model(
                torch.as_tensor(tx, device=device),
                tm,
                torch.as_tensor(ax, device=device),
                torch.as_tensor(am, device=device),
                *graph_batch,
            )["logits"]
            .cpu()
            .numpy()
        )
    stress_probs = apply_temperature(stress_logits, TEMPERATURE)
    stress_metrics = [
        {
            "id": row["id"],
            "group": row["group"],
            "probability": float(prob),
            **evaluator.evaluate(float(prob)),
        }
        for row, prob in zip(variants, stress_probs, strict=True)
    ]

    prospective_metrics = {}
    for name, track in prospect["tracks"].items():
        scored = [row for row in track["rows"] if row.get("probability") is not None]
        scores = np.asarray([row["probability"] for row in scored], dtype=np.float64)
        representatives = np.asarray([row["representative"] for row in scored], dtype=bool)
        prospective_metrics[name] = {
            "input_count": len(track["rows"]),
            "unscored_count": len(track["rows"]) - len(scored),
            "all_scored": summarize(evaluator, scores, np.zeros(len(scores), dtype=int)),
            "independent_representatives": summarize(
                evaluator, scores[representatives], np.zeros(int(representatives.sum()), dtype=int)
            ),
        }

    metrics = {
        "calibration": {"benign_count": len(evaluator.ncm_benign), "malicious_count": len(evaluator.ncm_malicious)},
        "test_internal": summarize(evaluator, probabilities[test], corpus.labels[test]),
        "loso_malicious_ood": {
            "strict_loso_available": False,
            "reason": "Canonical checkpoint includes the requested sources in training. Historical LOSO exports lack complete row-level scores and reusable weights.",
            "canonical_checkpoint_source_screen": ood_sources,
        },
        "phase_2_byte_stress": stress_metrics,
        "prospective_subset_b": prospective_metrics,
    }
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    output = REPO / "reports/experiments/mondrian_conformal_v3" / f"run_{now:%Y%m%dT%H%M%S%fZ}_{revision[:12]}"
    evaluator.to_json_file(CALIBRATION)
    output.mkdir(parents=True, exist_ok=False)
    write_json(
        output / "locked_methodology.json",
        {
            **metadata,
            "generated_utc": now.isoformat(),
            "revision": revision,
            "device": str(device),
            "alpha_benign": evaluator.alpha_benign,
            "alpha_malicious": evaluator.alpha_malicious,
            "decision_threshold": contract["decision_threshold"],
            "input_paths": {name: path.relative_to(REPO).as_posix() for name, path in inputs.items()},
            "requested_pool_path": requested_pool.relative_to(REPO).as_posix(),
            "calibration_sha256": sha256(CALIBRATION),
            "stress_export_sha256": sha256(stress_path),
            "prospective_metrics_sha256": sha256(prospect_path),
            "scoring_policy": "Temperature-scaled model probabilities. No runtime static overrides.",
            "error_rate_definition": "Fraction of rows whose true class is absent from the prediction set.",
            "ood_recall_definition": "Fraction of rows assigned the malicious singleton.",
            "ood_capture_rate_definition": "Fraction of threshold false negatives assigned ambiguous or empty sets.",
            "reference": "https://discovery.ucl.ac.uk/id/eprint/10142926/",
        },
    )
    write_json(output / "metrics.json", metrics)
    print(f"Saved calibration: {CALIBRATION.relative_to(REPO)}")
    print(f"Saved evaluation: {output.relative_to(REPO)}")


if __name__ == "__main__":
    main()
