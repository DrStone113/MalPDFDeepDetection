"""Score the locked v4 seed 42 on the frozen Subset B regression cohorts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import torch

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.score_benign_ood import GRAPH_KEYS, digest, graph_arrays, interval_summary, read_json  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import REGIME_B_INDICES, apply_temperature  # noqa: E402
from scripts.lab.train_eval_transgraph_v4 import (  # noqa: E402
    DEFAULT_SPLIT_VIEW,
    DEFAULT_SUPP,
    REGRESSION_DISCLOSURE,
    load_run_seed42,
    predict_v4_custom,
    write_json,
)

from malpdf.features.contract_v3 import FEATURES  # noqa: E402

DEFAULT_EXPORT = DEFAULT_SUPP.parent / "offline_numeric_export_16mib.json"
DEFAULT_REFERENCE = REPO / "reports/experiments/benign_v32_cohort/run_20261122T141916Z_08a93e72f13e/metrics.json"
TRACKS = {"prospective_diverse_publishers_v2": "Track B-v2", "prospective_hard_benign_v2": "Track C1-v2"}
MODALITIES = ("tab", "graph", "action_ir")


def load_subset(export: Path, reference: Path, train_input_hashes: dict) -> tuple[dict, dict]:
    ref = read_json(reference)
    ref_lock = reference.with_name("locked_methodology.json")
    read_json(ref_lock, ref["locked_methodology_sha256"])
    doc = read_json(export, ref["export_sha256"])
    if doc["feature_order"] != list(FEATURES) or doc["job_id"] != ref["job_id"]:
        raise ValueError("subset_b_export_contract_mismatch")
    if not ref["representative_scoring_complete"]:
        raise ValueError("incomplete_subset_b_representative_scoring")
    if digest(DEFAULT_SPLIT_VIEW) != train_input_hashes["split_view"]:
        raise ValueError("subset_b_split_view_changed")
    with DEFAULT_SPLIT_VIEW.open(encoding="utf-8") as stream:
        next(stream)
        fitted = {
            row["sha256"]
            for row in map(json.loads, stream)
            if row["role"] in {"train", "val_select", "val_calib", "test_internal"}
        }
    supplement = read_json(DEFAULT_SUPP, train_input_hashes["benign_supplement"])
    fitted.update(row["sha256"] for row in supplement["rows"])
    by_id = {r["id"]: r for r in doc["rows"]}
    if len(by_id) != len(doc["rows"]):
        raise ValueError("duplicate_subset_b_export_id")
    inputs = {}
    for track in TRACKS:
        metadata = ref["tracks"][track]["rows"]
        selected, raw, graphs = [], [], []
        for meta in metadata:
            if meta["score_status"] != "scored":
                continue
            row = by_id[meta["id"]]
            if row["sha256"] in fitted or row["sha256"] != meta["sha256"] or row["source"] != meta["source"]:
                raise ValueError(f"subset_b_identity_or_partition_mismatch:{meta['id']}")
            selected.append(meta)
            raw.append(row["features"])
            graphs.append(graph_arrays(dict(zip(GRAPH_KEYS, row["graph"], strict=True), node_feature_dim=23)))
        matrix = np.asarray(raw, dtype=np.float32)
        if not selected or not np.isfinite(matrix[:, REGIME_B_INDICES]).all():
            raise ValueError(f"incomplete_subset_b_scoring_inputs:{track}")
        inputs[track] = (len(metadata), selected, matrix, graphs)
    return inputs, {
        "offline_numeric_export_16mib.json": ref["export_sha256"],
        "reference_metrics": digest(reference),
        "reference_methodology": ref["locked_methodology_sha256"],
    }


def score_tracks(model, transform, seed: dict, inputs: dict, device: torch.device) -> dict:
    threshold = float(seed["thresholds"]["thr_val_calib"])
    tracks = {}
    for track, (count, metadata, raw, graphs) in inputs.items():
        logits, weights = predict_v4_custom(model, transform, raw, graphs, device)
        probs = apply_temperature(logits, seed["temperature"])
        rows = [
            {
                "id": meta["id"],
                "sha256": meta["sha256"],
                "source": meta["source"],
                "representative": bool(meta["representative"]),
                "probability": float(p),
                "predicted_malicious": bool(p >= threshold),
                "weights": dict(zip(MODALITIES, w.tolist(), strict=True)),
            }
            for meta, p, w in zip(metadata, probs, weights, strict=True)
        ]
        reps = np.asarray([row["representative"] for row in rows], dtype=bool)

        def summary(mask):
            return {
                **interval_summary(int((probs[mask] >= threshold).sum()), int(mask.sum())),
                "mean_modality_weights": dict(zip(MODALITIES, weights[mask].mean(axis=0).tolist(), strict=True))
                if mask.any()
                else None,
            }

        tracks[track] = {
            "track": TRACKS[track],
            "input_count": count,
            "unscored_count": count - len(rows),
            "all_scored": summary(np.ones(len(rows), dtype=bool)),
            "independent_representatives": summary(reps),
            "rows": rows,
        }
    return tracks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v4-run", type=Path)
    parser.add_argument("--export", type=Path, default=DEFAULT_EXPORT)
    parser.add_argument("--v32-subset-b-metrics", type=Path, default=DEFAULT_REFERENCE)
    args = parser.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.set_num_threads(min(torch.get_num_threads(), 4))
    run, seed, model, transform, methodology = load_run_seed42(args.v4_run, device)
    inputs, hashes = load_subset(args.export, args.v32_subset_b_metrics, methodology["inputs_sha256"])

    revision = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    now = datetime.now(timezone.utc)
    out = REPO / "reports/experiments/transgraph_v4_subset_b" / f"run_{now:%Y%m%dT%H%M%S%fZ}_{revision}"
    out.mkdir(parents=True, exist_ok=False)
    lock = out / "locked_methodology.json"
    write_json(
        lock,
        {
            "generated_utc": now.isoformat(),
            "revision": revision,
            "v4_run": str(run),
            "seed": seed["seed"],
            "thr_val_calib": seed["thresholds"]["thr_val_calib"],
            "temperature": seed["temperature"],
            "inputs_sha256": {
                "v4_locked_methodology": digest(run / "locked_methodology.json"),
                "v4_checkpoint_lock": digest(run / "checkpoint_lock.json"),
                **seed["artifacts"],
                **hashes,
            },
            "regression_provenance": REGRESSION_DISCLOSURE,
        },
    )
    write_json(
        out / "metrics.json",
        {"locked_methodology_sha256": digest(lock), "tracks": score_tracks(model, transform, seed, inputs, device)},
    )
    print("Saved v4 Subset B metrics:", out / "metrics.json")


if __name__ == "__main__":
    main()
