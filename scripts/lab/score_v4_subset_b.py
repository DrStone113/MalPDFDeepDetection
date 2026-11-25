"""Score locked PDF-TransGraph v4 checkpoint on untouched Subset B holdouts (Track B-v2 + Track C1-v2)."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
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
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.score_benign_ood import GRAPH_KEYS, graph_arrays, interval_summary  # noqa: E402
from scripts.lab.train_eval_transgraph_v3 import REGIME_B_INDICES, apply_temperature  # noqa: E402
from scripts.lab.train_eval_transgraph_v4 import predict_v4_custom  # noqa: E402

from malpdf.extraction.numeric_export import MAX_NODES  # noqa: E402
from malpdf.features.contract_v3 import FEATURES, RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v4 import (  # noqa: E402
    PDFTransGraphV4,
    TransGraphV4Config,
    load_v4_weights_npz,
)

IDX = {name: i for i, name in enumerate(FEATURES)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Score PDF-TransGraph v4 on locked Subset B cohorts")
    parser.add_argument("--v4-run", type=Path, default=None)
    parser.add_argument(
        "--export",
        type=Path,
        default=REPO / "data/processed/pooled_bulk/benign_v32_cohort/offline_numeric_export_16mib.json",
    )
    parser.add_argument(
        "--assignments",
        type=Path,
        default=REPO / "data/processed/pooled_bulk/benign_v32_cohort/subset_assignments.json",
    )
    parser.add_argument(
        "--v32-subset-b-metrics",
        type=Path,
        default=REPO / "reports/experiments/benign_v32_cohort/run_20261122T141916Z_08a93e72f13e/metrics.json",
    )
    args = parser.parse_args()

    v4_exp = (
        args.v4_run
        if args.v4_run is not None
        else REPO
        / (REPO / "data/processed/pooled_bulk/offline_provenance/current_transgraph_v4_run.txt")
        .read_text(encoding="utf-8")
        .strip()
    )
    v4_metrics = json.loads((v4_exp / "metrics.json").read_text(encoding="utf-8"))
    v4_art = REPO / v4_metrics["artifact_directory"]
    v4_seed_dir = v4_art / "seed_42"
    v4_seed42_meta = v4_metrics["seeds"][0]

    cfg = TransGraphV4Config(**json.loads((v4_seed_dir / "pdf_transgraph_v4_config.json").read_text(encoding="utf-8")))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PDFTransGraphV4(cfg).to(device).eval()
    load_v4_weights_npz(model, v4_seed_dir / "pdf_transgraph_v4.npz", map_location=device)
    with np.load(v4_art / "robust_transform.npz", allow_pickle=False) as sc:
        transform = RobustTransform(sc["center"], sc["scale"], sc["available"])

    temp = float(v4_seed42_meta["temperature"])
    thr = float(v4_seed42_meta["thresholds"]["thr_f1_macro"])

    export_doc = json.loads(args.export.read_text(encoding="utf-8"))
    row_by_id = {r["id"]: r for r in export_doc["rows"]}
    v32_b = json.loads(args.v32_subset_b_metrics.read_text(encoding="utf-8"))

    # Use exact frozen Subset B cluster admissions & representatives from 16 MiB qualification closeout
    tracks_out: dict[str, Any] = {}
    for track_name in ("prospective_diverse_publishers_v2", "prospective_hard_benign_v2"):
        ref_rows = v32_b["tracks"][track_name]["rows"]
        scored_records = []
        raw_inputs, graphs_in = [], []
        for meta in ref_rows:
            if meta.get("score_status") != "scored":
                continue
            src_row = row_by_id[meta["id"]]
            raw_vec = [np.nan if v is None else float(v) for v in src_row["features"]]
            gf, gt, es, ed, er = graph_arrays(dict(zip(GRAPH_KEYS, src_row["graph"], strict=True), node_feature_dim=23))
            g_tuple = (
                np.asarray(gf[:MAX_NODES], dtype=np.float32),
                np.asarray(gt[:MAX_NODES], dtype=np.int64),
                np.asarray(es, dtype=np.int64),
                np.asarray(ed, dtype=np.int64),
                np.asarray(er, dtype=np.int64),
            )
            raw_inputs.append(raw_vec)
            graphs_in.append(g_tuple)
            scored_records.append(meta)

        raw_mat = np.asarray(raw_inputs, dtype=np.float32)
        if np.isnan(raw_mat[:, REGIME_B_INDICES]).any():
            raise ValueError(f"missing_regime_b_features_in_{track_name}")
        logits, mod_w = predict_v4_custom(model, transform, raw_mat, graphs_in, device, batch_size=128)
        probs = apply_temperature(logits, temp)

        scored_entries = []
        for meta, p_val, w_vec, rv in zip(scored_records, probs, mod_w, raw_inputs, strict=True):
            scored_entries.append(
                {
                    "id": meta["id"],
                    "sha256": meta["sha256"],
                    "source": meta["source"],
                    "representative": bool(meta.get("representative")),
                    "is_le_10kb": rv[IDX["raw_size_bytes"]] <= 10240.0,
                    "probability": float(p_val),
                    "branch_weights": [float(x) for x in w_vec],
                }
            )

        reps = [e for e in scored_entries if e["representative"]]
        small = [e for e in scored_entries if e["is_le_10kb"]]
        tracks_out[track_name] = {
            "all_scored": interval_summary(sum(e["probability"] >= thr for e in scored_entries), len(scored_entries)),
            "independent_representatives": interval_summary(sum(e["probability"] >= thr for e in reps), len(reps)),
            "small_le_10kb": interval_summary(sum(e["probability"] >= thr for e in small), len(small)),
            "max_prob": float(max(e["probability"] for e in scored_entries)),
            "mean_prob": float(np.mean([e["probability"] for e in scored_entries])),
            "mean_branch_weights": [float(x) for x in np.mean([e["branch_weights"] for e in scored_entries], axis=0)],
            "rows": scored_entries,
        }

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO / f"reports/experiments/transgraph_v4_subset_b/run_{ts}_{git_rev}"
    out_dir.mkdir(parents=True, exist_ok=True)
    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ"),
        "revision": git_rev,
        "v4_run": str(v4_exp.relative_to(REPO)),
        "v32_reference_metrics_sha256": hashlib.sha256(args.v32_subset_b_metrics.read_bytes()).hexdigest(),
        "export_sha256": hashlib.sha256(args.export.read_bytes()).hexdigest(),
        "threshold_thr_f1_macro": thr,
        "temperature": temp,
    }
    (out_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")
    (out_dir / "metrics.json").write_text(json.dumps({"tracks": tracks_out}, indent=2) + "\n", encoding="utf-8")
    print("Subset B Track B-v2 reps:", tracks_out["prospective_diverse_publishers_v2"]["independent_representatives"])
    print("Subset B Track C1-v2 reps:", tracks_out["prospective_hard_benign_v2"]["independent_representatives"])
    print("Saved v4 Subset B metrics:", out_dir / "metrics.json")


if __name__ == "__main__":
    main()
