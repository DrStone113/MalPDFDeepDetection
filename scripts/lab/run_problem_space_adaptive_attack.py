"""Run Problem-Space Adaptive Subtree Grafting Attack across GBDTs, v3.2b, and TransGraph v4."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import lightgbm as lgb
import numpy as np
import pikepdf
import torch
import xgboost as xgb

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    IDX,
    REGIME_B_INDICES,
    apply_temperature,
    gather_graph_list_batch,
    load_pooled_corpus,
    prob_to_logits,
    slice_regime_inputs,
)
from scripts.lab.train_eval_transgraph_v4 import (  # noqa: E402
    DEFAULT_LABEL_VIEW,
    DEFAULT_POOL,
    DEFAULT_SPLIT_VIEW,
    DEFAULT_SUPP,
    DEFAULT_TABULAR,
    predict_v4_custom,
)

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes  # noqa: E402
from malpdf.evaluation.problem_space_attack import (  # noqa: E402
    physical_binary_graft_pdf,
    run_greedy_adaptive_graft_attack,
)
from malpdf.features.contract_v3 import RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v3 import (  # noqa: E402
    PDFTransGraphV3,
    TransGraphV3Config,
    extract_graph_summary_features,
    load_v3_weights_npz,
)
from malpdf.models.pdf_transgraph_v4 import (  # noqa: E402
    PDFTransGraphV4,
    TransGraphV4Config,
    load_v4_weights_npz,
)
from malpdf.scanner.engine import MalPDFScannerEngine  # noqa: E402


def _real_binary_graft_verification() -> dict[str, Any]:
    threat_bytes = load_real_threat_bytes()
    benign_bytes = load_real_benign_bytes()
    scanner = MalPDFScannerEngine(device="cpu")
    results: dict[str, Any] = {}
    for budget in (5, 10, 25, 50, 100):
        grafted = physical_binary_graft_pdf(threat_bytes, benign_bytes, num_padding_objects=budget)
        with pikepdf.open(Path(__file__).resolve().parents[2] / "tests/fixtures/real_threat_document.pdf") as _:
            pass
        res = scanner.scan_bytes(grafted, file_name=f"grafted_{budget}.pdf", explain=False)
        results[str(budget)] = {
            "byte_size": len(grafted),
            "pages": res.pages_count,
            "verdict": res.verdict,
            "malware_probability": res.malware_probability,
            "detected_static_count": res.threat_taxonomy.get("detected_count", 0),
        }
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Problem-Space Adaptive Attack Benchmark (Pierazzi Gamma 1-4)")
    parser.add_argument("--v4-run", type=Path, default=None)
    parser.add_argument("--budgets", type=int, nargs="+", default=[0, 5, 10, 25, 50, 100])
    parser.add_argument("--max-malicious", type=int, default=219)
    args = parser.parse_args()

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exp_dir = REPO / f"reports/experiments/problem_space_adaptive_attack/run_{ts}_{git_rev}"
    exp_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if args.v4_run is None:
        v4_exp = (
            REPO
            / (REPO / "data/processed/pooled_bulk/offline_provenance/current_transgraph_v4_run.txt")
            .read_text(encoding="utf-8")
            .strip()
        )
    else:
        v4_exp = args.v4_run
    v4_metrics = json.loads((v4_exp / "metrics.json").read_text(encoding="utf-8"))
    v4_art = REPO / v4_metrics["artifact_directory"]

    v3_exp = REPO / "reports/experiments/transgraph_v3/run_20261122T123421Z_16abd6134688"
    v3_metrics = json.loads((v3_exp / "metrics.json").read_text(encoding="utf-8"))
    v3_art = REPO / v3_metrics["artifact_directory"] / "regime_b"

    corpus = load_pooled_corpus(
        pool_path=DEFAULT_POOL,
        tabular_path=DEFAULT_TABULAR,
        label_view_path=DEFAULT_LABEL_VIEW,
        split_view_path=DEFAULT_SPLIT_VIEW,
        benign_supplement_path=DEFAULT_SUPP,
    )

    def _raw_graph(row_i: int):
        if not corpus.graph_present[row_i]:
            return None
        n0, n1 = int(corpus.node_ptr[row_i]), int(corpus.node_ptr[row_i + 1])
        e0, e1 = int(corpus.edge_ptr[row_i]), int(corpus.edge_ptr[row_i + 1])
        return (
            corpus.node_x[n0:n1],
            corpus.node_type[n0:n1],
            corpus.edge_src[e0:e1],
            corpus.edge_dst[e0:e1],
            corpus.edge_rel[e0:e1],
        )

    mal_idx = np.flatnonzero(
        (corpus.roles == "test_internal") & (corpus.labels == 1) & corpus.is_bc & corpus.graph_present
    )[: args.max_malicious]
    donor_idx = np.flatnonzero((corpus.roles == "train") & (corpus.labels == 0) & corpus.is_bc & corpus.graph_present)[
        :250
    ]

    mal_raw = corpus.raw_73[mal_idx]
    mal_graphs = [_raw_graph(int(i)) for i in mal_idx]
    donor_raw = corpus.raw_73[donor_idx]
    donor_graphs = [_raw_graph(int(i)) for i in donor_idx]

    with np.load(v3_art / "robust_transform.npz", allow_pickle=False) as sc:
        tf_v3 = RobustTransform(sc["center"], sc["scale"], sc["available"])
    with np.load(v4_art / "robust_transform.npz", allow_pickle=False) as sc:
        tf_v4 = RobustTransform(sc["center"], sc["scale"], sc["available"])

    # Load detectors
    v3_cfg = TransGraphV3Config(**json.loads((v3_art / "v3_tab_graph_ssl_inv_config.json").read_text(encoding="utf-8")))
    v3_mdl = PDFTransGraphV3(v3_cfg).to(device).eval()
    load_v3_weights_npz(v3_mdl, v3_art / "v3_tab_graph_ssl_inv.npz", map_location=device)
    v3_meta = v3_metrics["regime_b_primary"]["models"]["v3_tab_graph_ssl_inv"]

    tab_cfg = TransGraphV3Config(**json.loads((v3_art / "v3_tab_only_config.json").read_text(encoding="utf-8")))
    tab_mdl = PDFTransGraphV3(tab_cfg).to(device).eval()
    load_v3_weights_npz(tab_mdl, v3_art / "v3_tab_only.npz", map_location=device)
    tab_meta = v3_metrics["regime_b_primary"]["models"]["v3_tab_only"]

    v4_seed_dir = v4_art / "seed_42"
    v4_cfg = TransGraphV4Config(
        **json.loads((v4_seed_dir / "pdf_transgraph_v4_config.json").read_text(encoding="utf-8"))
    )
    v4_mdl = PDFTransGraphV4(v4_cfg).to(device).eval()
    load_v4_weights_npz(v4_mdl, v4_seed_dir / "pdf_transgraph_v4.npz", map_location=device)
    v4_meta = v4_metrics["seeds"][0]

    xgb_clf = xgb.XGBClassifier()
    xgb_clf.load_model(str(v3_art / "xgboost_v3.json"))
    xgb_meta = v3_metrics["regime_b_primary"]["models"]["xgboost_v3"]

    lgb_bst = lgb.Booster(model_file=str(v3_art / "lightgbm_v3.txt"))
    lgb_meta = v3_metrics["regime_b_primary"]["models"]["lightgbm_v3"]

    def _summary_from_graphs(graphs: list[Any]) -> np.ndarray:
        nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs, torch.device("cpu"))
        return extract_graph_summary_features(nt_t, ei_t, gb_t, batch_size=len(graphs)).numpy()

    def _score_v3(mdl: PDFTransGraphV3, temp: float, raw_m: np.ndarray, graphs_m: list[Any]) -> np.ndarray:
        sc, ms = tf_v3.transform(raw_m)
        tx, _, ax, am = slice_regime_inputs(sc, ms, "regime_b")
        out_p = []
        with torch.inference_mode():
            for st in range(0, len(raw_m), 256):
                ed = st + 256
                nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs_m[st:ed], device)
                lo = (
                    mdl(
                        torch.from_numpy(tx[st:ed]).to(device),
                        None,
                        torch.from_numpy(ax[st:ed]).to(device),
                        torch.from_numpy(am[st:ed]).to(device),
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
                out_p.append(apply_temperature(lo, temp))
        return np.concatenate(out_p, axis=0)

    def _score_v4(raw_m: np.ndarray, graphs_m: list[Any]) -> np.ndarray:
        lo, _ = predict_v4_custom(v4_mdl, tf_v4, raw_m, graphs_m, device, batch_size=128)
        return apply_temperature(lo, float(v4_meta["temperature"]))

    def _score_xgb(raw_m: np.ndarray, graphs_m: list[Any]) -> np.ndarray:
        xg = np.concatenate((raw_m[:, REGIME_B_INDICES], _summary_from_graphs(graphs_m)), axis=1)
        return apply_temperature(prob_to_logits(xgb_clf.predict_proba(xg)[:, 1]), float(xgb_meta["temperature"]))

    def _score_lgb(raw_m: np.ndarray, graphs_m: list[Any]) -> np.ndarray:
        xg = np.concatenate((raw_m[:, REGIME_B_INDICES], _summary_from_graphs(graphs_m)), axis=1)
        return apply_temperature(lgb_bst.predict(xg, raw_score=True), float(lgb_meta["temperature"]))

    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revision": git_rev,
        "n_malicious_test_bc": int(len(mal_raw)),
        "n_benign_train_donors": int(len(donor_raw)),
        "budgets": args.budgets,
        "v3_run": str(v3_exp.relative_to(REPO)),
        "v4_run": str(v4_exp.relative_to(REPO)),
        "program_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (exp_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")

    targets = [
        ("xgboost_v3", _score_xgb, float(xgb_meta["thresholds"]["thr_f1_macro"])),
        ("lightgbm_v3", _score_lgb, float(lgb_meta["thresholds"]["thr_f1_macro"])),
        (
            "v3_tab_only",
            lambda r, g: _score_v3(tab_mdl, float(tab_meta["temperature"]), r, g),
            float(tab_meta["thresholds"]["thr_f1_macro"]),
        ),
        (
            "pdf_transgraph_v3_2b",
            lambda r, g: _score_v3(v3_mdl, float(v3_meta["temperature"]), r, g),
            float(v3_meta["thresholds"]["thr_f1_macro"]),
        ),
        ("pdf_transgraph_v4", _score_v4, float(v4_meta["thresholds"]["thr_f1_macro"])),
    ]

    model_curves: dict[str, Any] = {}
    for name, fn, thr in targets:
        res = run_greedy_adaptive_graft_attack(
            mal_raw,
            mal_graphs,
            donor_raw,
            donor_graphs,
            IDX,
            fn,
            decision_threshold=thr,
            budgets=tuple(args.budgets),
            beam_candidates=16,
            seed=42,
        )
        model_curves[name] = res
        recalls = {b: round(res["budgets"][str(b)]["recall"], 4) for b in args.budgets}
        print(f"Adaptive Attack [{name}] recall@B: {recalls}", flush=True)

    binary_check = _real_binary_graft_verification()
    metrics = {
        "real_binary_pikepdf_graft_check": binary_check,
        "adaptive_graft_curves": model_curves,
    }
    (exp_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (REPO / "data/processed/pooled_bulk/offline_provenance/current_problem_space_attack_run.txt").write_text(
        str(exp_dir.relative_to(REPO)), encoding="utf-8"
    )
    print("Saved Adaptive Attack benchmark:", exp_dir / "metrics.json")


if __name__ == "__main__":
    main()
