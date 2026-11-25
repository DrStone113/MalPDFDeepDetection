"""End-to-end 5-seed CUDA training & multi-gate evaluation of PDF-TransGraph v4."""

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
import torch.nn.functional as F

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    IDX,
    REGIME_B_INDICES,
    CSRGraphCorpus,
    _load_controls,
    apply_stress_transform,
    apply_temperature,
    compute_debiased_weights,
    compute_slice_metrics,
    fit_temperature,
    load_pooled_corpus,
    perturb_raw_format,
    select_thresholds,
    set_all_seeds,
    simulate_objstm_tabular_mask,
    slice_regime_inputs,
)

from malpdf.evaluation.problem_space_attack import graft_benign_subtree_pair  # noqa: E402
from malpdf.features.contract_v3 import RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v4 import (  # noqa: E402
    ACTION_IR_DIM,
    PDFTransGraphV4,
    TransGraphV4Config,
    build_padded_graph_tensors,
    compute_dag_structural_encodings,
    extract_observable_action_ir_np,
    load_v4_weights_npz,
    save_v4_weights_npz,
    subtree_monotonic_loss,
)

DEFAULT_POOL = REPO / "data/processed/pooled_bulk/pooled.jsonl.gz"
DEFAULT_TABULAR = REPO / "data/processed/pooled_bulk/offline_provenance/tabular_v3.jsonl.gz"
DEFAULT_LABEL_VIEW = REPO / "data/processed/pooled_bulk/offline_provenance/training_labels_20261122T055618Z.jsonl"
DEFAULT_SPLIT_VIEW = REPO / "data/processed/pooled_bulk/offline_provenance/clean_split_20261122T064432Z.jsonl"
DEFAULT_CONTROLS = REPO / "data/processed/pooled_bulk/offline_provenance/reviewed_controls_v3.json"
DEFAULT_SUPP = REPO / "data/processed/pooled_bulk/benign_v32_cohort/v32_benign_supplement.json"
DEFAULT_STRESS = REPO / "data/processed/pooled_bulk/offline_provenance/byte_level_stress_v3.json"


def _precompute_corpus_v4_graphs(
    corpus: CSRGraphCorpus,
) -> tuple[list[tuple[Any, ...] | None], list[tuple[np.ndarray, np.ndarray]]]:
    n = len(corpus.shas)
    packed: list[tuple[Any, ...] | None] = [None] * n
    depths: list[tuple[np.ndarray, np.ndarray]] = [(np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.int64))] * n
    for i in range(n):
        if not corpus.graph_present[i]:
            continue
        n0, n1 = int(corpus.node_ptr[i]), int(corpus.node_ptr[i + 1])
        e0, e1 = int(corpus.edge_ptr[i]), int(corpus.edge_ptr[i + 1])
        nx = corpus.node_x[n0:n1]
        nt = corpus.node_type[n0:n1]
        es = corpus.edge_src[e0:e1]
        ed = corpus.edge_dst[e0:e1]
        er = corpus.edge_rel[e0:e1]
        spd, drel, rd, sd = compute_dag_structural_encodings(len(nx), nt, es, ed, er)
        packed[i] = (nx, nt, es, ed, er, spd, drel, rd, sd)
        depths[i] = (rd, sd)
    return packed, depths


def _pack_raw_graphs_v4(
    raw_graphs: list[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None],
) -> tuple[list[tuple[Any, ...] | None], list[tuple[np.ndarray, np.ndarray]]]:
    packed: list[tuple[Any, ...] | None] = []
    depths: list[tuple[np.ndarray, np.ndarray]] = []
    for g in raw_graphs:
        if g is None or len(g[0]) == 0:
            packed.append(None)
            depths.append((np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.int64)))
            continue
        nx = np.asarray(g[0], dtype=np.float32)
        nt = np.asarray(g[1], dtype=np.int64)
        es = np.asarray(g[2], dtype=np.int64)
        ed = np.asarray(g[3], dtype=np.int64)
        er = np.asarray(g[4], dtype=np.int64)
        spd, drel, rd, sd = compute_dag_structural_encodings(len(nx), nt, es, ed, er)
        packed.append((nx, nt, es, ed, er, spd, drel, rd, sd))
        depths.append((rd, sd))
    return packed, depths


def _extract_action_ir_from_packed(
    raw_73: np.ndarray,
    packed_graphs: list[tuple[Any, ...] | None],
    depths: list[tuple[np.ndarray, np.ndarray]],
) -> tuple[np.ndarray, np.ndarray]:
    b = len(raw_73)
    node_x_parts = []
    node_t_parts = []
    node_ptr = np.zeros(b + 1, dtype=np.int64)
    acc = 0
    for i, g in enumerate(packed_graphs):
        if g is not None and len(g[0]) > 0:
            node_x_parts.append(g[0])
            node_t_parts.append(g[1])
            acc += len(g[0])
        node_ptr[i + 1] = acc
    nx_cat = np.concatenate(node_x_parts, axis=0) if node_x_parts else np.zeros((0, 23), dtype=np.float32)
    nt_cat = np.concatenate(node_t_parts, axis=0) if node_t_parts else np.zeros((0,), dtype=np.int64)
    return extract_observable_action_ir_np(
        raw_73,
        REGIME_B_INDICES,
        IDX,
        node_x=nx_cat,
        node_type=nt_cat,
        node_ptr=node_ptr,
        row_indices=np.arange(b, dtype=np.int64),
        graph_spd_depths=depths,
    )


@torch.no_grad()
def predict_v4_logits(
    model: PDFTransGraphV4,
    corpus: CSRGraphCorpus,
    packed_graphs: list[tuple[Any, ...] | None],
    action_ir_all: np.ndarray,
    action_active_all: np.ndarray,
    tab_x_all: np.ndarray,
    indices: np.ndarray,
    device: torch.device,
    *,
    batch_size: int = 128,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    logits_parts, weight_parts = [], []
    for start in range(0, len(indices), batch_size):
        b_idx = indices[start : start + batch_size]
        g_tensors = build_padded_graph_tensors([packed_graphs[int(i)] for i in b_idx], device)
        out = model(
            torch.from_numpy(tab_x_all[b_idx]).to(device),
            torch.from_numpy(action_ir_all[b_idx]).to(device),
            torch.from_numpy(action_active_all[b_idx]).to(device),
            *g_tensors,
        )
        logits_parts.append(out["logits"].detach().cpu().numpy())
        weight_parts.append(out["weights"].detach().cpu().numpy())
    return np.concatenate(logits_parts, axis=0), np.concatenate(weight_parts, axis=0)


@torch.no_grad()
def predict_v4_custom(
    model: PDFTransGraphV4,
    transform: RobustTransform,
    raw_73: np.ndarray,
    raw_graphs: list[Any],
    device: torch.device,
    *,
    batch_size: int = 128,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    sc, ms = transform.transform(raw_73)
    tab_x, _, _, _ = slice_regime_inputs(sc, ms, "regime_b")
    packed, depths = _pack_raw_graphs_v4(raw_graphs)
    ir_x, ir_act = _extract_action_ir_from_packed(raw_73, packed, depths)
    logits_parts, weight_parts = [], []
    for start in range(0, len(raw_73), batch_size):
        end = start + batch_size
        g_tensors = build_padded_graph_tensors(packed[start:end], device)
        out = model(
            torch.from_numpy(tab_x[start:end]).to(device),
            torch.from_numpy(ir_x[start:end]).to(device),
            torch.from_numpy(ir_act[start:end]).to(device),
            *g_tensors,
        )
        logits_parts.append(out["logits"].detach().cpu().numpy())
        weight_parts.append(out["weights"].detach().cpu().numpy())
    return np.concatenate(logits_parts, axis=0), np.concatenate(weight_parts, axis=0)


def train_v4_single_seed(
    corpus: CSRGraphCorpus,
    packed_graphs: list[tuple[Any, ...] | None],
    depths: list[tuple[np.ndarray, np.ndarray]],
    transform: RobustTransform,
    scaled_all: np.ndarray,
    miss_all: np.ndarray,
    seed: int,
    device: torch.device,
    *,
    epochs: int = 25,
    batch_size: int = 128,
) -> dict[str, Any]:
    set_all_seeds(seed)
    train_lab_idx = np.flatnonzero((corpus.roles == "train") & (corpus.labels >= 0))
    val_sel_idx = np.flatnonzero(corpus.roles == "val_select")
    w_lab = compute_debiased_weights(
        corpus.labels[train_lab_idx], corpus.is_bc[train_lab_idx], corpus.label_sources[train_lab_idx]
    )

    tab_all, _, _, _ = slice_regime_inputs(scaled_all, miss_all, "regime_b")
    ir_all, ir_active_all = extract_observable_action_ir_np(
        corpus.raw_73,
        REGIME_B_INDICES,
        IDX,
        node_x=corpus.node_x,
        node_type=corpus.node_type,
        node_ptr=corpus.node_ptr,
        row_indices=np.arange(len(corpus.shas), dtype=np.int64),
        graph_spd_depths=depths,
    )

    cfg = TransGraphV4Config(
        tab_dim=tab_all.shape[1], action_ir_dim=ACTION_IR_DIM, hidden_dim=128, num_graph_layers=3, num_heads=4
    )
    model = PDFTransGraphV4(cfg).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=8e-4, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(1, epochs))
    rng = np.random.default_rng(seed + 404)

    benign_donors = np.flatnonzero(
        (corpus.roles == "train") & (corpus.labels == 0) & corpus.is_bc & corpus.graph_present
    )
    best_score = -1.0
    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    best_epoch = 0

    for epoch in range(epochs):
        model.train()
        perm = rng.permutation(len(train_lab_idx))
        for start in range(0, len(perm), batch_size):
            sel = perm[start : start + batch_size]
            b_idx = train_lab_idx[sel]
            b_w = torch.from_numpy(w_lab[sel]).to(device)
            b_y = torch.from_numpy(corpus.labels[b_idx]).to(device=device, dtype=torch.float32)

            pert_raw = perturb_raw_format(
                corpus.raw_73[b_idx], np.ones(len(b_idx), dtype=bool), rng, enable_padding=True
            )
            pert_raw = simulate_objstm_tabular_mask(pert_raw, corpus.graph_present[b_idx], rng, prob=0.20)
            sc_b, ms_b = transform.transform(pert_raw)
            tx_b, _, _, _ = slice_regime_inputs(sc_b, ms_b, "regime_b")
            ir_b, act_b = extract_observable_action_ir_np(
                pert_raw,
                REGIME_B_INDICES,
                IDX,
                node_x=None,
                node_type=None,
                node_ptr=np.zeros(len(b_idx) + 1, dtype=np.int64),
                row_indices=np.arange(len(b_idx), dtype=np.int64),
                graph_spd_depths=None,
            )
            # Re-inject clean graph Action-IR coordinates [16:] cleanly from precomputed clean graphs
            ir_b[:, 16:] = ir_all[b_idx, 16:]
            act_b = act_b | ir_active_all[b_idx]

            g_tensors = build_padded_graph_tensors([packed_graphs[int(i)] for i in b_idx], device)
            out = model(
                torch.from_numpy(tx_b).to(device),
                torch.from_numpy(ir_b).to(device),
                torch.from_numpy(act_b).to(device),
                *g_tensors,
            )
            loss = (F.binary_cross_entropy_with_logits(out["logits"], b_y, reduction="none") * b_w).mean()
            aux = (F.binary_cross_entropy_with_logits(out["tab_aux_logits"], b_y, reduction="none") * b_w).mean() + (
                F.binary_cross_entropy_with_logits(out["ir_aux_logits"], b_y, reduction="none") * b_w
            ).mean()
            gm = out["modality_mask"][:, 1]
            if gm.any():
                aux = (
                    aux
                    + (
                        F.binary_cross_entropy_with_logits(out["graph_aux_logits"][gm], b_y[gm], reduction="none")
                        * b_w[gm]
                    ).mean()
                )
            loss = loss + 0.35 * aux

            # Realizable Subtree-Insertion Monotonicity on malicious samples in batch (Chen et al., USENIX '20)
            mal_positions = np.flatnonzero((corpus.labels[b_idx] == 1) & corpus.graph_present[b_idx])
            if len(mal_positions) > 0 and len(benign_donors) > 0:
                sub_pos = mal_positions[: min(16, len(mal_positions))]
                g_raws, g_graphs = [], []
                for pos in sub_pos.tolist():
                    r_id = int(b_idx[pos])
                    d_id = int(benign_donors[rng.integers(0, len(benign_donors))])
                    m_g = packed_graphs[r_id][:5] if packed_graphs[r_id] is not None else None
                    d_g = packed_graphs[d_id][:5] if packed_graphs[d_id] is not None else None
                    gr, gg = graft_benign_subtree_pair(
                        corpus.raw_73[r_id],
                        m_g,
                        corpus.raw_73[d_id],
                        d_g,
                        IDX,
                        donor_fraction=float(rng.uniform(0.5, 1.0)),
                    )
                    g_raws.append(gr)
                    g_graphs.append(gg)
                gr_mat = np.stack(g_raws, axis=0)
                sc_g, ms_g = transform.transform(gr_mat)
                tx_g, _, _, _ = slice_regime_inputs(sc_g, ms_g, "regime_b")
                pk_g, dp_g = _pack_raw_graphs_v4(g_graphs)
                ir_g, act_g = _extract_action_ir_from_packed(gr_mat, pk_g, dp_g)
                gt_tensors = build_padded_graph_tensors(pk_g, device)
                g_out = model(
                    torch.from_numpy(tx_g).to(device),
                    torch.from_numpy(ir_g).to(device),
                    torch.from_numpy(act_g).to(device),
                    *gt_tensors,
                )
                sub_t = torch.as_tensor(sub_pos, device=device, dtype=torch.long)
                mono = subtree_monotonic_loss(out["logits"][sub_t], g_out["logits"], margin=0.25)
                mal_sup = F.binary_cross_entropy_with_logits(g_out["logits"], torch.ones_like(g_out["logits"]))
                loss = loss + 0.50 * mono + 0.25 * mal_sup

            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        sched.step()

        val_logits, _ = predict_v4_logits(
            model, corpus, packed_graphs, ir_all, ir_active_all, tab_all, val_sel_idx, device
        )
        val_probs = apply_temperature(val_logits, 1.0)
        val_y = corpus.labels[val_sel_idx]
        val_bc = corpus.is_bc[val_sel_idx]
        from sklearn.metrics import average_precision_score

        all_ap = float(average_precision_score(val_y, val_probs))
        bc_ap = (
            float(average_precision_score(val_y[val_bc], val_probs[val_bc]))
            if len(np.unique(val_y[val_bc])) == 2
            else all_ap
        )
        sel_score = 0.60 * bc_ap + 0.40 * all_ap
        if sel_score > best_score:
            best_score = sel_score
            best_epoch = epoch + 1
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    best_model = PDFTransGraphV4(cfg).to(device)
    best_model.load_state_dict(best_state, strict=True)
    return {
        "model": best_model,
        "config": cfg,
        "best_epoch": best_epoch,
        "val_select_composite_ap": best_score,
        "ir_all": ir_all,
        "ir_active_all": ir_active_all,
        "tab_all": tab_all,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate PDF-TransGraph v4 across seeds 42-46")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    parser.add_argument("--epochs", type=int, default=20)
    args = parser.parse_args()

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    exp_dir = REPO / f"reports/experiments/transgraph_v4/run_{ts}_{git_rev}"
    art_dir = REPO / f"data/processed/pooled_bulk/transgraph_v4/run_{ts}_{git_rev}"
    exp_dir.mkdir(parents=True, exist_ok=True)
    art_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    corpus = load_pooled_corpus(
        pool_path=DEFAULT_POOL,
        tabular_path=DEFAULT_TABULAR,
        label_view_path=DEFAULT_LABEL_VIEW,
        split_view_path=DEFAULT_SPLIT_VIEW,
        benign_supplement_path=DEFAULT_SUPP,
    )
    packed_graphs, depths = _precompute_corpus_v4_graphs(corpus)
    train_all_idx = np.flatnonzero(corpus.roles == "train")
    transform = RobustTransform.fit(corpus.raw_73[train_all_idx], roles=["train"] * len(train_all_idx))
    scaled_all, miss_all = transform.transform(corpus.raw_73)

    ctrl_names, ctrl_raw_73, ctrl_graphs, _ = _load_controls(DEFAULT_CONTROLS)
    stress_payload = json.loads(DEFAULT_STRESS.read_text(encoding="utf-8"))
    stress_rows = stress_payload["variants"]
    stress_raw = np.asarray(
        [[np.nan if v is None else float(v) for v in r["vector_v3"]] for r in stress_rows], dtype=np.float32
    )
    stress_graphs = [r["graph"] for r in stress_rows]

    val_cal_idx = np.flatnonzero(corpus.roles == "val_calib")
    test_idx = np.flatnonzero(corpus.roles == "test_internal")
    cal_y, cal_bc = corpus.labels[val_cal_idx], corpus.is_bc[val_cal_idx]
    test_y, test_bc = corpus.labels[test_idx], corpus.is_bc[test_idx]
    test_bc_mal = test_idx[test_bc & (test_y == 1)]

    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revision": git_rev,
        "device": str(device),
        "seeds": args.seeds,
        "epochs": args.epochs,
        "program_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (exp_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")

    np.savez_compressed(
        art_dir / "robust_transform.npz",
        center=transform.center,
        scale=transform.scale,
        available=transform.available,
    )

    seed_reports = []
    for seed in args.seeds:
        tr = train_v4_single_seed(
            corpus, packed_graphs, depths, transform, scaled_all, miss_all, seed, device, epochs=args.epochs
        )
        mdl = tr["model"]
        seed_dir = art_dir / f"seed_{seed}"
        seed_dir.mkdir(parents=True, exist_ok=True)
        save_v4_weights_npz(mdl, seed_dir / "pdf_transgraph_v4.npz")
        (seed_dir / "pdf_transgraph_v4_config.json").write_text(
            json.dumps(tr["config"].to_dict(), indent=2) + "\n", encoding="utf-8"
        )

        # Verify allow_pickle=False reload parity
        reloaded = PDFTransGraphV4(tr["config"]).to(device).eval()
        load_v4_weights_npz(reloaded, seed_dir / "pdf_transgraph_v4.npz", map_location=device)

        cal_logits, _ = predict_v4_logits(
            reloaded, corpus, packed_graphs, tr["ir_all"], tr["ir_active_all"], tr["tab_all"], val_cal_idx, device
        )
        temp = fit_temperature(cal_logits, cal_y)
        cal_probs = apply_temperature(cal_logits, temp)
        thrs = select_thresholds(cal_y, cal_probs, cal_bc)
        t_f1, t_fpr1 = thrs["thr_f1_macro"], thrs["thr_fpr1"]

        tst_logits, tst_weights = predict_v4_logits(
            reloaded, corpus, packed_graphs, tr["ir_all"], tr["ir_active_all"], tr["tab_all"], test_idx, device
        )
        tst_probs = apply_temperature(tst_logits, temp)
        ctrl_logits, _ = predict_v4_custom(reloaded, transform, ctrl_raw_73, ctrl_graphs, device)
        ctrl_probs = apply_temperature(ctrl_logits, temp)

        stress_logits, _ = predict_v4_custom(reloaded, transform, stress_raw, stress_graphs, device)
        stress_probs = apply_temperature(stress_logits, temp)
        nonjs_fp = sum(
            1
            for r, p in zip(stress_rows, stress_probs, strict=True)
            if r["group"] == "benign" and r["id"] != "benign_safe_js_alert" and p >= t_f1
        )
        thr_tp = sum(1 for r, p in zip(stress_rows, stress_probs, strict=True) if r["group"] == "threat" and p >= t_f1)
        objstm_p = float(
            next(p for r, p in zip(stress_rows, stress_probs, strict=True) if r["id"] == "threat_objstm_packed")
        )
        pad50_p = float(
            next(p for r, p in zip(stress_rows, stress_probs, strict=True) if r["id"] == "threat_padded_50_pages")
        )

        # Test pad_dilute 50-page +100 obj stress on Test_Internal BC malicious rows
        pert_mal_raw = apply_stress_transform(corpus.raw_73[test_bc_mal], "pad_dilute")
        pert_mal_graphs = [
            packed_graphs[int(i)][:5] if packed_graphs[int(i)] is not None else None for i in test_bc_mal
        ]
        pm_logits, _ = predict_v4_custom(reloaded, transform, pert_mal_raw, pert_mal_graphs, device)
        pm_probs = apply_temperature(pm_logits, temp)
        pad_dilute_recall = float(np.mean(pm_probs >= t_f1))

        rep = {
            "seed": seed,
            "best_epoch": tr["best_epoch"],
            "temperature": temp,
            "thresholds": thrs,
            "mean_modality_weights_test": [float(x) for x in tst_weights.mean(axis=0)],
            "test_all": compute_slice_metrics(test_y, tst_probs, t_f1, t_fpr1),
            "test_bc": compute_slice_metrics(test_y[test_bc], tst_probs[test_bc], t_f1, t_fpr1),
            "reviewed_controls_alerts_thr_f1": int(np.sum(ctrl_probs >= t_f1)),
            "byte_stress": {
                "threat_tp_of_8": int(thr_tp),
                "non_js_benign_fp_of_11": int(nonjs_fp),
                "threat_objstm_packed_p": objstm_p,
                "threat_padded_50_pages_p": pad50_p,
            },
            "pad_dilute_recall": pad_dilute_recall,
        }
        seed_reports.append(rep)
        print(
            f"[seed={seed}] F1={rep['test_all']['thr_f1_macro']['f1_macro']:.4f} "
            f"BC_F1={rep['test_bc']['thr_f1_macro']['f1_macro']:.4f} "
            f"weights={[round(x, 4) for x in rep['mean_modality_weights_test']]} "
            f"stress={thr_tp}/8 fp={nonjs_fp}/11 objstm={objstm_p:.4f} pad_dilute={pad_dilute_recall:.4f}",
            flush=True,
        )

    agg = {
        "test_all_pr_auc": [float(r["test_all"]["pr_auc"]) for r in seed_reports],
        "test_all_f1_macro": [float(r["test_all"]["thr_f1_macro"]["f1_macro"]) for r in seed_reports],
        "test_bc_pr_auc": [float(r["test_bc"]["pr_auc"]) for r in seed_reports],
        "test_bc_f1_macro": [float(r["test_bc"]["thr_f1_macro"]["f1_macro"]) for r in seed_reports],
        "byte_stress_tp_of_8": [r["byte_stress"]["threat_tp_of_8"] for r in seed_reports],
        "byte_stress_non_js_fp_of_11": [r["byte_stress"]["non_js_benign_fp_of_11"] for r in seed_reports],
        "pad_dilute_recall": [r["pad_dilute_recall"] for r in seed_reports],
        "action_ir_weight": [r["mean_modality_weights_test"][2] for r in seed_reports],
    }
    summary = {k: {"mean": float(np.mean(v)), "std": float(np.std(v))} for k, v in agg.items()}

    out_doc = {
        "run_directory": str(exp_dir.relative_to(REPO)),
        "artifact_directory": str(art_dir.relative_to(REPO)),
        "summary": summary,
        "seeds": seed_reports,
    }
    (exp_dir / "metrics.json").write_text(json.dumps(out_doc, indent=2) + "\n", encoding="utf-8")
    (REPO / "data/processed/pooled_bulk/offline_provenance/current_transgraph_v4_run.txt").write_text(
        str(exp_dir.relative_to(REPO)), encoding="utf-8"
    )
    print("Saved TransGraph v4 metrics:", exp_dir / "metrics.json")


if __name__ == "__main__":
    main()
