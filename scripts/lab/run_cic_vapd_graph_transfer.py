from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import numpy as np
import torch
from torch.utils.data import DataLoader

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from malpdf.data.graph_export_v2_loader import (
    collate_multimodal_batch_v2, collate_non_graph_batch_v2, load_multimodal_dataset_v2,
)
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph
from scripts.lab.export_vapd_retrospective_inputs import SPLITS, STATUSES, digest
from scripts.lab.run_cic_vapd_augmentation import (
    CIC_COUNTS, CIC_DIR, CIC_MANIFEST_SHA256, SUPPLEMENT_PER_CLASS, VAPD_INPUT, VAPD_INPUT_SHA256,
    load_cic, membership_hash, metrics_for_test, pick_supplement,
)
from scripts.lab.run_vapd_retrospective import (
    FPR_BUDGET, SEED, deduplicate_development, infer_batch, load_inputs, operating_point, write_json,
)
from scripts.lab.train_eval_pdf_transgraph_v2 import (
    DEFAULT_PARQUET_CIC, DEFAULT_PARQUET_OURS, evaluate_split_v2, set_deterministic_seed,
)

CIC_INPUT_HASHES = {
    CIC_DIR / "manifest.json": CIC_MANIFEST_SHA256,
    DEFAULT_PARQUET_CIC: "25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65",
    DEFAULT_PARQUET_OURS: "79f9e662b3f3b327bc2cc4e87fb5d097dd435b54ec56e6e1b72821456aeef1e2",
}
SUPPLEMENT_SHA256 = "a5aeaef440ca6cc8d931e1c6e6b90b46ca1fc5b9c8481bf5af317a01451df5a2"
CIC_EPOCHS = 25
PRETRAIN_EPOCHS = 10
BATCH_SIZE = 32


def initialize_full(tabular_dim, encoder_weights=None):
    set_deterministic_seed(SEED)
    model = PDFTransGraph(node_in_dim=23, tabular_in_features=tabular_dim, hidden_dim=128, ablation_mode="full")
    if encoder_weights is not None:
        model.graph_encoder.load_state_dict(encoder_weights, strict=True)
    return model


def train(model, samples, epochs, device, *, validation=None, fallback=None):
    collate = collate_non_graph_batch_v2 if model.ablation_mode == "tab_ast" else collate_multimodal_batch_v2
    loader = DataLoader(samples, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate,
                        generator=torch.Generator().manual_seed(SEED))
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.0001)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = FocalLoss(alpha=0.6, gamma=2.0)
    best, history = None, []
    for epoch in range(1, epochs + 1):
        model.train()
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            logits = infer_batch(model, batch, device)
            loss = criterion(logits, batch["labels"].to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()
        scheduler.step()
        if validation is not None:
            result = evaluate_split_v2(model, *validation, device, fallback_tab_ast_model=fallback)
            scores = result["full_denominator"]
            key = scores["f1"], scores["roc_auc"]
            history.append({"epoch": epoch, "f1": key[0], "roc_auc": key[1]})
            if best is None or key > best[0]:
                weights = {name: value.detach().cpu().clone() for name, value in model.state_dict().items()}
                best = key, epoch, weights
        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            print(f"{model.ablation_mode} epoch {epoch}/{epochs}", flush=True)
    if best is None:
        return {"epochs": epochs}
    _, best_epoch, weights = best
    model.load_state_dict(weights)
    return {"best_epoch": best_epoch, "validation_history": history}


def main():
    parser = argparse.ArgumentParser(description="Transfer a VAPD-initialized graph encoder to canonical CIC")
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for this comparison")
    torch.set_num_threads(4)
    device = torch.device("cuda")
    if digest(VAPD_INPUT) != VAPD_INPUT_SHA256 or any(digest(path) != h for path, h in CIC_INPUT_HASHES.items()):
        raise ValueError("A pinned input changed")

    canonical = load_multimodal_dataset_v2(CIC_DIR, DEFAULT_PARQUET_OURS, DEFAULT_PARQUET_CIC)
    full, gnn = canonical["full_split_samples"], canonical["gnn_eligible_samples"]
    dim = canonical["tabular_in_features"]
    if dim != 38 or {name: len(full[name]) for name in SPLITS} != CIC_COUNTS:
        raise ValueError("Unexpected canonical dimensions or partitions")
    all_samples = [item for split in SPLITS for item in full[split]]
    table = np.stack([sample["tab_features"].numpy() for sample in all_samples])
    roles = np.concatenate([np.full(len(full[split]), i) for i, split in enumerate(SPLITS)])
    if not np.isfinite(table).all() or [len(part) for part in deduplicate_development(table, roles)] != list(CIC_COUNTS.values()):
        raise ValueError("Canonical feature vectors are nonfinite or cross partitions")

    cic, common_table, *_ = load_cic(CIC_DIR)
    _, vapd, vapd_table, vapd_roles, vapd_labels, vapd_statuses = load_inputs(VAPD_INPUT)
    supplement = pick_supplement(
        [sample["sha256"] for sample in vapd], vapd_table, vapd_roles, vapd_labels,
        (vapd_statuses == STATUSES.index("bounded_complete"))
        & np.asarray([sample["gnn_message_passing_eligible"] for sample in vapd]),
        {sample["sha256"] for sample in cic}, common_table, SUPPLEMENT_PER_CLASS,
    )
    if membership_hash(vapd, supplement) != SUPPLEMENT_SHA256:
        raise ValueError("Supplement changed from paired augmentation experiment")
    pretrain_rows = [dict(vapd[i], tab_features=torch.from_numpy(vapd_table[i])) for i in supplement]
    validation = full["validation"], gnn["validation"]
    test_sha = membership_hash(full["test"], range(len(full["test"])))

    out = args.run_directory
    out.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path(__file__).with_name("run_cic_vapd_augmentation.py"),
             Path(__file__).with_name("run_vapd_retrospective.py"),
             Path(__file__).with_name("train_eval_pdf_transgraph_v2.py"),
             REPO / "src/malpdf/data/graph_export_v2_loader.py", REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "study": "vapd_graph_pretraining_cic_finetune",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "code_sha256": {str(path.relative_to(REPO)): digest(path) for path in paths},
        "cic_inputs": {str(path.relative_to(REPO)): checksum for path, checksum in CIC_INPUT_HASHES.items()},
        "vapd_numeric_bundle_sha256": VAPD_INPUT_SHA256, "supplement_sha256": SUPPLEMENT_SHA256,
        "supplement_counts": {"benign": SUPPLEMENT_PER_CLASS, "malicious": SUPPLEMENT_PER_CLASS},
        "supplement_policy": "Historical VAPD Train only, bounded_complete, graph-eligible, screened for exact CIC document and shared-table overlap.",
        "feature_names": canonical["tabular_feature_names"], "cic_partitions": CIC_COUNTS,
        "cic_train_gnn_n": len(gnn["train"]), "cic_test_sha256": test_sha,
        "transfer_scope": "Graph encoder weights only. Both arms seed other layers identically and fine-tune all layers on canonical CIC.",
        "validation_fallback": "Shared CIC-only Tabular+AST for two missing validation graphs",
        "seed": SEED, "pretrain_epochs": PRETRAIN_EPOCHS, "cic_epochs": CIC_EPOCHS,
        "batch_size": BATCH_SIZE, "threshold_policy": "Reference 0.50 and separate Validation-locked FPR <= 1% operating point.",
        "checkpoint_policy": "Maximum full CIC Validation F1 at 0.50, then maximum ROC-AUC",
        "environment": {"python": sys.version.split()[0], "torch": torch.__version__,
                        "device": torch.cuda.get_device_name(device), "cuda": torch.version.cuda},
    })
    set_deterministic_seed(SEED)
    vapd_graph = PDFTransGraph(node_in_dim=23, tabular_in_features=len(vapd_table[0]),
                               hidden_dim=128, ablation_mode="graph_only").to(device)
    print("Pretraining graph encoder with supplemental VAPD", flush=True)
    train(vapd_graph, pretrain_rows, PRETRAIN_EPOCHS, device)
    encoder = {name: value.detach().cpu().clone() for name, value in vapd_graph.graph_encoder.state_dict().items()}
    del vapd_graph, vapd, pretrain_rows

    set_deterministic_seed(SEED)
    print("Training shared CIC fallback", flush=True)
    fallback = PDFTransGraph(node_in_dim=23, tabular_in_features=dim, hidden_dim=128, ablation_mode="tab_ast").to(device)
    fallback_choice = train(fallback, full["train"], CIC_EPOCHS, device, validation=validation)

    models, locks = {}, {}
    for arm, weights in (("cic_only", None), ("vapd_graph_pretrain_then_cic", encoder)):
        model = initialize_full(dim, weights).to(device)
        print(f"Training {arm} on canonical CIC", flush=True)
        choice = train(model, gnn["train"], CIC_EPOCHS, device, validation=validation, fallback=fallback)
        result = evaluate_split_v2(model, *validation, device, fallback_tab_ast_model=fallback)
        point = operating_point(np.asarray(result["targets"]), np.asarray(result["probs"]), FPR_BUDGET)
        locks[arm] = {**choice, "operating_point": point}
        models[arm] = model
    write_json(out / "validation_lock.json", {"fallback": fallback_choice, "arms": locks})
    write_json(out / "test_evaluation_started.json", {
        "cic_test_sha256": test_sha, "validation_lock_sha256": digest(out / "validation_lock.json"),
    })
    statuses = np.array([sample["meta"]["status"] for sample in full["test"]])
    metrics, decisions = {}, {}
    for arm, model in models.items():
        result = evaluate_split_v2(model, full["test"], gnn["test"], device, fallback_tab_ast_model=fallback)
        scores, labels = np.asarray(result["probs"]), np.asarray(result["targets"])
        points = {"reference_0_50": 0.5, "validation_locked_1pct": locks[arm]["operating_point"]["threshold"]}
        decisions[arm] = {name: scores >= threshold for name, threshold in points.items()}
        metrics[arm] = {name: metrics_for_test(labels, scores, predicted, statuses)
                        for name, predicted in decisions[arm].items()}
    paired = {}
    for key in decisions["cic_only"]:
        old = decisions["cic_only"][key] == labels
        new = decisions["vapd_graph_pretrain_then_cic"][key] == labels
        paired[key] = {group: {"fixed": int((~old & new & mask).sum()),
                               "introduced": int((old & ~new & mask).sum())}
                       for group, mask in (("malicious", labels == 1), ("benign", labels == 0))}
    write_json(out / "metrics.json", {"schema_version": 1, "test_n": len(labels), "arms": metrics, "paired": paired})
    print(f"Completed {out}", flush=True)


if __name__ == "__main__":
    main()
