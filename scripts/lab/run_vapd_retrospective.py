from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re
import subprocess
import sys
from time import perf_counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import DataLoader
from xgboost import XGBClassifier

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from malpdf.data.graph_export_v2_loader import collate_multimodal_batch_v2, collate_non_graph_batch_v2
from malpdf.evaluation.binary import evaluate_binary_predictions
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph
from scripts.lab.export_vapd_retrospective_inputs import (
    EXPECTED_COUNTS, INPUT_HASHES, SPLITS, STATUSES, TABULAR_FEATURES, digest,
)

SEED = 42
FPR_BUDGET = 0.01
EPOCHS = 10
BATCH_SIZE = 64
TREE_PARAMS = {
    "random_forest": {"n_estimators": 300, "min_samples_leaf": 2, "n_jobs": 6, "random_state": SEED},
    "xgboost": {"n_estimators": 300, "max_depth": 6, "learning_rate": 0.05, "tree_method": "hist",
                "eval_metric": "logloss", "n_jobs": 6, "random_state": SEED},
}
NEURAL_MODES = ("tab_only", "tab_graph")
TEST_IDENTITY_SHA256 = "97be7876f2ccff650e69f0d21302e6ed6500e676f6ccdd152f5051963139ec36"


def deduplicate_development(values, roles):
    train, validation, test = (np.flatnonzero(roles == index) for index in range(3))
    normalized = np.ascontiguousarray(values.copy())
    normalized[normalized == 0] = 0
    keys = [row.tobytes() for row in normalized]
    held_out = {keys[i] for i in test}
    validation_keys = {keys[i] for i in validation}
    return (
        np.array([i for i in train if keys[i] not in held_out and keys[i] not in validation_keys], dtype=int),
        np.array([i for i in validation if keys[i] not in held_out], dtype=int),
        test,
    )


def operating_point(labels, scores, budget):
    if len(set(labels)) != 2 or not np.isfinite(scores).all():
        raise ValueError("Need both classes and finite scores at operating point")
    fpr, recall, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    eligible = np.flatnonzero(fpr <= budget)
    best = int(eligible[np.argmax(recall[eligible])])
    threshold = float(thresholds[best])
    if not np.isfinite(threshold):
        threshold = 2.0
    return {"threshold": threshold, "fpr": float(fpr[best]), "recall": float(recall[best])}


def load_inputs(path):
    samples, values, roles, labels, statuses = [], [], [], [], []
    seen = set()
    tokens = torch.zeros(32, dtype=torch.long)
    with gzip.open(path, "rt", encoding="ascii") as handle:
        header = json.loads(handle.readline(100000))
        if (
            header["schema_version"] != 1 or tuple(header["features"]) != TABULAR_FEATURES
            or header["counts"] != EXPECTED_COUNTS or tuple(header["splits"]) != SPLITS
            or tuple(header["statuses"]) != STATUSES
            or any(header["inputs"].get(key) != value for key, value in INPUT_HASHES.items())
        ):
            raise ValueError("unexpected numeric bundle header")
        for line in handle:
            if len(line) > 1000000 or len(samples) >= sum(EXPECTED_COUNTS.values()):
                raise ValueError("numeric bundle bounds exceeded")
            identity, role, label, status, tabular, nodes, types, src, dst, relations = json.loads(line)
            if (
                identity in seen or not re.fullmatch(r"[0-9a-f]{64}", identity)
                or role not in range(3) or label not in (0, 1) or status not in range(len(STATUSES))
                or len(tabular) != len(TABULAR_FEATURES)
            ):
                raise ValueError("invalid numeric identity or row contract")
            seen.add(identity)
            values.append(tabular)
            roles.append(role)
            labels.append(label)
            statuses.append(status)
            samples.append({
                "sha256": identity, "index": len(samples), "label": label,
                "node_features": torch.tensor(nodes, dtype=torch.float32),
                "node_types": torch.tensor(types, dtype=torch.long),
                "edge_src": torch.tensor(src, dtype=torch.long),
                "edge_dst": torch.tensor(dst, dtype=torch.long),
                "edge_rel": torch.tensor(relations, dtype=torch.long),
                "ast_tokens": tokens, "gnn_message_passing_eligible": True,
            })
    if dict(Counter(SPLITS[i] for i in roles)) != EXPECTED_COUNTS:
        raise ValueError("numeric bundle role counts changed")
    from hashlib import sha256
    test_id_bytes = "".join(identity + "\n" for identity in sorted(
        sample["sha256"] for sample, role in zip(samples, roles, strict=True) if role == 2
    )).encode("ascii")
    if sha256(test_id_bytes).hexdigest() != TEST_IDENTITY_SHA256:
        raise ValueError("historical Test membership changed")
    table = np.asarray(values, dtype=np.float32)
    if not np.isfinite(table).all():
        raise ValueError("nonfinite table values")
    return header, samples, table, np.array(roles), np.array(labels), np.array(statuses)


def batches(samples, indices, mode, *, shuffle=False):
    collate = collate_multimodal_batch_v2 if mode == "tab_graph" else collate_non_graph_batch_v2
    return DataLoader([samples[i] for i in indices], batch_size=BATCH_SIZE, shuffle=shuffle,
                      generator=torch.Generator().manual_seed(SEED), collate_fn=collate)


def infer_batch(model, batch, device):
    arguments = ("node_features", "node_types", "edge_index", "edge_rel", "batch", "ast_tokens", "tab_features")
    tensors = [batch[name].to(device) if batch[name] is not None else None for name in arguments]
    return model(*tensors)[0]


@torch.inference_mode()
def neural_scores(model, loader, device):
    model.eval()
    return np.concatenate([infer_batch(model, batch, device).sigmoid().cpu().numpy() for batch in loader])


def fit_neural(mode, samples, train, validation, labels, device):
    torch.manual_seed(SEED)
    model = PDFTransGraph(node_in_dim=23, tabular_in_features=len(TABULAR_FEATURES),
                          hidden_dim=128, ablation_mode=mode).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.0001)
    schedule = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)
    criterion = FocalLoss(alpha=0.6, gamma=2.0)
    train_loader = batches(samples, train, mode, shuffle=True)
    val_loader = batches(samples, validation, mode)
    best, history = None, []
    for epoch in range(1, EPOCHS + 1):
        model.train()
        for batch in train_loader:
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(infer_batch(model, batch, device), batch["labels"].to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
            optimizer.step()
        schedule.step()
        scores = neural_scores(model, val_loader, device)
        point = operating_point(labels, scores, FPR_BUDGET)
        auc = float(roc_auc_score(labels, scores))
        key = (point["recall"], -point["fpr"], auc)
        history.append({"epoch": epoch, "roc_auc": auc, **point})
        print(f"{mode} epoch {epoch}/{EPOCHS}: validation recall={point['recall']:.4f}, FPR={point['fpr']:.4f}", flush=True)
        if best is None or key > best[0]:
            best = key, epoch, point, {name: value.detach().cpu().clone() for name, value in model.state_dict().items()}
    _, epoch, point, weights = best
    model.load_state_dict(weights)
    return model, {"best_epoch": epoch, "operating_point": point, "validation_history": history}


def summarize_test(labels, scores, statuses, threshold):
    predicted = scores >= threshold
    metrics = evaluate_binary_predictions(labels, predicted, scores)
    tn, fp = metrics["confusion_matrix"][0]
    metrics["fpr"] = fp / (tn + fp)
    equal_fpr = operating_point(labels, scores, FPR_BUDGET)
    metrics["descriptive_test_roc_at_1pct_fpr"] = {key: equal_fpr[key] for key in ("fpr", "recall")}
    strata = {}
    for index, name in enumerate(STATUSES):
        mask = statuses == index
        subset = labels[mask]
        positives = subset == 1
        negatives = subset == 0
        decisions = predicted[mask]
        strata[name] = {
            "n_malicious": int(positives.sum()), "n_benign": int(negatives.sum()),
            "tp": int((decisions & positives).sum()), "fp": int((decisions & negatives).sum()),
        }
    metrics["by_extraction_status"] = strata
    return metrics


def write_json(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Run the fixed retrospective VAPD D1 comparison")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    args = parser.parse_args()
    device = torch.device("cuda")
    if not torch.cuda.is_available():
        raise RuntimeError("A CUDA device is required for this locked comparison")
    torch.set_num_threads(4)

    header, samples, table, roles, labels, statuses = load_inputs(args.input)
    train, validation, test = deduplicate_development(table, roles)
    scaler = StandardScaler().fit(table[train])
    scaled = scaler.transform(table).astype(np.float32)
    if any(not np.array_equal(a, b) for a, b in zip(
        (train, validation, test), deduplicate_development(scaled, roles), strict=True
    )):
        raise ValueError("Scaling changed exact cross-role numeric collisions")
    used = dict(zip(SPLITS, (train, validation, test), strict=True))
    counts = {
        split: {"benign": int((labels[index] == 0).sum()), "malicious": int((labels[index] == 1).sum())}
        for split, index in used.items()
    }
    if any(min(role.values()) == 0 for role in counts.values()):
        raise ValueError("Each comparison partition needs both classes")

    out = args.run_directory
    out.mkdir(parents=True, exist_ok=False)
    timestamp = datetime.now(timezone.utc).isoformat()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    sources = [Path(__file__), Path(__file__).with_name("export_vapd_retrospective_inputs.py"),
               REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "started_utc": timestamp, "study": "vapd_d1_retrospective_graph_comparison",
        "git_commit": commit, "code_sha256": {str(p.relative_to(REPO)): digest(p) for p in sources},
        "numeric_bundle_sha256": digest(args.input), "upstream": header, "test_identity_sha256": TEST_IDENTITY_SHA256,
        "seed": SEED, "input_counts": EXPECTED_COUNTS, "used_counts": counts,
        "overlap_policy": "Keep every historical Test row; remove earlier development rows with identical float32 tables.",
        "preprocessing": "No imputation; table scaler fit only on retained Train. Tree models receive unscaled table.",
        "method": "Retrospective comparison. AST branch excluded to measure the addition of the 23D graph.",
        "feature_policy": "Raw lexical and byte statistics; omit parser flags, StartXref and unavailable suffix entropy.",
        "threshold_policy": "Maximize recall at validation FPR <= 1%; prefer less FPR on ties.",
        "test_policy": "One score pass per fitted model after all Validation choices are sealed. Test ROC point is descriptive.",
        "tree_parameters": TREE_PARAMS,
        "neural_parameters": {"modes": NEURAL_MODES, "epochs": EPOCHS, "batch_size": BATCH_SIZE, "hidden_dim": 128,
                              "optimizer": "AdamW", "lr": 0.001, "weight_decay": 0.0001, "clip_grad_norm": 2.0,
                              "loss": {"type": "focal", "alpha": 0.6, "gamma": 2.0}},
        "environment": {"torch": torch.__version__, "cuda": torch.version.cuda,
                        "device": torch.cuda.get_device_name(device), "python": sys.version.split()[0]},
    })
    for sample, values in zip(samples, scaled, strict=True):
        sample["tab_features"] = torch.from_numpy(values)
    print(f"Comparison partitions: {counts}", flush=True)

    trees = {"random_forest": RandomForestClassifier(**TREE_PARAMS["random_forest"]),
             "xgboost": XGBClassifier(**TREE_PARAMS["xgboost"])}
    fitted, locks = {}, {}
    for name, tree in trees.items():
        started = perf_counter()
        tree.fit(table[train], labels[train])
        scores = tree.predict_proba(table[validation])[:, 1]
        locks[name] = {"operating_point": operating_point(labels[validation], scores, FPR_BUDGET),
                       "fit_and_validation_seconds": perf_counter() - started}
        print(f"{name}: validation choices ready", flush=True)
    for mode in NEURAL_MODES:
        started = perf_counter()
        fitted[mode], locks[mode] = fit_neural(mode, samples, train, validation, labels[validation], device)
        locks[mode]["fit_and_validation_seconds"] = perf_counter() - started
    write_json(out / "validation_lock.json", locks)
    write_json(out / "test_evaluation_started.json", {
        "test_identity_sha256": TEST_IDENTITY_SHA256, "models": list(locks),
        "validation_lock_sha256": digest(out / "validation_lock.json"),
    })
    metrics, decisions = {}, {}
    for name, model in (trees | fitted).items():
        started = perf_counter()
        if name in trees:
            scores = model.predict_proba(table[test])[:, 1]
        else:
            scores = neural_scores(model, batches(samples, test, name), device)
        inference_seconds = perf_counter() - started
        threshold = locks[name]["operating_point"]["threshold"]
        metrics[name] = summarize_test(labels[test], scores, statuses[test], threshold)
        metrics[name]["inference_seconds"] = inference_seconds
        decisions[name] = scores >= threshold
    truth = labels[test] == 1
    old = decisions["tab_only"] == truth
    new = decisions["tab_graph"] == truth
    paired = {name: {"fixed": int((~old & new & mask).sum()), "introduced": int((old & ~new & mask).sum())}
              for name, mask in (("malicious", truth), ("benign", ~truth))}
    write_json(out / "metrics.json", {
        "schema_version": 1, "test_n": len(test), "models": metrics,
        "paired_graph_vs_tab_at_validation_thresholds": paired,
    })
    print(f"Completed {out}", flush=True)


if __name__ == "__main__":
    main()
