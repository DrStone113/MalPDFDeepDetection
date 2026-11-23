from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import subprocess

import numpy as np
import torch
from xgboost import XGBClassifier

from malpdf.data.graph_export_v2_loader import collate_multimodal_batch_v2
from malpdf.models.pdf_transgraph import PDFTransGraph
from scripts.lab.export_pooled_bulk_inputs import CLASSES, COUNTS, GRAPH_COUNT, TABULAR_FEATURES
from scripts.lab.export_vapd_retrospective_inputs import GRAPH_KEYS, digest
from scripts.lab.run_cic_vapd_graph_transfer import SEED, infer_batch, set_deterministic_seed, train, write_json


REPO = Path(__file__).resolve().parents[2]
GRAPH_EPOCHS = 5
TREE_PARAMETERS = dict(n_estimators=200, max_depth=5, learning_rate=0.05, tree_method="hist",
                       random_state=SEED, n_jobs=4, eval_metric="logloss")


def load_pool(path):
    samples, seen, counts = [], set(), Counter()
    graph_count = 0
    with gzip.open(path, "rt", encoding="ascii") as stream:
        header = json.loads(stream.readline(8192))
        if (header["schema_version"] != 1 or tuple(header["features"]) != TABULAR_FEATURES
                or header["counts"] != COUNTS or header["graphs"] != GRAPH_COUNT):
            raise ValueError("unexpected_pool_contract")
        for line in stream:
            sha, label, source, status, fields, graph = json.loads(line)
            if sha in seen or len(fields) != len(TABULAR_FEATURES) or len(seen) >= sum(COUNTS.values()):
                raise ValueError("unexpected_pool_row")
            seen.add(sha)
            counts[CLASSES[label]] += 1
            graph_count += graph is not None
            if label is not None:
                samples.append(dict(sha256=sha, label=label, source=source, status=status,
                                    tabular=np.asarray(fields, dtype=np.float32), graph=graph))
    if counts != COUNTS or graph_count != GRAPH_COUNT:
        raise ValueError("pool_counts_changed")
    return header, samples


def prepare_graph_rows(samples, mean, scale):
    tokens = torch.zeros(32, dtype=torch.long)
    rows = []
    for sample in samples:
        graph = sample["graph"]
        if graph is None:
            continue
        raw = sample["tabular"]
        row = dict(sha256=sample["sha256"], label=sample["label"], index=len(rows), ast_tokens=tokens,
                   tab_features=torch.from_numpy(np.where(np.isnan(raw), 0.0, (raw - mean) / scale)),
                   gnn_message_passing_eligible=True)
        row.update({key: torch.tensor(values, dtype=torch.float32 if key == "node_features" else torch.long)
                    for key, values in zip(GRAPH_KEYS, graph, strict=True)})
        rows.append(row)
    return rows


def fit_report(labels, probabilities):
    if probabilities.shape != labels.shape or not np.isfinite(probabilities).all():
        raise ValueError("invalid_training_scores")
    positive = labels == 1
    flagged = probabilities >= 0.5
    return {"n": len(labels), "positive_labels": int(positive.sum()), "negative_labels": int((~positive).sum()),
            "reference_0_50": {"tp": int((flagged & positive).sum()), "fp": int((flagged & ~positive).sum()),
                               "tn": int((~flagged & ~positive).sum()), "fn": int((~flagged & positive).sum())}}


def main():
    parser = argparse.ArgumentParser(description="Train research models on a single pooled PDF corpus")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--run-directory", required=True, type=Path)
    parser.add_argument("--checkpoint-directory", required=True, type=Path)
    args = parser.parse_args()
    if digest(args.input) != args.sha256:
        raise ValueError("pool_transfer_hash_mismatch")
    if not torch.cuda.is_available():
        raise RuntimeError("pooled graph training requires CUDA")
    torch.set_num_threads(4)
    device = torch.device("cuda")

    header, labeled = load_pool(args.input)
    samples = [row for row in labeled if np.isfinite(row["tabular"]).any()]
    table = np.stack([row["tabular"] for row in samples])
    if np.isinf(table).any() or np.isnan(table).all(axis=0).any():
        raise ValueError("invalid_pooled_tabular_inputs")
    labels = np.asarray([row["label"] for row in samples], dtype=np.int64)
    mean = np.nanmean(table, axis=0, dtype=np.float64).astype(np.float32)
    scale = np.nanstd(table, axis=0, dtype=np.float64).astype(np.float32)
    scale[scale == 0] = 1
    graphs = prepare_graph_rows(samples, mean, scale)
    source_counts = Counter(row["source"] for row in samples)
    out, weights = args.run_directory, args.checkpoint_directory
    out.mkdir(parents=True, exist_ok=False)
    weights.mkdir(parents=True, exist_ok=False)
    code = [Path(__file__), Path(__file__).with_name("export_pooled_bulk_inputs.py"),
            Path(__file__).with_name("run_cic_vapd_graph_transfer.py"), REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "study": "pooled_supervised_bulk_training",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "code_sha256": {str(path.relative_to(REPO)): digest(path) for path in code},
        "input_sha256": args.sha256, "pool": header, "split_policy": "No partition. Every usable labeled row is training data.",
        "unlabeled_policy": "Stored with null labels. Omitted from supervised loss.",
        "label_source_counts": source_counts, "table_fit_n": len(samples), "graph_fit_n": len(graphs),
        "graph_model": "PDFTransGraph tab_graph: 25 observed static columns plus 23D graph, AST disabled",
        "missing_input_policy": "Native missing values in XGBoost; centered missing values after pooled observed-mean scaling in TransGraph.",
        "source_and_status_as_predictors": False, "seed": SEED, "graph_epochs": GRAPH_EPOCHS,
        "xgboost_parameters": TREE_PARAMETERS,
        "device": torch.cuda.get_device_name(device), "evaluation": "Training fit and checkpoint readback only",
    })
    print(f"Fitting tabular model on {len(samples)} labeled samples", flush=True)
    tree = XGBClassifier(**TREE_PARAMETERS).fit(table, labels)
    tree_path = weights / "xgboost_pooled.json"
    tree.save_model(tree_path)
    tree_readback = XGBClassifier()
    tree_readback.load_model(tree_path)
    tree_scores = tree.predict_proba(table)[:, 1]
    np.testing.assert_array_equal(tree_readback.predict_proba(table[:64])[:, 1], tree_scores[:64])

    del labeled, samples
    set_deterministic_seed(SEED)
    model = PDFTransGraph(node_in_dim=23, tabular_in_features=len(TABULAR_FEATURES), ablation_mode="tab_graph").to(device)
    print(f"Fitting TransGraph on {len(graphs)} labeled graphs", flush=True)
    train(model, graphs, GRAPH_EPOCHS, device)
    model.eval()
    graph_path = weights / "transgraph_pooled.npz"
    trained_state = {name: value.detach().cpu() for name, value in model.state_dict().items()}
    np.savez_compressed(graph_path, **{name: value.numpy() for name, value in trained_state.items()})
    write_json(weights / "tabular_scaler.json", {"feature_names": TABULAR_FEATURES, "mean": mean.tolist(), "scale": scale.tolist()})
    batch = collate_multimodal_batch_v2(graphs[:32])
    with torch.inference_mode():
        expected = infer_batch(model, batch, device).cpu()
        reloaded = PDFTransGraph(node_in_dim=23, tabular_in_features=len(TABULAR_FEATURES), ablation_mode="tab_graph").to(device)
        with np.load(graph_path, allow_pickle=False) as state:
            recovered_state = {name: torch.from_numpy(state[name]) for name in state.files}
        torch.testing.assert_close(recovered_state, trained_state, rtol=0, atol=0)
        reloaded.load_state_dict(recovered_state, strict=True)
        reloaded.eval()
        observed = infer_batch(reloaded, batch, device).cpu()
        if not torch.isfinite(observed).all():
            raise ValueError("nonfinite_graph_readback")
        torch.testing.assert_close(observed, expected, rtol=1e-6, atol=1e-6)
    write_json(out / "metrics.json", {
        "schema_version": 1, "pool_rows": sum(COUNTS.values()), "labeled_rows": len(labels),
        "unlabeled_rows": COUNTS["unlabeled"], "xgboost_training_fit_only": fit_report(labels, tree_scores),
        "transgraph_fit_counts": Counter(CLASSES[row["label"]] for row in graphs), "transgraph_fit_n": len(graphs),
        "transgraph_epochs": GRAPH_EPOCHS, "checkpoint_readback": {"xgboost": 64, "transgraph": len(observed)},
        "independent_evaluation": False, "checkpoint_directory": str(weights),
        "checkpoint_sha256": {path.name: digest(path) for path in (tree_path, graph_path, weights / "tabular_scaler.json")},
    })
    print(f"Completed {out}", flush=True)


if __name__ == "__main__":
    main()
