from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import numpy as np
import torch

from malpdf.data.graph_export_v2_loader import collate_multimodal_batch_v2
from malpdf.models.pdf_transgraph import PDFTransGraph
from scripts.lab.export_vapd_retrospective_inputs import digest
from scripts.lab.run_cic_vapd_graph_transfer import SEED, infer_batch, set_deterministic_seed, train, write_json
from scripts.lab.train_pooled_bulk import GRAPH_EPOCHS, REPO, TABULAR_FEATURES, load_pool, prepare_graph_rows


POOL_SHA256 = "24a202d8307ec4f52798d09e3a2cc6ad60ce6c774175a058ea7342c394e14bf2"
DISPUTES_SHA256 = "9aad62c3e662b94dbf3b75a9fd9c615a134b4a56ecab34a5fd8a46d81397eba4"


def reviewed_training_rows(samples, disputes):
    by_sha = {sample["sha256"]: sample for sample in samples}
    rejected = set()
    for dispute in disputes:
        sha = dispute["sha256"]
        sample = by_sha.get(sha)
        if (sha in rejected or sample is None
                or type(dispute["pooled_label"]) is not int or type(dispute["cic_label"]) is not int
                or {dispute["pooled_label"], dispute["cic_label"]} != {0, 1}
                or (sample["label"], sample["source"]) != (dispute["pooled_label"], dispute["pooled_source"])):
            raise ValueError("label_dispute_does_not_match_training_record")
        rejected.add(sha)
    return [sample for sample in samples if sample["sha256"] not in rejected]


def main():
    parser = argparse.ArgumentParser(description="Measure pooled TransGraph training with disputed labels excluded")
    parser.add_argument("--run-directory", required=True, type=Path)
    parser.add_argument("--checkpoint-directory", required=True, type=Path)
    args = parser.parse_args()
    pool = REPO / "data/processed/pooled_bulk/pooled.jsonl.gz"
    dispute_file = REPO / "data/processed/pooled_bulk/independent_audit/label_conflicts.json"
    if digest(pool) != POOL_SHA256 or digest(dispute_file) != DISPUTES_SHA256:
        raise ValueError("label_review_source_changed")
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA required for the paired training comparison")
    torch.set_num_threads(4)
    header, labeled = load_pool(pool)
    disputes = json.loads(dispute_file.read_text(encoding="utf-8"))
    if len(disputes) != 3732:
        raise ValueError("label_dispute_count_changed")
    reviewed = reviewed_training_rows(labeled, disputes)
    samples = [row for row in reviewed if np.isfinite(row["tabular"]).any()]
    table = np.stack([row["tabular"] for row in samples])
    if np.isinf(table).any() or np.isnan(table).all(axis=0).any():
        raise ValueError("unusable_reviewed_features")
    mean = np.nanmean(table, axis=0, dtype=np.float64).astype(np.float32)
    scale = np.nanstd(table, axis=0, dtype=np.float64).astype(np.float32)
    scale[scale == 0] = 1
    graphs = prepare_graph_rows(samples, mean, scale)
    out, weights = args.run_directory, args.checkpoint_directory
    out.mkdir(parents=True, exist_ok=False)
    weights.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), REPO / "scripts/lab/train_pooled_bulk.py",
             REPO / "scripts/lab/run_cic_vapd_graph_transfer.py", REPO / "src/malpdf/models/pdf_transgraph.py"]
    write_json(out / "locked_methodology.json", {
        "schema_version": 1, "study": "pooled_transgraph_disputed_label_exclusion",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "code_sha256": {str(path.relative_to(REPO)): digest(path) for path in paths},
        "input_sha256": POOL_SHA256, "label_disputes_sha256": DISPUTES_SHA256,
        "pool": header, "label_disputes_excluded_from_loss": len(disputes),
        "excluded_source_counts": Counter(row["pooled_source"] for row in disputes),
        "label_source_counts": Counter(row["source"] for row in samples),
        "table_fit_n": len(samples), "graph_fit_n": len(graphs),
        "graph_label_counts": Counter(str(row["label"]) for row in graphs),
        "graph_model": "PDFTransGraph tab_graph: 25 static columns and measured 23D graph",
        "graph_epochs": GRAPH_EPOCHS, "seed": SEED, "threshold": 0.5,
        "scaler_policy": "Observed mean and standard deviation fitted on retained labeled rows",
        "evaluation": "Previously observed frozen diagnostics for development only",
        "device": torch.cuda.get_device_name(),
    })
    print(f"Retained {len(samples)} labeled rows and {len(graphs)} graphs after excluding {len(disputes)} disputed labels", flush=True)
    del labeled, reviewed, samples, table
    set_deterministic_seed(SEED)
    device = torch.device("cuda")
    model = PDFTransGraph(node_in_dim=23, tabular_in_features=len(TABULAR_FEATURES), ablation_mode="tab_graph").to(device)
    train(model, graphs, GRAPH_EPOCHS, device)
    model.eval()
    checkpoint = weights / "transgraph_pooled.npz"
    state = {name: value.detach().cpu() for name, value in model.state_dict().items()}
    np.savez_compressed(checkpoint, **{name: value.numpy() for name, value in state.items()})
    write_json(weights / "tabular_scaler.json", {"feature_names": TABULAR_FEATURES, "mean": mean.tolist(), "scale": scale.tolist()})
    with np.load(checkpoint, allow_pickle=False) as archive:
        recovered = {name: torch.from_numpy(archive[name]) for name in archive.files}
    torch.testing.assert_close(recovered, state, rtol=0, atol=0)
    reloaded = PDFTransGraph(node_in_dim=23, tabular_in_features=len(TABULAR_FEATURES), ablation_mode="tab_graph").to(device)
    reloaded.load_state_dict(recovered, strict=True)
    reloaded.eval()
    batch = collate_multimodal_batch_v2(graphs[:32])
    with torch.inference_mode():
        expected = infer_batch(model, batch, device)
        observed = infer_batch(reloaded, batch, device)
    if not torch.isfinite(observed).all():
        raise ValueError("nonfinite_reviewed_model_output")
    torch.testing.assert_close(observed, expected, rtol=1e-6, atol=1e-6)
    write_json(out / "metrics.json", {
        "schema_version": 1, "checkpoint_directory": str(weights),
        "checkpoint_sha256": {path.name: digest(path) for path in (checkpoint, weights / "tabular_scaler.json")},
        "graph_fit_n": len(graphs), "transgraph_epochs": GRAPH_EPOCHS,
        "checkpoint_readback": {"transgraph": len(observed)}, "independent_evaluation": False,
    })
    print(f"Completed {out}", flush=True)


if __name__ == "__main__":
    main()
