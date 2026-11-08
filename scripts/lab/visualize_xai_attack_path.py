from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import torch

from malpdf.models.pdf_transgraph import PDFTransGraph
from train_pdf_transgraph import collate_multimodal_batch, load_dataset

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description="Visualize attention using the measured features of one existing cache sample")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.checkpoint.is_file():
        raise FileNotFoundError("Trained checkpoint required; random weights are forbidden")
    samples, tab_dim = load_dataset()
    selected = [sample for partition in samples.values() for sample in partition if sample["sha256"] == args.sha256]
    if len(selected) != 1:
        raise ValueError("Expected exactly one measured cache sample with the requested SHA256")
    state = torch.load(args.checkpoint, map_location="cpu", weights_only=True)
    model = PDFTransGraph(node_in_dim=19, num_node_types=9, num_relations=8, ast_vocab_size=64, tabular_in_features=tab_dim, hidden_dim=128)
    model.load_state_dict(state)
    model.eval()
    batch = collate_multimodal_batch(selected)
    with torch.no_grad():
        logits, attention = model(batch["node_features"], batch["node_types"], batch["edge_index"], batch["edge_rel"], batch["batch"], batch["ast_tokens"], batch["tab_features"])
    weights = attention.reshape(-1).numpy()
    fig, axis = plt.subplots(figsize=(7, 4), dpi=200)
    axis.bar(["Graph branch", "AST branch"], weights)
    axis.set_ylabel("Measured cross-modal attention")
    axis.set_title(f"Cached sample {args.sha256[:12]} - model score {torch.sigmoid(logits).item():.4f}")
    axis.set_ylim(0, 1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(args.output)
    plt.close(fig)
    print(f"Saved measured cache attention: {args.output}")


if __name__ == "__main__":
    main()
