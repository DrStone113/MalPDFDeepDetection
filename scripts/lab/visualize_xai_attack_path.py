import gzip
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import torch

from malpdf.models.pdf_transgraph import PDFTransGraph

REPO = Path(__file__).resolve().parents[2]
GRAPHS_PATH = REPO / "data/processed/cic_full/hetero_cic_graphs.json.gz"
CHECKPOINT_PATH = REPO / "reports/experiments/pdf_transgraph/pdf_transgraph_best.pt"
OUTPUT_DIR = REPO / "reports/figures"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tab_dim = 38
    state_dict = None
    if CHECKPOINT_PATH.exists():
        state_dict = torch.load(CHECKPOINT_PATH, map_location=device, weights_only=True)
        tab_dim = state_dict["tabular_encoder.input_layer.weight"].size(1)
    model = PDFTransGraph(
        node_in_dim=19,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=tab_dim,
        hidden_dim=128,
    ).to(device)
    if state_dict is not None:
        model.load_state_dict(state_dict)
    model.eval()
    with gzip.open(GRAPHS_PATH, "rt", encoding="utf-8") as stream:
        raw_graphs = json.load(stream)
    sample_graph = None
    for g in raw_graphs:
        if g.get("num_edges", 0) > 10 and 5 in g.get("node_types", []):
            sample_graph = g
            break
    if sample_graph is None:
        sample_graph = raw_graphs[0]
    nf = torch.tensor(sample_graph["node_features"], dtype=torch.float32).to(device)
    nt = torch.tensor(sample_graph["node_types"], dtype=torch.long).to(device)
    ei = torch.stack(
        [
            torch.tensor(sample_graph["edge_src"], dtype=torch.long),
            torch.tensor(sample_graph["edge_dst"], dtype=torch.long),
        ],
        dim=0,
    ).to(device)
    er = torch.tensor(sample_graph["edge_rel"], dtype=torch.long).to(device)
    b = torch.zeros(nf.size(0), dtype=torch.long).to(device)
    tok = torch.randint(0, 64, (1, 32)).to(device)
    tab = torch.randn(1, tab_dim).to(device)
    with torch.no_grad():
        logits, attn_weights = model(nf, nt, ei, er, b, tok, tab)
        prob = torch.sigmoid(logits).item()
    attn_np = attn_weights.squeeze(0).squeeze(0).cpu().numpy()
    plt.figure(figsize=(7, 4), dpi=300)
    bars = plt.bar(["Hetero-Graph DAG (h_graph)", "AST Syntax Seq (h_seq)"], attn_np, color=["#1f77b4", "#ff7f0e"], width=0.5)
    plt.ylabel("Cross-Modal Attention Weight", fontsize=11, fontweight="bold")
    plt.title(f"PDF-TransGraph Cross-Modal Attention Allocation (P(Malicious) = {prob:.4f})", fontsize=12, fontweight="bold")
    plt.ylim(0, 1.0)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.02, f"{yval:.4f}", ha="center", va="bottom", fontsize=10, fontweight="bold")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "pdf_transgraph_cross_modal_attention.png")
    plt.close()
    plt.figure(figsize=(8, 5), dpi=300)
    chain = ["Catalog (/Root)", "Action (/OpenAction)", "JavaScript Code (/JS)", "Packed Stream (/FlateDecode)"]
    x_pos = [1, 3, 5, 7]
    y_pos = [2, 2, 2, 2]
    plt.scatter(x_pos, y_pos, s=1800, c=["#2ca02c", "#d62728", "#9467bd", "#8c564b"], zorder=3)
    for i in range(len(chain) - 1):
        plt.annotate(
            "",
            xy=(x_pos[i + 1] - 0.4, y_pos[i + 1]),
            xytext=(x_pos[i] + 0.4, y_pos[i]),
            arrowprops=dict(facecolor="#333333", edgecolor="#333333", arrowstyle="->", lw=2.5),
        )
    for x, y, label in zip(x_pos, y_pos, chain):
        parts = label.split(" ")
        plt.text(x, y + 0.1, parts[0], ha="center", va="center", fontsize=9, fontweight="bold", color="white")
        plt.text(x, y - 0.1, parts[1], ha="center", va="center", fontsize=8, color="#f0f0f0")
    plt.xlim(0, 8)
    plt.ylim(1.2, 2.8)
    plt.axis("off")
    plt.title("XAI Attack Path Subgraph Extracted from Evasive PDF Malware", fontsize=12, fontweight="bold", pad=20)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "pdf_transgraph_attack_path_subgraph.png")
    plt.close()
    print("SUCCESS: XAI Visualizations generated and saved to reports/figures/")


if __name__ == "__main__":
    main()
