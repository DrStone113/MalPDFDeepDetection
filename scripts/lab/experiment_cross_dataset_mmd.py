import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import torch

from malpdf.data.cross_dataset_loader import load_aligned_datasets

REPO = Path(__file__).resolve().parents[2]
REPORT_DIR = REPO / "reports/experiments/cross_dataset_rit_cic"
FIGURES_DIR = REPO / "reports/figures"


def compute_rbf_mmd(x: np.ndarray, y: np.ndarray, gamma: float = 1.0) -> float:
    tx = torch.tensor(x, dtype=torch.float32)
    ty = torch.tensor(y, dtype=torch.float32)
    n = tx.size(0)
    m = ty.size(0)
    xx_dist = torch.cdist(tx, tx, p=2) ** 2
    yy_dist = torch.cdist(ty, ty, p=2) ** 2
    xy_dist = torch.cdist(tx, ty, p=2) ** 2
    k_xx = torch.exp(-gamma * xx_dist)
    k_yy = torch.exp(-gamma * yy_dist)
    k_xy = torch.exp(-gamma * xy_dist)
    mmd_sq = k_xx.mean() + k_yy.mean() - 2.0 * k_xy.mean()
    return float(torch.clamp(mmd_sq, min=0.0).sqrt().item())


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    rit_df, cic_df = load_aligned_datasets(REPO, include_ratios=True)

    feature_cols = [c for c in rit_df.columns if c not in {"label", "split"}]

    scaler = StandardScaler()
    rit_scaled = scaler.fit_transform(rit_df[feature_cols].values)
    cic_scaled = scaler.transform(cic_df[feature_cols].values)

    np.random.seed(42)
    sample_size = 1400
    rit_sub_idx = np.random.choice(len(rit_scaled), sample_size, replace=False)
    cic_sub_idx = np.random.choice(len(cic_scaled), sample_size, replace=False)

    x_rit = rit_scaled[rit_sub_idx]
    x_cic = cic_scaled[cic_sub_idx]

    overall_mmd = compute_rbf_mmd(x_rit, x_cic, gamma=0.1)

    categories = {
        "Structure & Size": [c for c in ["pdfsize", "metadata_size", "stream", "obj", "density_stream_ratio", "density_obj_stream_ratio"] if c in feature_cols],
        "Script & Execution": [c for c in ["JS", "JavaScript", "OpenAction", "AA", "Launch", "EmbeddedFile"] if c in feature_cols],
        "Xref & Traversal": [c for c in ["startxref", "xref", "xref_length", "trailer"] if c in feature_cols],
        "Form & Encodings": [c for c in ["Acroform", "XFA", "JBIG2Decode", "RichMedia", "Colors"] if c in feature_cols],
    }

    category_mmds = {}
    for cat_name, cols in categories.items():
        col_indices = [feature_cols.index(c) for c in cols]
        cat_mmd = compute_rbf_mmd(x_rit[:, col_indices], x_cic[:, col_indices], gamma=0.2)
        category_mmds[cat_name] = round(cat_mmd, 4)

    def calc_ratio(df, col, condition):
        m = df[df["label"] == 1]
        b = df[df["label"] == 0]
        m_pct = (condition(m[col])).mean() * 100.0
        b_pct = (condition(b[col])).mean() * 100.0
        return {"malware_pct": round(m_pct, 2), "benign_pct": round(b_pct, 2)}

    inversion_stats = {
        "JS_presence": {
            "RIT_Conventional": calc_ratio(rit_df, "JS", lambda s: s > 0),
            "CIC_Evasive": calc_ratio(cic_df, "JS", lambda s: s > 0),
        },
        "OpenAction_presence": {
            "RIT_Conventional": calc_ratio(rit_df, "OpenAction", lambda s: s > 0),
            "CIC_Evasive": calc_ratio(cic_df, "OpenAction", lambda s: s > 0),
        },
        "StartXref_mean": {
            "RIT_Conventional": {
                "malware_mean": round(float(rit_df[rit_df["label"] == 1]["startxref"].mean()), 2),
                "benign_mean": round(float(rit_df[rit_df["label"] == 0]["startxref"].mean()), 2),
            },
            "CIC_Evasive": {
                "malware_mean": round(float(cic_df[cic_df["label"] == 1]["startxref"].mean()), 2),
                "benign_mean": round(float(cic_df[cic_df["label"] == 0]["startxref"].mean()), 2),
            },
        },
        "Density_Stream_Ratio_mean": {
            "RIT_Conventional": {
                "malware_mean": round(float(rit_df[rit_df["label"] == 1]["density_stream_ratio"].mean()), 4),
                "benign_mean": round(float(rit_df[rit_df["label"] == 0]["density_stream_ratio"].mean()), 4),
            },
            "CIC_Evasive": {
                "malware_mean": round(float(cic_df[cic_df["label"] == 1]["density_stream_ratio"].mean()), 4),
                "benign_mean": round(float(cic_df[cic_df["label"] == 0]["density_stream_ratio"].mean()), 4),
            },
        },
    }

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    plt.subplots_adjust(hspace=0.35, wspace=0.25)

    ax1 = axes[0, 0]
    rit_js_m = rit_df[rit_df["label"] == 1]["JS"].clip(upper=10)
    rit_js_b = rit_df[rit_df["label"] == 0]["JS"].clip(upper=10)
    ax1.hist([rit_js_b, rit_js_m], bins=11, range=(-0.5, 10.5), density=True, label=["Benign (Wild)", "Malware (Wild)"], color=["#2ca02c", "#d62728"], alpha=0.7)
    ax1.set_title("RIT-PDFMal-2026: JS Keyword Distribution (Conventional)", fontsize=11, fontweight="bold")
    ax1.set_xlabel("JS Count")
    ax1.set_ylabel("Probability Density")
    ax1.legend()
    ax1.grid(True, linestyle="--", alpha=0.5)

    ax2 = axes[0, 1]
    cic_js_m = cic_df[cic_df["label"] == 1]["JS"].clip(upper=10)
    cic_js_b = cic_df[cic_df["label"] == 0]["JS"].clip(upper=10)
    ax2.hist([cic_js_b, cic_js_m], bins=11, range=(-0.5, 10.5), density=True, label=["Benign (Enterprise)", "Malware (Evasive)"], color=["#1f77b4", "#ff7f0e"], alpha=0.7)
    ax2.set_title("CIC-Evasive-PDFMal: JS Keyword Distribution (INVERTED)", fontsize=11, fontweight="bold")
    ax2.set_xlabel("JS Count")
    ax2.set_ylabel("Probability Density")
    ax2.legend()
    ax2.grid(True, linestyle="--", alpha=0.5)

    ax3 = axes[1, 0]
    rit_oa_m = (rit_df[rit_df["label"] == 1]["OpenAction"] > 0).astype(int)
    rit_oa_b = (rit_df[rit_df["label"] == 0]["OpenAction"] > 0).astype(int)
    ax3.bar(["Benign (0)", "Malware (1)"], [rit_oa_b.mean() * 100, rit_oa_m.mean() * 100], color=["#2ca02c", "#d62728"], alpha=0.8, width=0.5)
    ax3.set_title("RIT-PDFMal-2026: OpenAction Presence %", fontsize=11, fontweight="bold")
    ax3.set_ylabel("% Samples with OpenAction")
    ax3.set_ylim(0, 100)
    for i, v in enumerate([rit_oa_b.mean() * 100, rit_oa_m.mean() * 100]):
        ax3.text(i, v + 2, f"{v:.1f}%", ha="center", fontweight="bold")
    ax3.grid(True, linestyle="--", alpha=0.5)

    ax4 = axes[1, 1]
    cic_oa_m = (cic_df[cic_df["label"] == 1]["OpenAction"] > 0).astype(int)
    cic_oa_b = (cic_df[cic_df["label"] == 0]["OpenAction"] > 0).astype(int)
    ax4.bar(["Benign (0)", "Malware (1)"], [cic_oa_b.mean() * 100, cic_oa_m.mean() * 100], color=["#1f77b4", "#ff7f0e"], alpha=0.8, width=0.5)
    ax4.set_title("CIC-Evasive-PDFMal: OpenAction Presence % (INVERTED)", fontsize=11, fontweight="bold")
    ax4.set_ylabel("% Samples with OpenAction")
    ax4.set_ylim(0, 100)
    for i, v in enumerate([cic_oa_b.mean() * 100, cic_oa_m.mean() * 100]):
        ax4.text(i, v + 2, f"{v:.1f}%", ha="center", fontweight="bold")
    ax4.grid(True, linestyle="--", alpha=0.5)

    fig_path = FIGURES_DIR / "kde_feature_inversion_rit_vs_cic.png"
    plt.savefig(fig_path, dpi=300, bbox_inches="tight")
    plt.close()

    output_data = {
        "overall_mmd_distance": round(overall_mmd, 4),
        "category_mmd_distances": category_mmds,
        "feature_inversion_statistics": inversion_stats,
        "figure_exported": str(fig_path),
    }

    with (REPORT_DIR / "mmd_and_inversion_analysis.json").open("w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print("Experiment 2.1 (MMD & KDE Inversion) Completed Successfully!")
    print(f"Overall MMD: {overall_mmd:.4f}")
    for k, v in category_mmds.items():
        print(f"  - {k} MMD: {v:.4f}")
    print(f"Figure saved to: {fig_path}")


if __name__ == "__main__":
    main()
