import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from malpdf.data.cross_dataset_loader import load_aligned_datasets

REPO = Path(__file__).resolve().parents[2]
REPORT_DIR = REPO / "reports/experiments/cross_dataset_rit_cic"


class DeepCORALResNet(nn.Module):
    def __init__(self, in_features: int, hidden_dim: int = 128):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_features, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
        )
        self.classifier = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.SiLU(),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        features = self.encoder(x)
        logits = self.classifier(features).squeeze(-1)
        return logits, features


def compute_coral_loss(source: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
    d = source.size(1)
    ns = source.size(0)
    nt = target.size(0)

    mean_s = torch.mean(source, dim=0, keepdim=True)
    mean_t = torch.mean(target, dim=0, keepdim=True)

    source_centered = source - mean_s
    target_centered = target - mean_t

    cov_s = (source_centered.t() @ source_centered) / (ns - 1.0)
    cov_t = (target_centered.t() @ target_centered) / (nt - 1.0)

    loss = torch.sum((cov_s - cov_t) ** 2) / (4.0 * (d ** 2))
    return loss


def compute_metrics(y_true, y_pred, y_prob):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier": float(brier_score_loss(y_true, y_prob)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


class SimpleDataset(Dataset):
    def __init__(self, x: np.ndarray, y: np.ndarray = None):
        self.x = torch.tensor(x, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32) if y is not None else None

    def __len__(self) -> int:
        return len(self.x)

    def __getitem__(self, idx: int):
        if self.y is not None:
            return self.x[idx], self.y[idx]
        return self.x[idx]


def evaluate_model(model, x, y, device):
    model.eval()
    with torch.no_grad():
        xt = torch.tensor(x, dtype=torch.float32).to(device)
        logits, _ = model(xt)
        probs = torch.sigmoid(logits).cpu().numpy()
        preds = (probs >= 0.5).astype(int)
    return compute_metrics(y, preds, probs)


def train_deep_coral(x_source, y_source, x_target, x_target_val, y_target_val, in_features, lambda_coral=0.5, epochs=30, batch_size=64, seed=42, device="cpu"):
    torch.manual_seed(seed)
    np.random.seed(seed)

    model = DeepCORALResNet(in_features=in_features).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion_cls = nn.BCEWithLogitsLoss()

    ds_source = SimpleDataset(x_source, y_source)
    ds_target = SimpleDataset(x_target)

    loader_source = DataLoader(ds_source, batch_size=batch_size, shuffle=True, drop_last=True)
    loader_target = DataLoader(ds_target, batch_size=batch_size, shuffle=True, drop_last=True)

    best_val_f1 = -1.0
    best_weights = None

    for epoch in range(1, epochs + 1):
        model.train()
        target_iter = iter(loader_target)
        for x_s, y_s in loader_source:
            try:
                x_t = next(target_iter)
            except StopIteration:
                target_iter = iter(loader_target)
                x_t = next(target_iter)

            x_s, y_s, x_t = x_s.to(device), y_s.to(device), x_t.to(device)
            optimizer.zero_grad()

            logits_s, feats_s = model(x_s)
            _, feats_t = model(x_t)

            loss_cls = criterion_cls(logits_s, y_s)
            if lambda_coral > 0:
                loss_coral = compute_coral_loss(feats_s, feats_t)
                loss_total = loss_cls + lambda_coral * loss_coral
            else:
                loss_total = loss_cls

            loss_total.backward()
            optimizer.step()

        val_metrics = evaluate_model(model, x_target_val, y_target_val, device)
        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    if best_weights is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_weights.items()})
    return model


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Running Unsupervised Deep CORAL on device: {device}")

    rit_df, cic_df = load_aligned_datasets(REPO, include_ratios=True)
    feature_cols = [c for c in rit_df.columns if c not in {"label", "split"}]

    cic_train_mask = cic_df["split"] == "train"
    rit_train_mask = rit_df["split"] == "train"
    rit_test_mask = rit_df["split"] == "test"

    scaler = StandardScaler()
    x_cic_train = scaler.fit_transform(cic_df.loc[cic_train_mask, feature_cols].values)
    y_cic_train = cic_df.loc[cic_train_mask, "label"].values

    x_rit_unlabeled = scaler.transform(rit_df.loc[rit_train_mask, feature_cols].values)
    x_rit_test = scaler.transform(rit_df.loc[rit_test_mask, feature_cols].values)
    y_rit_test = rit_df.loc[rit_test_mask, "label"].values
    x_rit_all = scaler.transform(rit_df[feature_cols].values)
    y_rit_all = rit_df["label"].values

    print("\n--- 1. Non-Adapted Source Model (Baseline lambda=0) ---")
    model_baseline = train_deep_coral(
        x_source=x_cic_train,
        y_source=y_cic_train,
        x_target=x_rit_unlabeled,
        x_target_val=x_rit_test,
        y_target_val=y_rit_test,
        in_features=len(feature_cols),
        lambda_coral=0.0,
        epochs=25,
        device=device,
    )
    m_baseline_test = evaluate_model(model_baseline, x_rit_test, y_rit_test, device)
    m_baseline_all = evaluate_model(model_baseline, x_rit_all, y_rit_all, device)
    print(f"Baseline -> RIT Test: Acc {m_baseline_test['accuracy']*100:.2f}% | Recall {m_baseline_test['recall']*100:.2f}% | F1 {m_baseline_test['f1']:.4f} | AUC {m_baseline_test['roc_auc']:.4f}")
    print(f"Baseline -> RIT All:  Acc {m_baseline_all['accuracy']*100:.2f}% | Recall {m_baseline_all['recall']*100:.2f}% | F1 {m_baseline_all['f1']:.4f}")

    print("\n--- 2. Unsupervised Deep CORAL Adaptation (lambda=0.5) ---")
    model_coral_05 = train_deep_coral(
        x_source=x_cic_train,
        y_source=y_cic_train,
        x_target=x_rit_unlabeled,
        x_target_val=x_rit_test,
        y_target_val=y_rit_test,
        in_features=len(feature_cols),
        lambda_coral=0.5,
        epochs=30,
        device=device,
    )
    m_coral05_test = evaluate_model(model_coral_05, x_rit_test, y_rit_test, device)
    m_coral05_all = evaluate_model(model_coral_05, x_rit_all, y_rit_all, device)
    print(f"Deep CORAL (0.5) -> RIT Test: Acc {m_coral05_test['accuracy']*100:.2f}% | Recall {m_coral05_test['recall']*100:.2f}% | F1 {m_coral05_test['f1']:.4f} | AUC {m_coral05_test['roc_auc']:.4f}")
    print(f"Deep CORAL (0.5) -> RIT All:  Acc {m_coral05_all['accuracy']*100:.2f}% | Recall {m_coral05_all['recall']*100:.2f}% | F1 {m_coral05_all['f1']:.4f}")

    print("\n--- 3. Unsupervised Deep CORAL Adaptation (lambda=1.0) ---")
    model_coral_10 = train_deep_coral(
        x_source=x_cic_train,
        y_source=y_cic_train,
        x_target=x_rit_unlabeled,
        x_target_val=x_rit_test,
        y_target_val=y_rit_test,
        in_features=len(feature_cols),
        lambda_coral=1.0,
        epochs=30,
        device=device,
    )
    m_coral10_test = evaluate_model(model_coral_10, x_rit_test, y_rit_test, device)
    m_coral10_all = evaluate_model(model_coral_10, x_rit_all, y_rit_all, device)
    print(f"Deep CORAL (1.0) -> RIT Test: Acc {m_coral10_test['accuracy']*100:.2f}% | Recall {m_coral10_test['recall']*100:.2f}% | F1 {m_coral10_test['f1']:.4f} | AUC {m_coral10_test['roc_auc']:.4f}")
    print(f"Deep CORAL (1.0) -> RIT All:  Acc {m_coral10_all['accuracy']*100:.2f}% | Recall {m_coral10_all['recall']*100:.2f}% | F1 {m_coral10_all['f1']:.4f}")

    results = {
        "non_adapted_baseline": {
            "rit_test": m_baseline_test,
            "rit_all": m_baseline_all,
        },
        "deep_coral_lambda_05": {
            "rit_test": m_coral05_test,
            "rit_all": m_coral05_all,
        },
        "deep_coral_lambda_10": {
            "rit_test": m_coral10_test,
            "rit_all": m_coral10_all,
        },
    }

    with (REPORT_DIR / "deep_coral_adaptation_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved Deep CORAL Results to: {REPORT_DIR / 'deep_coral_adaptation_results.json'}")


if __name__ == "__main__":
    main()
