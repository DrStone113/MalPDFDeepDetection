"""Deterministic-capable PyTorch training utilities with validation-only control."""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from time import perf_counter
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader

from malpdf.reproducibility import set_random_seed


def set_deep_learning_seed(seed: int) -> dict[str, Any]:
    """Seed Python, NumPy, PyTorch CPU, and CUDA when available.

    Deterministic algorithms are requested in warning mode because GPU kernels
    can still have platform-specific constraints; provenance records this
    limitation rather than promising bit-identical GPU execution.
    """
    set_random_seed(seed)
    random.seed(seed)
    torch.manual_seed(seed)
    cuda_available = torch.cuda.is_available()
    if cuda_available:
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.use_deterministic_algorithms(True, warn_only=True)
    return {
        "seed": seed,
        "torch_deterministic_algorithms_requested": True,
        "torch_deterministic_warn_only": True,
        "cudnn_benchmark": False,
        "cudnn_deterministic": True,
        "cuda_seeded": cuda_available,
        "limitation": "GPU kernels and drivers can still prevent bit-identical results across environments.",
    }


def probabilities_from_logits(logits: torch.Tensor) -> np.ndarray:
    """Return finite malicious-class probabilities from one binary-logit tensor."""
    probabilities = torch.sigmoid(logits.detach()).reshape(-1).cpu().numpy().astype(float)
    if not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any():
        raise RuntimeError("Binary model produced an invalid probability")
    return probabilities


def binary_predictions_from_probabilities(probabilities: np.ndarray, threshold: float = 0.5) -> np.ndarray:
    """Apply the fixed, precommitted malicious-positive decision threshold."""
    values = np.asarray(probabilities, dtype=float)
    if not np.isfinite(values).all() or not 0.0 <= threshold <= 1.0:
        raise ValueError("Probabilities and threshold must be finite and within [0, 1]")
    return (values >= threshold).astype(int)


@dataclass
class EarlyStopping:
    """Validation-loss-only early stopping state; lower loss is better."""

    patience: int
    min_delta: float = 0.0
    best_loss: float = float("inf")
    best_epoch: int = 0
    stale_epochs: int = 0

    def update(self, epoch: int, validation_loss: float) -> bool:
        """Record a validation loss and return whether training should stop."""
        if not np.isfinite(validation_loss):
            raise RuntimeError("Validation loss is non-finite")
        if validation_loss < self.best_loss - self.min_delta:
            self.best_loss = float(validation_loss)
            self.best_epoch = int(epoch)
            self.stale_epochs = 0
            return False
        self.stale_epochs += 1
        return self.stale_epochs >= self.patience


@dataclass(frozen=True)
class TrainingOutcome:
    """Training-only outcome. It deliberately contains no test evaluation."""

    best_state_dict: dict[str, torch.Tensor]
    best_epoch: int
    best_validation_loss: float
    training_seconds: float
    history: list[dict[str, float | int]]


def _mean_loss(model: nn.Module, loader: DataLoader, loss_function: nn.Module, device: torch.device) -> float:
    model.eval()
    total_loss = 0.0
    total_rows = 0
    with torch.no_grad():
        for features, labels in loader:
            logits = model(features.to(device)).reshape(-1)
            loss = loss_function(logits, labels.to(device))
            batch_rows = int(labels.shape[0])
            total_loss += float(loss.item()) * batch_rows
            total_rows += batch_rows
    if total_rows == 0:
        raise ValueError("A validation loader cannot be empty")
    return total_loss / total_rows


def train_with_validation(
    model: nn.Module,
    train_loader: DataLoader,
    validation_loader: DataLoader,
    *,
    device: torch.device,
    learning_rate: float,
    weight_decay: float,
    max_epochs: int,
    patience: int,
    min_delta: float,
) -> TrainingOutcome:
    """Fit using train data and choose the checkpoint solely by validation loss.

    There is intentionally no test-loader argument. Test data cannot affect
    epoch selection, optimization, or the early-stopping decision through this
    training API.
    """
    if max_epochs < 1 or patience < 1:
        raise ValueError("max_epochs and patience must be positive")
    model.to(device)
    loss_function = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    stopper = EarlyStopping(patience=patience, min_delta=min_delta)
    best_state: dict[str, torch.Tensor] | None = None
    history: list[dict[str, float | int]] = []
    training_started = perf_counter()
    for epoch in range(1, max_epochs + 1):
        model.train()
        train_total = 0.0
        train_rows = 0
        for features, labels in train_loader:
            optimizer.zero_grad(set_to_none=True)
            logits = model(features.to(device)).reshape(-1)
            loss = loss_function(logits, labels.to(device))
            loss.backward()
            optimizer.step()
            batch_rows = int(labels.shape[0])
            train_total += float(loss.item()) * batch_rows
            train_rows += batch_rows
        if train_rows == 0:
            raise ValueError("A training loader cannot be empty")
        validation_loss = _mean_loss(model, validation_loader, loss_function, device)
        history.append({"epoch": epoch, "train_loss": train_total / train_rows, "validation_loss": validation_loss})
        previous_best = stopper.best_epoch
        should_stop = stopper.update(epoch, validation_loss)
        if stopper.best_epoch != previous_best:
            best_state = copy.deepcopy(model.state_dict())
        if should_stop:
            break
    if best_state is None:
        raise RuntimeError("No finite validation checkpoint was selected")
    return TrainingOutcome(
        best_state_dict=best_state,
        best_epoch=stopper.best_epoch,
        best_validation_loss=stopper.best_loss,
        training_seconds=perf_counter() - training_started,
        history=history,
    )


def evaluate_loaded_binary_model(
    model: nn.Module,
    loader: DataLoader,
    *,
    device: torch.device,
) -> tuple[np.ndarray, np.ndarray]:
    """Run one held-out inference pass, returning labels and malicious scores."""
    model.eval()
    labels: list[np.ndarray] = []
    probabilities: list[np.ndarray] = []
    with torch.no_grad():
        for features, batch_labels in loader:
            logits = model(features.to(device))
            probabilities.append(probabilities_from_logits(logits))
            labels.append(batch_labels.detach().cpu().numpy().astype(int))
    if not labels:
        raise ValueError("A held-out evaluation loader cannot be empty")
    return np.concatenate(labels), np.concatenate(probabilities)
