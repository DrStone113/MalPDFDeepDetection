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


def _features_to_device(features, device, non_blocking, channels_last):
    value = features.to(device, non_blocking=non_blocking)
    return value.contiguous(memory_format=torch.channels_last) if channels_last and value.ndim == 4 else value


def _mean_loss(model: nn.Module, loader: DataLoader, loss_function: nn.Module, device: torch.device,
               *, mixed_precision=False, non_blocking=False, channels_last=False,
               weighted_validation=False) -> float:
    model.eval()
    total_loss = torch.zeros((), device=device, dtype=torch.float64)
    total_mass = torch.zeros((), device=device, dtype=torch.float64)
    with torch.no_grad():
        for batch in loader:
            if len(batch) != (3 if weighted_validation else 2):
                raise ValueError("Validation batches differ from their declared weighting contract")
            features, labels = batch[:2]
            targets = labels.to(device, non_blocking=non_blocking)
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=mixed_precision):
                logits = model(_features_to_device(features, device, non_blocking, channels_last)).reshape(-1)
                if weighted_validation:
                    if not isinstance(loss_function, nn.BCEWithLogitsLoss):
                        raise ValueError("Weighted validation requires binary logit loss")
                    loss = nn.functional.binary_cross_entropy_with_logits(logits, targets,
                        weight=loss_function.weight, pos_weight=loss_function.pos_weight, reduction="none")
                else:
                    loss = loss_function(logits, targets)
            if weighted_validation:
                weights = batch[2].to(device, non_blocking=non_blocking).double()
                if weights.shape != targets.shape or not torch.isfinite(weights).all() or (weights <= 0).any():
                    raise ValueError("Validation weights must be aligned, positive and finite")
                total_loss += (loss.detach().double() * weights).sum()
                total_mass += weights.sum()
            else:
                total_loss += loss.detach().double() * len(labels)
                total_mass += len(labels)
    if total_mass.item() == 0:
        raise ValueError("A validation loader cannot be empty")
    result = float((total_loss / total_mass).item())
    if not np.isfinite(result):
        raise RuntimeError("Validation loss is non-finite")
    return result


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
    progress=None,
    mixed_precision: bool = False,
    non_blocking: bool = False,
    channels_last: bool = False,
    record_performance: bool = False,
    weighted_validation: bool = False,
) -> TrainingOutcome:
    """Fit using train data and choose the checkpoint solely by validation loss.

    There is intentionally no test-loader argument. Test data cannot affect
    epoch selection, optimization, or the early-stopping decision through this
    training API.
    """
    if max_epochs < 1 or patience < 1:
        raise ValueError("max_epochs and patience must be positive")
    if mixed_precision and device.type != "cuda":
        raise ValueError("FP16 mixed precision requires a CUDA device")
    model.to(device)
    loss_function = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scaler = torch.amp.GradScaler("cuda", enabled=mixed_precision)
    stopper = EarlyStopping(patience=patience, min_delta=min_delta)
    best_state: dict[str, torch.Tensor] | None = None
    history: list[dict[str, float | int]] = []
    training_started = perf_counter()
    last_progress = training_started
    for epoch in range(1, max_epochs + 1):
        epoch_started = perf_counter()
        model.train()
        train_total = torch.zeros((), device=device, dtype=torch.float64)
        train_rows = 0
        data_wait_seconds = 0.0
        skipped_steps = 0
        steps = 0
        waiting_since = perf_counter()
        for features, labels in train_loader:
            data_wait_seconds += perf_counter() - waiting_since
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=mixed_precision):
                logits = model(_features_to_device(features, device, non_blocking, channels_last)).reshape(-1)
                loss = loss_function(logits, labels.to(device, non_blocking=non_blocking))
            if not torch.isfinite(loss):
                raise RuntimeError("Training loss is non-finite")
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            finite_checks = [torch.isfinite(p.grad).all() for p in model.parameters() if p.grad is not None]
            finite_gradients = not finite_checks or bool(torch.stack(finite_checks).all())
            if not finite_gradients and not mixed_precision:
                raise RuntimeError("Training gradient is non-finite")


            skipped_steps += int(not finite_gradients)
            steps += 1
            scaler.step(optimizer)
            scaler.update()
            batch_rows = int(labels.shape[0])
            train_total += loss.detach().double() * batch_rows
            train_rows += batch_rows
            if progress is not None and perf_counter() - last_progress >= 20:
                progress({"event": "training_progress", "epoch": epoch, "rows": train_rows,
                          "train_loss": float(train_total.item()) / train_rows})
                last_progress = perf_counter()
            waiting_since = perf_counter()
        if train_rows == 0:
            raise ValueError("A training loader cannot be empty")
        if skipped_steps == steps:
            raise RuntimeError("AMP did not produce any finite optimizer update")
        validation_loss = _mean_loss(model, validation_loader, loss_function, device,
            mixed_precision=mixed_precision, non_blocking=non_blocking, channels_last=channels_last,
            weighted_validation=weighted_validation)
        epoch_seconds = perf_counter() - epoch_started
        entry = {"epoch": epoch, "train_loss": float(train_total.item()) / train_rows,
                 "validation_loss": validation_loss}
        if record_performance:
            entry.update(epoch_seconds=epoch_seconds, train_data_wait_seconds=data_wait_seconds,
                         train_rows_per_second=train_rows / epoch_seconds, amp_skipped_steps=skipped_steps)
        history.append(entry)
        if progress is not None:
            progress({"event": "epoch_completed", **history[-1]})
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
