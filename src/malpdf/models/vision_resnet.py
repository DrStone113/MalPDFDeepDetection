"""Single-channel ResNet-18 for 256 x 256 byte Markov matrices."""

from __future__ import annotations

import torch
from torch import nn
from torchvision.models import resnet18


class VisionResNet18(nn.Module):
    """Scratch-initialized binary classifier; forward returns one stable logit.

    No pretrained weights are fetched. Use ``predict_proba`` or sigmoid on
    logits for P(Label=1 malicious); train with BCEWithLogitsLoss.
    """

    def __init__(self) -> None:
        super().__init__()
        self.backbone = resnet18(weights=None)
        self.backbone.conv1 = nn.Conv2d(1, 64, kernel_size=7, stride=2, padding=3, bias=False)
        nn.init.kaiming_normal_(self.backbone.conv1.weight, mode="fan_out", nonlinearity="relu")
        self.backbone.fc = nn.Linear(self.backbone.fc.in_features, 1)

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        if inputs.ndim != 4 or tuple(inputs.shape[1:]) != (1, 256, 256) or inputs.shape[0] == 0:
            raise ValueError("VisionResNet18 requires (B, 1, 256, 256) input")
        if inputs.dtype != torch.float32 or not torch.isfinite(inputs).all():
            raise ValueError("Vision input must be finite float32")
        return self.backbone(inputs)

    def predict_proba(self, inputs: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self(inputs))
