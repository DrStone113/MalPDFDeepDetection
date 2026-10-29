import torch
import torch.nn as nn
import torch.nn.functional as F

from malpdf.models.pdf_transgraph import FocalLoss


class AdversarialRobustLoss(nn.Module):
    def __init__(self, alpha: float = 0.5, beta: float = 1.0, gamma: float = 2.0):
        super().__init__()
        self.alpha = alpha
        self.beta = beta
        self.focal_loss = FocalLoss(alpha=0.6, gamma=gamma)

    def forward(
        self,
        logits_clean: torch.Tensor,
        logits_adv: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        loss_clean = self.focal_loss(logits_clean, targets)
        loss_adv = self.focal_loss(logits_adv, targets)
        prob_clean = torch.sigmoid(logits_clean)
        prob_adv = torch.sigmoid(logits_adv)
        consistency_loss = F.mse_loss(prob_clean, prob_adv)
        total_loss = (self.alpha * loss_clean) + ((1.0 - self.alpha) * loss_adv) + (self.beta * consistency_loss)
        return total_loss
