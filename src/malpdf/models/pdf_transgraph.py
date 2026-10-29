import torch
import torch.nn as nn
import torch.nn.functional as F

from malpdf.models.ast_transformer import ASTSequenceTransformer
from malpdf.models.cross_attention_fusion import CrossModalAttentionFusion
from malpdf.models.hetero_hgt import HeteroGraphTransformer
from malpdf.models.tabular_resnet import TabularResNet


class FocalLoss(nn.Module):
    def __init__(self, alpha: float = 0.6, gamma: float = 2.0, reduction: str = "mean"):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        bce_loss = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
        probs = torch.sigmoid(logits)
        p_t = targets * probs + (1 - targets) * (1 - probs)
        alpha_t = targets * self.alpha + (1 - targets) * (1 - self.alpha)
        focal_weight = alpha_t * ((1.0 - p_t) ** self.gamma)
        loss = focal_weight * bce_loss
        if self.reduction == "mean":
            return loss.mean()
        if self.reduction == "sum":
            return loss.sum()
        return loss


class PDFTransGraph(nn.Module):
    def __init__(
        self,
        node_in_dim: int = 19,
        num_node_types: int = 9,
        num_relations: int = 8,
        ast_vocab_size: int = 64,
        tabular_in_features: int = 35,
        hidden_dim: int = 128,
        ablation_mode: str = "full",
    ):
        super().__init__()
        self.ablation_mode = ablation_mode
        self.hidden_dim = hidden_dim
        self.graph_encoder = HeteroGraphTransformer(
            node_in_dim=node_in_dim,
            hidden_dim=hidden_dim,
            num_node_types=num_node_types,
            num_relations=num_relations,
        )
        self.ast_encoder = ASTSequenceTransformer(
            vocab_size=ast_vocab_size,
            hidden_dim=hidden_dim,
        )
        self.tabular_encoder = TabularResNet(
            in_features=tabular_in_features,
            hidden_dim=hidden_dim,
        )
        self.fusion = CrossModalAttentionFusion(hidden_dim=hidden_dim)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1),
        )
        self.single_branch_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.LayerNorm(hidden_dim // 2),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(
        self,
        node_features: torch.Tensor,
        node_types: torch.Tensor,
        edge_index: torch.Tensor,
        edge_rel: torch.Tensor,
        batch: torch.Tensor,
        ast_tokens: torch.Tensor,
        tabular_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        if self.ablation_mode == "tab_only":
            h_tab = self.tabular_encoder(tabular_features)
            logits = self.single_branch_head(h_tab).squeeze(-1)
            dummy_attn = torch.zeros(h_tab.size(0), 1, 2, device=h_tab.device)
            return logits, dummy_attn
        if self.ablation_mode == "graph_only":
            h_graph = self.graph_encoder(node_features, node_types, edge_index, edge_rel, batch)
            logits = self.single_branch_head(h_graph).squeeze(-1)
            dummy_attn = torch.zeros(h_graph.size(0), 1, 2, device=h_graph.device)
            return logits, dummy_attn
        if self.ablation_mode == "ast_only":
            h_seq = self.ast_encoder(ast_tokens)
            logits = self.single_branch_head(h_seq).squeeze(-1)
            dummy_attn = torch.zeros(h_seq.size(0), 1, 2, device=h_seq.device)
            return logits, dummy_attn
        h_graph = self.graph_encoder(node_features, node_types, edge_index, edge_rel, batch)
        h_seq = self.ast_encoder(ast_tokens)
        h_tab = self.tabular_encoder(tabular_features)
        if self.ablation_mode == "tab_ast":
            h_graph = torch.zeros_like(h_graph)
        elif self.ablation_mode == "tab_graph":
            h_seq = torch.zeros_like(h_seq)
        z_final, attn_weights = self.fusion(h_graph, h_seq, h_tab)
        logits = self.classifier(z_final).squeeze(-1)
        return logits, attn_weights
