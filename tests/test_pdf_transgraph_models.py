import torch
from malpdf.models.ast_transformer import ASTSequenceTransformer
from malpdf.models.cross_attention_fusion import CrossModalAttentionFusion
from malpdf.models.hetero_hgt import HeteroGraphTransformer
from malpdf.models.pdf_transgraph import FocalLoss, PDFTransGraph
from malpdf.models.tabular_resnet import TabularResNet


def test_hetero_graph_transformer_forward():
    model = HeteroGraphTransformer(node_in_dim=19, hidden_dim=64, num_node_types=9, num_relations=8)
    node_feat = torch.randn(10, 19)
    node_types = torch.randint(0, 9, (10,))
    edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)
    edge_rel = torch.tensor([0, 1, 2, 3], dtype=torch.long)
    batch = torch.tensor([0, 0, 0, 0, 0, 1, 1, 1, 1, 1], dtype=torch.long)
    out = model(node_feat, node_types, edge_index, edge_rel, batch)
    assert out.shape == (2, 64)


def test_ast_sequence_transformer_forward():
    model = ASTSequenceTransformer(vocab_size=64, hidden_dim=64, max_len=32)
    tokens = torch.randint(0, 64, (4, 32))
    out = model(tokens)
    assert out.shape == (4, 64)


def test_tabular_resnet_forward():
    model = TabularResNet(in_features=35, hidden_dim=64, num_blocks=2)
    x = torch.randn(4, 35)
    out = model(x)
    assert out.shape == (4, 64)


def test_cross_modal_fusion_forward():
    fusion = CrossModalAttentionFusion(hidden_dim=64, num_heads=2)
    h_graph = torch.randn(4, 64)
    h_seq = torch.randn(4, 64)
    h_tab = torch.randn(4, 64)
    fused, weights = fusion(h_graph, h_seq, h_tab)
    assert fused.shape == (4, 128)
    assert weights.shape == (4, 1, 2)


def test_pdf_transgraph_end_to_end_forward():
    model = PDFTransGraph(
        node_in_dim=19,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=35,
        hidden_dim=64,
    )
    node_feat = torch.randn(12, 19)
    node_types = torch.randint(0, 9, (12,))
    edge_index = torch.tensor([[0, 1, 2, 4], [1, 2, 3, 5]], dtype=torch.long)
    edge_rel = torch.tensor([0, 1, 2, 3], dtype=torch.long)
    batch = torch.tensor([0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2], dtype=torch.long)
    ast_tokens = torch.randint(0, 64, (3, 32))
    tabular_features = torch.randn(3, 35)
    logits, attn = model(node_feat, node_types, edge_index, edge_rel, batch, ast_tokens, tabular_features)
    assert logits.shape == (3,)
    assert attn.shape == (3, 1, 2)


def test_focal_loss_computation():
    criterion = FocalLoss(alpha=0.6, gamma=2.0)
    logits = torch.tensor([2.0, -1.0, 0.5])
    targets = torch.tensor([1.0, 0.0, 1.0])
    loss = criterion(logits, targets)
    assert loss.dim() == 0
    assert not torch.isnan(loss)
    assert loss.item() > 0.0
