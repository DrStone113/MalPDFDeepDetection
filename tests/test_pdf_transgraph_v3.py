"""Unit tests for PDFTransGraphV3 bidirectional graph, masked fusion, SSL, and NPZ parity."""

from __future__ import annotations

import torch

from malpdf.models.pdf_transgraph_v3 import (
    PDFTransGraphV3,
    TransGraphV3Config,
    extract_graph_summary_features,
    load_v3_weights_npz,
    save_v3_weights_npz,
)


def _sample_graph_batch():
    node_x = torch.randn(6, 23, dtype=torch.float32)
    node_type = torch.tensor([0, 1, 2, 7, 3, 8], dtype=torch.long)
    # Graph 0: nodes 0..3 with edges; Graph 1: empty (0 nodes); Graph 2: nodes 4..5 with 0 edges.
    edge_index = torch.tensor([[0, 1, 2], [1, 2, 3]], dtype=torch.long)
    edge_rel = torch.tensor([0, 3, 5], dtype=torch.long)
    graph_batch = torch.tensor([0, 0, 0, 0, 2, 2], dtype=torch.long)
    return node_x, node_type, edge_index, edge_rel, graph_batch


def test_empty_and_isolated_graphs_are_finite_and_masked() -> None:
    torch.manual_seed(7)
    cfg = TransGraphV3Config(tab_dim=32, use_missing_mask=False, modality_drop_prob=0.0)
    model = PDFTransGraphV3(cfg).eval()
    node_x, node_type, edge_index, edge_rel, graph_batch = _sample_graph_batch()
    tab_x = torch.randn(3, 32)
    ast_x = torch.zeros(3, 26)
    ast_missing = torch.ones(3, 26)

    summary = extract_graph_summary_features(node_type, edge_index, graph_batch, batch_size=3)
    assert summary.shape == (3, 12)
    assert torch.equal(summary[1], torch.zeros(12))
    assert float(summary[2, 11]) > 0.0

    with torch.no_grad():
        out = model(
            tab_x=tab_x,
            tab_missing=None,
            ast_x=ast_x,
            ast_missing=ast_missing,
            node_x=node_x,
            node_type=node_type,
            edge_index=edge_index,
            edge_rel=edge_rel,
            graph_batch=graph_batch,
        )
    assert torch.isfinite(out["logits"]).all()
    assert torch.isfinite(out["weights"]).all()
    assert torch.allclose(out["weights"][1, 1], torch.tensor(0.0), atol=1e-7)
    assert torch.allclose(out["weights"][:, 2], torch.zeros(3), atol=1e-7)
    assert torch.allclose(out["weights"].sum(dim=-1), torch.ones(3), atol=1e-6)


def test_masked_fusion_blocks_gradients_into_inactive_branches() -> None:
    torch.manual_seed(11)
    cfg = TransGraphV3Config(tab_dim=16, modality_drop_prob=0.0)
    model = PDFTransGraphV3(cfg).train()
    node_x, node_type, edge_index, edge_rel, graph_batch = _sample_graph_batch()
    tab_x = torch.randn(3, 16)
    tab_miss = torch.zeros(3, 16)
    ast_x = torch.randn(3, 26)
    ast_miss = torch.ones(3, 26)

    out = model(
        tab_x=tab_x,
        tab_missing=tab_miss,
        ast_x=ast_x,
        ast_missing=ast_miss,
        node_x=node_x,
        node_type=node_type,
        edge_index=edge_index,
        edge_rel=edge_rel,
        graph_batch=graph_batch,
    )
    assert float(out["weights"][:, 2].detach().abs().max()) == 0.0
    out["logits"].sum().backward()

    for p in model.ast_encoder.parameters():
        assert p.grad is None or float(p.grad.abs().max()) == 0.0
    assert any(p.grad is not None and float(p.grad.abs().max()) > 0.0 for p in model.tab_encoder.parameters())

    model.zero_grad()
    out_no_graph = model(
        tab_x=tab_x,
        tab_missing=tab_miss,
        ast_x=ast_x,
        ast_missing=ast_miss,
        node_x=None,
        node_type=None,
        edge_index=None,
        edge_rel=None,
        graph_batch=None,
    )
    assert float(out_no_graph["weights"][:, 1].detach().abs().max()) == 0.0
    out_no_graph["logits"].sum().backward()
    for p in model.graph_encoder.parameters():
        assert p.grad is None or float(p.grad.abs().max()) == 0.0


def test_bidirectional_message_passing_flows_both_directions() -> None:
    torch.manual_seed(19)
    cfg = TransGraphV3Config(tab_dim=8, dropout=0.0)
    encoder = PDFTransGraphV3(cfg).graph_encoder.eval()

    x_base = torch.tensor([[1.0] + [0.0] * 22, [0.0, 2.0] + [0.0] * 21], dtype=torch.float32)
    node_type = torch.tensor([0, 7], dtype=torch.long)
    edge_index = torch.tensor([[0], [1]], dtype=torch.long)
    edge_rel = torch.tensor([2], dtype=torch.long)

    x_pert_dst = x_base.clone()
    x_pert_dst[1, 3] = 5.0
    x_pert_src = x_base.clone()
    x_pert_src[0, 4] = -4.0

    with torch.no_grad():
        h_base = encoder.encode_nodes(x_base, node_type, edge_index, edge_rel)
        h_dst_changed = encoder.encode_nodes(x_pert_dst, node_type, edge_index, edge_rel)
        h_src_changed = encoder.encode_nodes(x_pert_src, node_type, edge_index, edge_rel)

    assert float((h_base[0] - h_dst_changed[0]).abs().max()) > 1e-4
    assert float((h_base[1] - h_src_changed[1]).abs().max()) > 1e-4


def test_regime_b_ignores_missingness_flags_exactly() -> None:
    torch.manual_seed(23)
    tab_x = torch.randn(4, 32)
    miss_a = torch.zeros(4, 32)
    miss_b = torch.ones(4, 32)

    cfg_b = TransGraphV3Config(tab_dim=32, use_missing_mask=False, enable_graph=False, enable_ast=False, modality_drop_prob=0.0)
    model_b = PDFTransGraphV3(cfg_b).eval()
    with torch.no_grad():
        out_a = model_b(tab_x=tab_x, tab_missing=miss_a)["logits"]
        out_b = model_b(tab_x=tab_x, tab_missing=miss_b)["logits"]
    assert torch.equal(out_a, out_b)

    cfg_a = TransGraphV3Config(tab_dim=32, use_missing_mask=True, enable_graph=False, enable_ast=False, modality_drop_prob=0.0)
    model_a = PDFTransGraphV3(cfg_a).eval()
    with torch.no_grad():
        out_ma = model_a(tab_x=tab_x, tab_missing=miss_a)["logits"]
        out_mb = model_a(tab_x=tab_x, tab_missing=miss_b)["logits"]
    assert float((out_ma - out_mb).abs().max()) > 1e-5


def test_ssl_loss_finite_and_handles_single_present_graph() -> None:
    torch.manual_seed(31)
    cfg = TransGraphV3Config(tab_dim=16, use_missing_mask=False)
    model = PDFTransGraphV3(cfg).train()
    node_x, node_type, edge_index, edge_rel, graph_batch = _sample_graph_batch()
    tab_x = torch.randn(3, 16)
    tab_miss = torch.zeros(3, 16, dtype=torch.bool)
    tab_miss[:, 0] = True

    losses = model.ssl_loss(
        tab_x=tab_x,
        tab_missing=tab_miss,
        node_x=node_x,
        node_type=node_type,
        edge_index=edge_index,
        edge_rel=edge_rel,
        graph_batch=graph_batch,
    )
    assert all(torch.isfinite(v) for v in losses.values())
    assert float(losses["total"].detach()) > 0.0
    losses["total"].backward()

    # Single present graph must yield clip=0 without NaN.
    model.zero_grad()
    one_losses = model.ssl_loss(
        tab_x=tab_x,
        tab_missing=tab_miss,
        node_x=node_x[:4],
        node_type=node_type[:4],
        edge_index=edge_index,
        edge_rel=edge_rel,
        graph_batch=torch.zeros(4, dtype=torch.long),
    )
    assert float(one_losses["clip"]) == 0.0
    assert torch.isfinite(one_losses["total"])


def test_npz_save_and_load_exact_parity(tmp_path) -> None:
    torch.manual_seed(42)
    cfg = TransGraphV3Config(tab_dim=16, use_missing_mask=False)
    model = PDFTransGraphV3(cfg).eval()
    weights_path = tmp_path / "weights.npz"
    save_v3_weights_npz(model, weights_path)

    reloaded = PDFTransGraphV3(cfg).eval()
    load_v3_weights_npz(reloaded, weights_path)
    for k, tensor in model.state_dict().items():
        assert torch.equal(tensor, reloaded.state_dict()[k])

    node_x, node_type, edge_index, edge_rel, graph_batch = _sample_graph_batch()
    tab_x = torch.randn(3, 16)
    with torch.no_grad():
        logits_a = model(tab_x=tab_x, node_x=node_x, node_type=node_type, edge_index=edge_index, edge_rel=edge_rel, graph_batch=graph_batch)["logits"]
        logits_b = reloaded(tab_x=tab_x, node_x=node_x, node_type=node_type, edge_index=edge_index, edge_rel=edge_rel, graph_batch=graph_batch)["logits"]
    assert torch.allclose(logits_a, logits_b, atol=1e-6)
