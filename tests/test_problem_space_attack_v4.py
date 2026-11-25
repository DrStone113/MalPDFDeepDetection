import numpy as np
import pytest
from scripts.lab.train_eval_transgraph_v4 import ABLATIONS, EMPTY_IR, IDX, calibrate_thresholds, format_view
import torch

from malpdf.evaluation.problem_space_attack import evaluate_budgeted_attack_curve, graft_benign_subtree_pair
from malpdf.models.pdf_transgraph_v4 import (
    SINK_NODE_TYPES,
    PDFTransGraphV4,
    TransGraphV4Config,
    build_padded_graph_tensors,
    compute_dag_structural_encodings,
    extract_observable_action_ir_np,
    extract_single_graph_action_ir_np,
)


def graph():
    types = np.arange(8, dtype=np.int64)
    nodes = np.zeros((len(types), 23), dtype=np.float32)
    src, dst, rel = np.array([0, 4, 3]), np.array([4, 3, 5]), np.array([5, 3, 4])
    nodes[3, :4] = [2, 1, 3, 1]
    nodes[5, :4] = [200, 0, 300, 0]
    nodes[7, :4] = [4, 1, 7, 1]
    nodes[4, :4] = nodes[6, :4] = [400, 1, 500, 1]
    return (nodes, types, src, dst, rel, *compute_dag_structural_encodings(len(types), types, src, dst, rel))


def test_action_ir_uses_canonical_sinks_and_observation_masks():
    nx, nt, es, ed, er, spd, _, rd, sd = graph()
    ir, active = extract_single_graph_action_ir_np(nx, nt, es, ed, er, spd, rd, sd)
    assert active
    assert SINK_NODE_TYPES == (3, 5, 7)
    assert ir[:3] == pytest.approx(np.full(3, np.log(2)))
    assert ir[3] == 0.0
    assert ir[4] == pytest.approx(np.log(2))
    assert ir[5] == pytest.approx(3 / 5)
    assert ir[6] == pytest.approx(1 / 5)
    assert ir[12:16] == pytest.approx([2 / 9, 1 / 9, 1 / 3, 2 / 3])
    assert ir[16:20] == pytest.approx([4, 3, 7, 2 / 3])


def test_action_ir_is_independent_of_tabular_inputs_and_handles_missing_graph():
    packed = graph()
    props = dict(
        node_x=packed[0],
        node_type=packed[1],
        node_ptr=np.array([0, 8, 8]),
        row_indices=np.array([0, 1]),
        precomputed_graphs=[packed, None],
    )
    a, a_active = extract_observable_action_ir_np(np.zeros((2, 73)), **props)
    b, b_active = extract_observable_action_ir_np(np.full((2, 73), 100), **props)
    np.testing.assert_array_equal(a, b)
    np.testing.assert_array_equal(a_active, b_active)
    np.testing.assert_array_equal(b_active, [True, False])
    assert np.flatnonzero(b[1]).tolist() == [12, 13]


def test_fixed_condition_curve_counts_new_misses_even_when_other_rows_recover():
    curve = evaluate_budgeted_attack_curve(
        {
            0: [0.7, 0.8, 0.1],
            10: [0.3, 0.9, 0.9],
            25: [0.1, 0.2, 0.9],
            50: [0.7, 0.3, 0.9],
            100: [0.2, 0.3, 0.4],
        },
        threshold=0.5,
    )
    assert [r["budget"] for r in curve] == [0, 10, 25, 50, 100]
    assert [r["clean_detected_count"] for r in curve] == [2] * 5
    assert [r["detected_count"] for r in curve] == [2, 2, 1, 2, 0]
    assert [r["newly_evaded_count"] for r in curve] == [0, 1, 2, 1, 2]
    assert curve[1]["newly_evaded_rate_among_detected"] == 0.5
    assert curve[1]["recall"] == pytest.approx(2 / 3)


def test_calibration_accounts_for_ties_and_preserves_primary_threshold_alias():
    labels = np.r_[np.zeros(200, dtype=int), np.ones(2, dtype=int)]
    probabilities = np.r_[np.full(198, 0.1), 0.4, 0.4, 0.8, 0.9]
    thresholds, fprs = calibrate_thresholds(labels, probabilities)
    assert 0.4 < thresholds["thr_val_calib"] == thresholds["thr_f1_macro"] <= 0.50
    assert thresholds["thr_fpr_05pct"] > 0.4
    assert thresholds["thr_fpr1"] <= 0.4
    assert fprs["thr_fpr_05pct"] == 0
    assert fprs["thr_fpr1"] == 0.01


def test_numeric_format_changes_preserve_clean_ir_except_for_graph_dropout():
    packed = graph()
    count = 200
    raw = np.full((count, 73), 4.0, dtype=np.float32)
    clean_ir, _ = extract_single_graph_action_ir_np(*packed[:5])
    ir = np.broadcast_to(clean_ir, (count, len(clean_ir))).copy()
    active = np.ones(count, dtype=bool)
    graphs = [packed] * count
    perturbed, pert_ir, pert_active, pert_graphs = format_view(
        raw,
        active,
        ir,
        active,
        graphs,
        np.random.default_rng(42),
    )
    surviving = np.asarray([g is packed for g in pert_graphs])
    assert surviving.any() and not surviving.all()
    assert ((perturbed[:, IDX["lexical_JS"]] == 0) & surviving).any()
    np.testing.assert_array_equal(pert_active, surviving)
    np.testing.assert_array_equal(pert_ir[surviving], ir[surviving])
    np.testing.assert_array_equal(pert_ir[~surviving], np.broadcast_to(EMPTY_IR, pert_ir[~surviving].shape))
    assert (perturbed[~surviving, IDX["lexical_page_command"]] >= 50).all()
    assert active.all() and all(g is packed for g in graphs)
    np.testing.assert_array_equal(raw, 4.0)


@pytest.mark.parametrize(
    "arm",
    [
        "gin_tab_baseline",
        "v4_no_action_ir",
        "v4_no_spd_bias",
        "v4_no_monotonic_loss",
        "pdf_transgraph_v4",
    ],
)
def test_ablation_forward_and_ssl_backward(arm):
    torch.set_num_threads(1)
    opts, _ = ABLATIONS[arm]
    model = PDFTransGraphV4(TransGraphV4Config(tab_dim=4, hidden_dim=16, num_graph_layers=1, **opts))
    device = torch.device("cpu")
    packed = build_padded_graph_tensors([graph()] * 4 + [None], device)
    tab = torch.arange(20, dtype=torch.float32).reshape(5, 4) / 10
    tab_mask = tab < 0.5
    node_mask = packed[3].clone()
    node_mask[:, 2:] = False
    ir, active = extract_observable_action_ir_np(
        node_x=None,
        node_type=None,
        node_ptr=np.zeros(6, dtype=np.int64),
        row_indices=np.arange(5),
        precomputed_graphs=[graph()] * 4 + [None],
    )
    out = model(tab, torch.from_numpy(ir), torch.from_numpy(active), *packed)
    assert torch.isfinite(out["logits"]).all()
    assert torch.equal(out["modality_mask"][:, 2], torch.tensor(active) & model.config.enable_action_ir)
    loss = model.ssl_loss(tab, tab_mask, *packed, node_mask)
    assert torch.isfinite(loss)
    (loss + out["logits"].mean()).backward()
    gradients = [p.grad for p in model.parameters() if p.grad is not None]
    assert model.ssl_tab_head.weight.grad is not None
    assert model.ssl_node_type_head.weight.grad is not None
    assert all(torch.isfinite(grad).all() for grad in gradients)


def test_graft_benign_subtree_pair_appends_passive_nodes_up_to_320_without_filespec_leak():
    m_nx = np.zeros((150, 23), dtype=np.float32)
    m_nt = np.r_[np.array([0, 1, 3, 5], dtype=np.int64), np.full(146, 2, dtype=np.int64)]
    m_es = np.array([0, 0, 2], dtype=np.int64)
    m_ed = np.array([1, 2, 3], dtype=np.int64)
    m_er = np.array([0, 2, 4], dtype=np.int64)

    d_nx = np.ones((120, 23), dtype=np.float32)
    d_nt = np.r_[np.full(50, 2, dtype=np.int64), np.full(50, 6, dtype=np.int64), np.full(20, 7, dtype=np.int64)]
    d_es = np.arange(50, dtype=np.int64)
    d_ed = np.arange(50, 100, dtype=np.int64)
    d_er = np.full(50, 6, dtype=np.int64)

    base_raw = np.ones(73, dtype=np.float32)
    donor_raw = np.ones(73, dtype=np.float32) * 10.0
    out_raw, grafted = graft_benign_subtree_pair(
        base_raw,
        (m_nx, m_nt, m_es, m_ed, m_er),
        donor_raw,
        (d_nx, d_nt, d_es, d_ed, d_er),
        IDX,
        donor_fraction=1.0,
        max_nodes=320,
    )
    assert grafted is not None
    g_nx, g_nt, g_es, g_ed, g_er = grafted
    assert len(g_nx) == 250
    assert not (g_nt[150:] == 7).any()
    assert set(g_nt[150:].tolist()) == {2, 6}
    spd_before = compute_dag_structural_encodings(len(m_nt), m_nt, m_es, m_ed, m_er)[0]
    spd_after = compute_dag_structural_encodings(len(g_nt), g_nt, g_es, g_ed, g_er)[0]
    np.testing.assert_array_equal(spd_before, spd_after[:150, :150])
    ir_before, _ = extract_single_graph_action_ir_np(m_nx, m_nt, m_es, m_ed, m_er)
    ir_after, _ = extract_single_graph_action_ir_np(g_nx, g_nt, g_es, g_ed, g_er)
    np.testing.assert_allclose(ir_before, ir_after, atol=0.0)
    assert out_raw[IDX["lexical_obj"]] > base_raw[IDX["lexical_obj"]]
