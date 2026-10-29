import pytest
import torch

from malpdf.models.adversarial_simulator import (
    create_adversarial_sample,
    drop_and_rewire_edges,
    inject_orphan_nodes,
    mutate_ast_tokens,
    perturb_tabular_features,
)


def create_dummy_sample():
    num_nodes = 5
    return {
        "sha256": "dummy_sha256",
        "sample_id": "dummy_id",
        "label": 1,
        "node_features": torch.randn((num_nodes, 19)),
        "node_types": torch.tensor([0, 1, 2, 4, 5], dtype=torch.long),
        "edge_src": torch.tensor([0, 0, 1], dtype=torch.long),
        "edge_dst": torch.tensor([1, 2, 3], dtype=torch.long),
        "edge_rel": torch.tensor([0, 1, 2], dtype=torch.long),
        "ast_tokens": torch.randint(0, 64, (32,), dtype=torch.long),
        "tab_features": torch.randn((38,)),
        "meta": {"status": "bounded_complete"},
    }


def test_inject_orphan_nodes():
    sample = create_dummy_sample()
    num_orig = sample["node_features"].size(0)
    nf, nt, es, ed, er = inject_orphan_nodes(
        sample["node_features"],
        sample["node_types"],
        sample["edge_src"],
        sample["edge_dst"],
        sample["edge_rel"],
        num_orphans=20,
    )
    assert nf.size(0) == num_orig + 20
    assert nf.size(1) == 19
    assert nt.size(0) == num_orig + 20
    assert es.size(0) == ed.size(0) == er.size(0)


def test_mutate_ast_tokens():
    tokens = torch.randint(1, 64, (32,), dtype=torch.long)
    mutated = mutate_ast_tokens(tokens, mutation_rate=0.5, vocab_size=64)
    assert mutated.size(0) == 32
    assert (mutated >= 0).all() and (mutated < 64).all()


def test_drop_and_rewire_edges():
    es = torch.tensor([0, 1, 2, 3, 4], dtype=torch.long)
    ed = torch.tensor([1, 2, 3, 4, 0], dtype=torch.long)
    er = torch.tensor([0, 1, 2, 0, 1], dtype=torch.long)
    n_es, n_ed, n_er = drop_and_rewire_edges(es, ed, er, drop_rate=0.5)
    assert n_es.size(0) <= 5
    assert n_es.size(0) == n_ed.size(0) == n_er.size(0)


def test_perturb_tabular_features():
    tab = torch.zeros((38,))
    perturbed = perturb_tabular_features(tab, shift_intensity=1.0)
    assert perturbed.size(0) == 38
    assert not torch.allclose(tab, perturbed)


def test_create_adversarial_sample():
    sample = create_dummy_sample()
    for mode in ["orphan_only", "ast_only", "structure_only", "combined"]:
        adv = create_adversarial_sample(sample, attack_type=mode, num_orphans=15)
        assert adv["label"] == sample["label"]
        assert adv["sha256"] == sample["sha256"]
        assert adv["node_features"].size(1) == 19
        assert adv["ast_tokens"].size(0) == 32
        assert adv["tab_features"].size(0) == 38
