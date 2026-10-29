from __future__ import annotations

import copy
import numpy as np
import torch


def inject_orphan_nodes(
    node_features: torch.Tensor,
    node_types: torch.Tensor,
    edge_src: torch.Tensor,
    edge_dst: torch.Tensor,
    edge_rel: torch.Tensor,
    num_orphans: int = 25,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    num_existing = node_features.size(0)
    orphan_types_candidates = torch.tensor([1, 2, 4, 5], dtype=torch.long)
    rand_idx = torch.randint(0, len(orphan_types_candidates), (num_orphans,))
    orphan_types = orphan_types_candidates[rand_idx]

    orphan_feats = torch.zeros((num_orphans, 19), dtype=torch.float32)
    orphan_feats[:, 0] = torch.randint(0, 3, (num_orphans,)).float()
    orphan_feats[:, 1] = torch.randint(0, 3, (num_orphans,)).float()
    orphan_feats[:, 2] = orphan_feats[:, 0] + orphan_feats[:, 1]

    new_node_features = torch.cat([node_features, orphan_feats], dim=0)
    new_node_types = torch.cat([node_types, orphan_types], dim=0)

    orphan_src = []
    orphan_dst = []
    orphan_rel = []
    for i in range(num_orphans - 1):
        if torch.rand(1).item() < 0.4:
            orphan_src.append(num_existing + i)
            orphan_dst.append(num_existing + i + 1)
            orphan_rel.append(1)

    if len(orphan_src) > 0:
        o_src = torch.tensor(orphan_src, dtype=torch.long)
        o_dst = torch.tensor(orphan_dst, dtype=torch.long)
        o_rel = torch.tensor(orphan_rel, dtype=torch.long)
        new_edge_src = torch.cat([edge_src, o_src], dim=0)
        new_edge_dst = torch.cat([edge_dst, o_dst], dim=0)
        new_edge_rel = torch.cat([edge_rel, o_rel], dim=0)
    else:
        new_edge_src = edge_src.clone()
        new_edge_dst = edge_dst.clone()
        new_edge_rel = edge_rel.clone()

    return new_node_features, new_node_types, new_edge_src, new_edge_dst, new_edge_rel


def mutate_ast_tokens(
    ast_tokens: torch.Tensor,
    mutation_rate: float = 0.35,
    vocab_size: int = 64,
) -> torch.Tensor:
    mutated = ast_tokens.clone()
    seq_len = mutated.size(0)
    mask = torch.rand(seq_len) < mutation_rate
    for idx in range(seq_len):
        if mask[idx]:
            action = torch.rand(1).item()
            if action < 0.4:
                mutated[idx] = 0
            elif action < 0.8:
                mutated[idx] = torch.randint(1, vocab_size, (1,)).item()
            else:
                shift_idx = (idx + 1) % seq_len
                mutated[idx] = ast_tokens[shift_idx]
    return mutated


def drop_and_rewire_edges(
    edge_src: torch.Tensor,
    edge_dst: torch.Tensor,
    edge_rel: torch.Tensor,
    drop_rate: float = 0.2,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    num_edges = edge_src.size(0)
    if num_edges == 0:
        return edge_src.clone(), edge_dst.clone(), edge_rel.clone()
    keep_mask = torch.rand(num_edges) >= drop_rate
    if not keep_mask.any():
        keep_mask[0] = True
    return edge_src[keep_mask], edge_dst[keep_mask], edge_rel[keep_mask]


def perturb_tabular_features(
    tab_features: torch.Tensor,
    shift_intensity: float = 0.5,
) -> torch.Tensor:
    perturbed = tab_features.clone()
    dim = perturbed.size(0)
    noise = torch.randn(dim) * (0.2 * shift_intensity)
    perturbed = perturbed + noise
    if dim > 7:
        perturbed[2] = perturbed[2] + (1.5 * shift_intensity)
        perturbed[4] = perturbed[4] + (1.2 * shift_intensity)
        perturbed[7] = perturbed[7] + (1.0 * shift_intensity)
    return perturbed


def create_adversarial_sample(
    sample: dict,
    attack_type: str = "combined",
    num_orphans: int = 30,
) -> dict:
    new_sample = {
        "sha256": sample["sha256"],
        "sample_id": sample.get("sample_id", ""),
        "label": sample["label"],
        "meta": copy.deepcopy(sample.get("meta", {})),
    }

    nf = sample["node_features"].clone()
    nt = sample["node_types"].clone()
    es = sample["edge_src"].clone()
    ed = sample["edge_dst"].clone()
    er = sample["edge_rel"].clone()
    ast = sample["ast_tokens"].clone()
    tab = sample["tab_features"].clone()

    if attack_type == "orphan_only":
        nf, nt, es, ed, er = inject_orphan_nodes(nf, nt, es, ed, er, num_orphans=num_orphans)
        tab = perturb_tabular_features(tab, shift_intensity=0.6)
    elif attack_type == "ast_only":
        ast = mutate_ast_tokens(ast, mutation_rate=0.45)
    elif attack_type == "structure_only":
        es, ed, er = drop_and_rewire_edges(es, ed, er, drop_rate=0.3)
    elif attack_type == "combined":
        nf, nt, es, ed, er = inject_orphan_nodes(nf, nt, es, ed, er, num_orphans=num_orphans)
        es, ed, er = drop_and_rewire_edges(es, ed, er, drop_rate=0.2)
        ast = mutate_ast_tokens(ast, mutation_rate=0.35)
        tab = perturb_tabular_features(tab, shift_intensity=0.5)

    new_sample["node_features"] = nf
    new_sample["node_types"] = nt
    new_sample["edge_src"] = es
    new_sample["edge_dst"] = ed
    new_sample["edge_rel"] = er
    new_sample["ast_tokens"] = ast
    new_sample["tab_features"] = tab
    return new_sample
