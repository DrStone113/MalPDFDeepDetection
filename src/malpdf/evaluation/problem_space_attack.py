"""Problem-space adaptive subtree grafting attacker satisfying Pierazzi et al. (IEEE S&P 2020) Gamma constraints."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import io
from typing import Any

import numpy as np
import pikepdf

from malpdf.extraction.numeric_export import MAX_EDGES

TARGET_DONOR_CAPS = {0: 8, 1: 12, 2: 20, 3: 32, 4: 48}


def evaluate_budgeted_attack_curve(
    probabilities_by_budget: Mapping[int, Sequence[float] | np.ndarray], *, threshold: float
) -> list[dict[str, int | float | None]]:
    """Summarize pre-scored, row-aligned conditions against their common clean baseline."""
    if 0 not in probabilities_by_budget or not 0 <= threshold <= 1:
        raise ValueError("missing_clean_baseline_or_invalid_threshold")
    clean = np.asarray(probabilities_by_budget[0], dtype=np.float64) >= threshold
    clean_detected = int(clean.sum())
    rows = []
    for budget, values in sorted(probabilities_by_budget.items()):
        scores = np.asarray(values, dtype=np.float64)
        if (
            budget < 0
            or scores.ndim != 1
            or scores.shape != clean.shape
            or not len(scores)
            or not np.all((scores >= 0) & (scores <= 1))
        ):
            raise ValueError(f"invalid_or_unaligned_probabilities_at_budget:{budget}")
        detected = scores >= threshold
        missed = int((clean & ~detected).sum())
        rows.append(
            {
                "budget": budget,
                "count": len(scores),
                "clean_detected_count": clean_detected,
                "detected_count": int(detected.sum()),
                "recall": float(detected.mean()),
                "newly_evaded_count": missed,
                "newly_evaded_rate_among_detected": missed / clean_detected if clean_detected else None,
                "mean_prob": float(scores.mean()),
            }
        )
    return rows


def _recompute_derived_raw(row: np.ndarray, idx_map: dict[str, int]) -> None:
    obj = max(float(row[idx_map["lexical_obj"]]), 1.0)
    endobj = float(row[idx_map["lexical_endobj"]])
    stream = float(row[idx_map["lexical_stream"]])
    endstream = float(row[idx_map["lexical_endstream"]])
    js = float(row[idx_map["lexical_JS"]])
    javascript = float(row[idx_map["lexical_JavaScript"]])
    row[idx_map["js_per_obj"]] = (js + javascript) / obj
    row[idx_map["stream_per_obj"]] = stream / obj
    row[idx_map["obj_endobj_diff"]] = abs(obj - endobj)
    row[idx_map["stream_endstream_diff"]] = abs(stream - endstream)


def graft_benign_subtree_pair(
    mal_raw: np.ndarray,
    mal_graph: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None,
    donor_raw: np.ndarray,
    donor_graph: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None,
    idx_map: dict[str, int],
    *,
    donor_fraction: float = 1.0,
    max_nodes: int = 320,
) -> tuple[np.ndarray, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None]:
    """Attach a real benign PDF's passive objects/pages onto a malicious sample preserving all trigger tokens."""
    out_raw = np.array(mal_raw, dtype=np.float32, copy=True)
    frac = float(np.clip(donor_fraction, 0.1, 1.0))

    for col in (
        "lexical_obj",
        "lexical_endobj",
        "lexical_stream",
        "lexical_endstream",
        "lexical_page_command",
        "lexical_Resources",
        "raw_size_bytes",
    ):
        d_val = max(0.0, float(donor_raw[idx_map[col]]) * frac)
        if np.isfinite(d_val) and np.isfinite(out_raw[idx_map[col]]):
            out_raw[idx_map[col]] += d_val
    _recompute_derived_raw(out_raw, idx_map)

    if mal_graph is None or len(mal_graph[0]) == 0:
        return out_raw, mal_graph
    if donor_graph is None or len(donor_graph[0]) == 0:
        return out_raw, mal_graph

    m_nx, m_nt, m_es, m_ed, m_er = mal_graph
    d_nx, d_nt, d_es, d_ed, d_er = donor_graph
    # Graft only passive structure nodes (page=2, stream=6, pdf_object=8) so zero triggers/filespecs are mutated.
    passive_idx = np.flatnonzero((d_nt == 2) | (d_nt == 6) | (d_nt == 8))
    if len(passive_idx) == 0:
        return out_raw, mal_graph

    room = max(0, int(max_nodes) - len(m_nx))
    if room == 0:
        return out_raw, mal_graph
    keep_cap = min(room, max(1, int(round(len(passive_idx) * frac))))
    chosen_d = passive_idx[:keep_cap]
    remap = {int(old_i): len(m_nx) + new_off for new_off, old_i in enumerate(chosen_d.tolist())}

    new_nx = np.concatenate((m_nx, d_nx[chosen_d]), axis=0)
    new_nt = np.concatenate((m_nt, d_nt[chosen_d]), axis=0)

    pages_nodes = np.flatnonzero((m_nt == 1) | (m_nt == 0))
    attach_parent = int(pages_nodes[0]) if len(pages_nodes) > 0 else 0

    add_es, add_ed, add_er = [], [], []
    for ds, dd, dr in zip(d_es.tolist(), d_ed.tolist(), d_er.tolist(), strict=True):
        if ds in remap and dd in remap:
            add_es.append(remap[ds])
            add_ed.append(remap[dd])
            add_er.append(int(dr))
    for old_i in chosen_d.tolist():
        if int(d_nt[old_i]) == 2:
            add_es.append(attach_parent)
            add_ed.append(remap[old_i])
            add_er.append(0)

    if add_es:
        comb_es = np.concatenate((m_es, np.asarray(add_es, dtype=np.int64)))[:MAX_EDGES]
        comb_ed = np.concatenate((m_ed, np.asarray(add_ed, dtype=np.int64)))[:MAX_EDGES]
        comb_er = np.concatenate((m_er, np.asarray(add_er, dtype=np.int64)))[:MAX_EDGES]
    else:
        comb_es, comb_ed, comb_er = m_es, m_ed, m_er

    return out_raw, (new_nx, new_nt, comb_es, comb_ed, comb_er)


def physical_binary_graft_pdf(
    threat_pdf_bytes: bytes,
    benign_donor_bytes: bytes,
    *,
    num_padding_objects: int,
    payload_bytes_per_obj: int = 1024,
) -> bytes:
    """Physically append valid benign pages/streams into a threat PDF using pikepdf (Pierazzi Gamma 1-4)."""
    with pikepdf.open(io.BytesIO(threat_pdf_bytes)) as dst, pikepdf.open(io.BytesIO(benign_donor_bytes)) as src:
        num_pages = max(1, min(len(src.pages), max(1, num_padding_objects // 8)))
        for p_idx in range(num_pages):
            dst.pages.append(src.pages[p_idx % len(src.pages)])
        # Append deterministic benign structural objects inside existing pages' /Resources /ExtGState
        extra_needed = max(0, int(num_padding_objects) - num_pages * 2)
        if extra_needed > 0:
            res = dst.pages[0].obj.get("/Resources")
            if not isinstance(res, pikepdf.Dictionary):
                res = pikepdf.Dictionary()
                dst.pages[0].obj["/Resources"] = res
            holder = pikepdf.Dictionary()
            blob = (b"BT /F1 10 Tf 0 0 Td (PaddingSection) Tj ET\n" * max(1, payload_bytes_per_obj // 40))[
                :payload_bytes_per_obj
            ]
            for idx in range(extra_needed):
                holder[f"/BenignGraft{idx}"] = dst.make_indirect(pikepdf.Stream(dst, blob))
            res["/MalPDFBenignGrafts"] = holder
        out = io.BytesIO()
        dst.save(out, compress_streams=False)
        return out.getvalue()


def run_greedy_adaptive_graft_attack(
    mal_rows_raw: np.ndarray,
    mal_graphs: list[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None],
    donor_raws: np.ndarray,
    donor_graphs: list[tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None],
    idx_map: dict[str, int],
    score_fn: Callable[[np.ndarray, list[Any]], np.ndarray],
    *,
    decision_threshold: float,
    budgets: tuple[int, ...] = (0, 10, 25, 50, 100),
    beam_candidates: int = 16,
    max_nodes: int = 320,
    seed: int = 42,
) -> dict[str, Any]:
    """Evaluate detector recall decay under adaptive greedy subtree grafting at object-count budgets B."""
    rng = np.random.default_rng(seed)
    n_mal = len(mal_rows_raw)
    n_donors = len(donor_raws)
    donor_objs = np.maximum(donor_raws[:, idx_map["lexical_obj"]], 1.0)
    per_budget: dict[str, Any] = {}
    probs_by_budget: dict[int, np.ndarray] = {}

    cur_raw = np.array(mal_rows_raw, dtype=np.float32, copy=True)
    cur_graphs = list(mal_graphs)
    added_objs = np.zeros(n_mal, dtype=np.float32)

    sorted_budgets = sorted(set(int(b) for b in budgets))
    for target_b in sorted_budgets:
        if target_b > 0:
            for _step in range(8):
                need = np.flatnonzero(added_objs < float(target_b))
                if len(need) == 0:
                    break
                cand_raws = []
                cand_graphs = []
                cand_added = []
                cand_meta = []
                for m_pos in need.tolist():
                    remaining = max(1.0, float(target_b) - float(added_objs[m_pos]))
                    pool_cands = rng.choice(n_donors, size=min(beam_candidates, n_donors), replace=False)
                    for d_pos in pool_cands.tolist():
                        frac = min(1.0, remaining / float(donor_objs[d_pos]))
                        g_raw, g_graph = graft_benign_subtree_pair(
                            cur_raw[m_pos],
                            cur_graphs[m_pos],
                            donor_raws[d_pos],
                            donor_graphs[d_pos],
                            idx_map,
                            donor_fraction=frac,
                            max_nodes=max_nodes,
                        )
                        cand_raws.append(g_raw)
                        cand_graphs.append(g_graph)
                        cand_added.append(max(1.0, float(donor_objs[d_pos]) * frac))
                        cand_meta.append(m_pos)

                probs = score_fn(np.stack(cand_raws, axis=0), cand_graphs)
                best_for_m: dict[int, tuple[float, int]] = {}
                for c_idx, m_pos in enumerate(cand_meta):
                    sc = float(probs[c_idx])
                    if m_pos not in best_for_m or sc < best_for_m[m_pos][0]:
                        best_for_m[m_pos] = (sc, c_idx)
                for m_pos, (_, best_c) in best_for_m.items():
                    cur_raw[m_pos] = cand_raws[best_c]
                    cur_graphs[m_pos] = cand_graphs[best_c]
                    added_objs[m_pos] += cand_added[best_c]

        p_now = np.asarray(score_fn(cur_raw, cur_graphs), dtype=np.float64)
        probs_by_budget[target_b] = p_now
        detected = p_now >= float(decision_threshold)
        recall = float(np.mean(detected))
        per_budget[str(target_b)] = {
            "budget_objects": target_b,
            "mean_added_objects": float(np.mean(added_objs)),
            "recall": round(recall, 6),
            "evasion_success_rate": round(1.0 - recall, 6),
            "mean_prob": round(float(np.mean(p_now)), 6),
            "min_prob": round(float(np.min(p_now)), 6),
        }

    return {
        "n_malicious": n_mal,
        "decision_threshold": float(decision_threshold),
        "budgets": per_budget,
        "curve": evaluate_budgeted_attack_curve(probs_by_budget, threshold=float(decision_threshold)),
        "probabilities_by_budget": {str(k): v.tolist() for k, v in probs_by_budget.items()},
    }
