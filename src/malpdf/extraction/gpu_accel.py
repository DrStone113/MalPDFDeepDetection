"""Hybrid CPU/GPU tensor acceleration for RWSE graphs, Markov matrices, and raw entropy."""

from __future__ import annotations

from collections.abc import Sequence
import os

import numpy as np
import torch

from malpdf.static.markov import MARKOV_SHAPE, byte_transition_matrix


def resolve_extraction_device(device: str | torch.device = "auto") -> torch.device:
    if isinstance(device, torch.device):
        target = device
    elif device == "auto":
        target = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        target = torch.device(device)
    if target.type == "cuda" and not torch.cuda.is_available():
        return torch.device("cpu")
    return target


def hardware_profile(device: str | torch.device = "auto") -> dict:
    resolved = resolve_extraction_device(device)
    cuda_ok = torch.cuda.is_available()
    info = {
        "requested_device": str(device),
        "resolved_device": str(resolved),
        "cuda_available": bool(cuda_ok),
        "cpu_count": os.cpu_count() or 1,
        "torch_version": torch.__version__,
        "gpu_name": None,
        "gpu_memory_bytes": None,
    }
    if resolved.type == "cuda" and cuda_ok:
        idx = resolved.index if resolved.index is not None else torch.cuda.current_device()
        props = torch.cuda.get_device_properties(idx)
        info["gpu_name"] = props.name
        info["gpu_memory_bytes"] = int(props.total_memory)
    return info


def compute_rwse_batch_torch(
    graphs: Sequence[tuple[int, Sequence[int], Sequence[int]]],
    *,
    steps: int = 16,
    device: str | torch.device = "auto",
    max_batch_graphs: int = 256,
) -> list[list[list[float]]]:
    if steps < 1:
        raise ValueError("steps must be >= 1")
    results: list[list[list[float]]] = [[] for _ in graphs]
    non_empty = [
        (idx, num_nodes, edge_src, edge_dst)
        for idx, (num_nodes, edge_src, edge_dst) in enumerate(graphs)
        if num_nodes > 0
    ]
    if not non_empty:
        return results

    resolved = resolve_extraction_device(device)
    non_empty.sort(key=lambda item: item[1])

    for start in range(0, len(non_empty), max_batch_graphs):
        chunk = non_empty[start:start + max_batch_graphs]
        batch_size = len(chunk)
        max_nodes = max(item[1] for item in chunk)
        adj = torch.zeros((batch_size, max_nodes, max_nodes), dtype=torch.float32, device=resolved)

        b_indices: list[int] = []
        s_indices: list[int] = []
        d_indices: list[int] = []
        lengths: list[int] = []
        for batch_pos, (_, num_nodes, edge_src, edge_dst) in enumerate(chunk):
            lengths.append(num_nodes)
            for src, dst in zip(edge_src, edge_dst):
                if 0 <= src < num_nodes and 0 <= dst < num_nodes:
                    b_indices.append(batch_pos)
                    s_indices.append(src)
                    d_indices.append(dst)

        if b_indices:
            b_t = torch.tensor(b_indices, dtype=torch.long, device=resolved)
            s_t = torch.tensor(s_indices, dtype=torch.long, device=resolved)
            d_t = torch.tensor(d_indices, dtype=torch.long, device=resolved)
            ones = torch.ones(len(b_indices), dtype=torch.float32, device=resolved)
            adj.index_put_((b_t, s_t, d_t), ones, accumulate=True)

        deg = adj.sum(dim=-1, keepdim=True)
        transition = torch.where(deg > 0, adj / deg.clamp(min=1.0), torch.zeros_like(adj))

        lengths_t = torch.tensor(lengths, dtype=torch.long, device=resolved)
        node_valid = torch.arange(max_nodes, device=resolved).unsqueeze(0) < lengths_t.unsqueeze(1)
        zero_rows = (deg.squeeze(-1) == 0) & node_valid
        diag_idx = torch.arange(max_nodes, device=resolved)
        diag_vals = transition[:, diag_idx, diag_idx]
        transition[:, diag_idx, diag_idx] = torch.where(zero_rows, torch.ones_like(diag_vals), diag_vals)

        power = transition.clone()
        diag_steps = torch.empty((batch_size, max_nodes, steps), dtype=torch.float32, device=resolved)
        for step_idx in range(steps):
            diag_steps[:, :, step_idx] = torch.diagonal(power, dim1=1, dim2=2).clamp(0.0, 1.0)
            if step_idx + 1 < steps:
                power = torch.bmm(power, transition)

        cpu_out = diag_steps.cpu().tolist()
        for batch_pos, (orig_idx, num_nodes, _, _) in enumerate(chunk):
            results[orig_idx] = cpu_out[batch_pos][:num_nodes]

    return results


def _normalize_markov_counts(counts: torch.Tensor) -> torch.Tensor:
    counts_f = counts.to(torch.float32)
    row_totals = counts_f.sum(dim=-1, keepdim=True)
    return torch.where(row_totals > 0, counts_f / row_totals.clamp(min=1.0), torch.zeros_like(counts_f))


def _single_large_markov_gpu(data: bytes | bytearray | memoryview, device: torch.device, chunk_bytes: int) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = torch.zeros(256 * 256, dtype=torch.int64, device=device)
    step = max(2, chunk_bytes)
    pos = 0
    total = len(arr)
    while pos < total - 1:
        end = min(total, pos + step)
        chunk = torch.from_numpy(np.array(arr[pos:end], copy=True)).to(device=device).to(dtype=torch.int64)
        pairs = chunk[:-1] * 256 + chunk[1:]
        counts += torch.bincount(pairs, minlength=256 * 256)
        if end >= total:
            break
        pos = end - 1
    probs = _normalize_markov_counts(counts.view(MARKOV_SHAPE))
    return probs.cpu().numpy()


def byte_transition_matrices_batch(
    byte_buffers: Sequence[bytes | bytearray | memoryview],
    *,
    device: str | torch.device = "auto",
    max_batch_bytes: int = 32 * 1024 * 1024,
    max_batch_samples: int = 128,
) -> list[np.ndarray]:
    if not byte_buffers:
        return []
    for buf in byte_buffers:
        if not isinstance(buf, (bytes, bytearray, memoryview)) or len(buf) < 2:
            raise ValueError("At least two bytes are required for a Markov matrix")

    resolved = resolve_extraction_device(device)
    if resolved.type != "cuda":
        return [byte_transition_matrix(bytes(buf) if not isinstance(buf, bytes) else buf) for buf in byte_buffers]

    results: list[np.ndarray | None] = [None] * len(byte_buffers)
    pending: list[tuple[int, np.ndarray]] = []
    pending_bytes = 0

    def flush_batch() -> None:
        nonlocal pending, pending_bytes
        if not pending:
            return
        batch_len = len(pending)
        lengths = [len(arr) for _, arr in pending]
        total_bytes = sum(lengths)
        host_u8 = np.empty(total_bytes, dtype=np.uint8)
        cursor = 0
        cum_ends = []
        for _, arr in pending:
            n = len(arr)
            host_u8[cursor:cursor + n] = arr
            cursor += n
            cum_ends.append(cursor)

        gpu_u8 = torch.from_numpy(host_u8).to(device=resolved).to(dtype=torch.int64)
        all_pairs = gpu_u8[:-1] * 256 + gpu_u8[1:]
        if batch_len > 1:
            valid_mask = torch.ones(total_bytes - 1, dtype=torch.bool, device=resolved)
            boundary_idx = torch.tensor([pos - 1 for pos in cum_ends[:-1]], dtype=torch.long, device=resolved)
            valid_mask[boundary_idx] = False
            valid_pairs = all_pairs[valid_mask]
        else:
            valid_pairs = all_pairs

        pair_counts = torch.tensor([n - 1 for n in lengths], dtype=torch.long, device=resolved)
        sample_ids = torch.repeat_interleave(
            torch.arange(batch_len, dtype=torch.long, device=resolved),
            pair_counts,
        )
        counts = torch.bincount(sample_ids * 65536 + valid_pairs, minlength=batch_len * 65536).view(batch_len, *MARKOV_SHAPE)
        probs = _normalize_markov_counts(counts).cpu().numpy()
        for pos, (orig_idx, _) in enumerate(pending):
            results[orig_idx] = probs[pos]
        pending = []
        pending_bytes = 0

    for idx, buf in enumerate(byte_buffers):
        arr = np.frombuffer(buf, dtype=np.uint8)
        if len(arr) > max_batch_bytes:
            flush_batch()
            results[idx] = _single_large_markov_gpu(buf, resolved, max_batch_bytes)
            continue
        if pending and (pending_bytes + len(arr) > max_batch_bytes or len(pending) >= max_batch_samples):
            flush_batch()
        pending.append((idx, arr))
        pending_bytes += len(arr)

    flush_batch()
    return [item for item in results if item is not None]


def window_entropy_batch(
    data: bytes | bytearray | memoryview,
    *,
    window_bytes: int = 4096,
    device: str | torch.device = "auto",
) -> tuple[float, list[float]]:
    total = len(data)
    if total == 0:
        return 0.0, []
    resolved = resolve_extraction_device(device)
    arr = np.frombuffer(data, dtype=np.uint8)
    if resolved.type == "cuda" and total >= 256 * 1024:
        gpu_u8 = torch.from_numpy(np.array(arr, copy=True)).to(device=resolved).to(dtype=torch.int64)
        global_counts = torch.bincount(gpu_u8, minlength=256).to(torch.float64)
        global_probs = global_counts[global_counts > 0] / float(total)
        global_ent = float(-(global_probs * torch.log2(global_probs)).sum().item())

        num_windows = (total + window_bytes - 1) // window_bytes
        win_ids = torch.arange(total, dtype=torch.int64, device=resolved) // window_bytes
        win_hist = torch.bincount(win_ids * 256 + gpu_u8, minlength=num_windows * 256).view(num_windows, 256).to(torch.float64)
        win_lens = win_hist.sum(dim=1, keepdim=True).clamp(min=1.0)
        probs = win_hist / win_lens
        safe_probs = torch.where(probs > 0, probs, torch.ones_like(probs))
        win_ents = (-(probs * torch.log2(safe_probs)).sum(dim=1)).cpu().tolist()
        return global_ent, [float(v) for v in win_ents]

    counts = np.bincount(arr, minlength=256)
    nz = counts[counts > 0].astype(np.float64) / float(total)
    global_ent = float(-(nz * np.log2(nz)).sum())
    win_ents: list[float] = []
    for start in range(0, total, window_bytes):
        w = arr[start:start + window_bytes]
        wc = np.bincount(w, minlength=256)
        wnz = wc[wc > 0].astype(np.float64) / float(len(w))
        win_ents.append(float(-(wnz * np.log2(wnz)).sum()))
    return global_ent, win_ents
