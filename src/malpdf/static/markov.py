"""Byte-transition probabilities without PDF parsing, rendering or execution."""

from __future__ import annotations

import numpy as np

MARKOV_ALGORITHM = "byte-transition-row-probability-v1"
MARKOV_SHAPE = (256, 256)


def byte_transition_matrix(data: bytes) -> np.ndarray:
    """Return float32 P(next byte | current byte); unseen rows remain zero.

    Store the single channel as (256, 256); a tensor loader can add the channel
    axis to obtain (1, 256, 256). Callers must bound file reads before this API.
    """
    if not isinstance(data, bytes) or len(data) < 2:
        raise ValueError("At least two bytes are required for a Markov matrix")
    values = np.frombuffer(data, dtype=np.uint8).astype(np.uint16)
    transitions = values[:-1] * 256 + values[1:]
    counts = np.bincount(transitions, minlength=256 * 256).reshape(MARKOV_SHAPE)
    row_totals = counts.sum(axis=1, keepdims=True)
    probabilities = np.zeros(MARKOV_SHAPE, dtype=np.float64)
    np.divide(counts, row_totals, out=probabilities, where=row_totals != 0)
    return probabilities.astype(np.float32)
