"""Portable, bounded numeric Markov cache format; no PDF-parser dependencies."""

import io
import numpy as np

MARKOV_SHAPE = (256, 256)
MAX_CACHE_BYTES = 1024 * 1024


def load_markov_npy(content: bytes) -> np.ndarray:
    if len(content) > MAX_CACHE_BYTES:
        raise ValueError("Cache exceeds its byte cap")
    handle = io.BytesIO(content)
    if np.lib.format.read_magic(handle) != (1, 0):
        raise ValueError("Expected NPY format version 1.0")
    shape, fortran_order, dtype = np.lib.format.read_array_header_1_0(handle, max_header_size=512)
    if shape != MARKOV_SHAPE or fortran_order or dtype != np.dtype("float32"):
        raise ValueError("Cache must be a C-order float32 (256, 256) matrix")
    if len(content) - handle.tell() != 256 * 256 * 4:
        raise ValueError("Cache payload size differs from its header")
    matrix = np.load(io.BytesIO(content), allow_pickle=False, max_header_size=512)
    sums = matrix.sum(axis=1, dtype=np.float64)
    if not np.isfinite(matrix).all() or (matrix < 0).any() or (matrix > 1).any():
        raise ValueError("Cache probabilities must be finite and in [0, 1]")
    if not np.all((sums == 0) | np.isclose(sums, 1, rtol=0, atol=1e-6)):
        raise ValueError("Cache rows must sum to zero or one")
    return matrix
