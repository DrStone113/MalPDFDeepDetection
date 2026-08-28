"""Helpers for deterministic experiment setup."""

from __future__ import annotations

import os
import random

import numpy as np

DEFAULT_RANDOM_SEED = 42


def set_random_seed(seed: int = DEFAULT_RANDOM_SEED) -> None:
    """Seed Python and NumPy, and propagate the seed to child processes."""
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")

    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
