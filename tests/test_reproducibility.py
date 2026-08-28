import random

import numpy as np
import pytest

from malpdf.reproducibility import set_random_seed


def test_set_random_seed_repeats_sequences():
    set_random_seed(123)
    first = (random.random(), np.random.random())

    set_random_seed(123)
    second = (random.random(), np.random.random())

    assert first == second


@pytest.mark.parametrize("seed", [-1, 1.5, True])
def test_set_random_seed_rejects_invalid_values(seed):
    with pytest.raises(ValueError, match="non-negative integer"):
        set_random_seed(seed)
