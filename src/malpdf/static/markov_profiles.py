"""Fixed byte-structure summaries of existing Markov probabilities, without fitting."""
import numpy as np

MARKOV_PROFILE_FEATURES = tuple("markov__" + name for name in (
    "active_fraction", "transition_density", "entropy_mean", "entropy_std", "entropy_max",
    "row_max_mean", "diagonal_mean", "row_squared_mass_mean", "asymmetry_mean",
    *(f"active_band_{i}" for i in range(4)),
    *(f"transition_band_{i}_{j}" for i in range(4) for j in range(4)),
    *(f"destination_band_{i}" for i in range(4))))


def markov_profile(matrix):
    """Return 33 measured descriptors; do not alter or renormalize the matrix.

    Bands are consecutive ranges of 64 byte values. Transition-band mass is
    averaged over active source rows. This conditional summary is not a byte
    frequency estimate: the original cache does not retain source frequencies.
    Empty matrices have explicit zero summaries. No labels, splits or fitted
    transforms enter this function; descriptors are not exploit signatures.
    """
    p = np.asarray(matrix)
    if (p.shape != (256, 256) or p.dtype != np.float32 or not np.isfinite(p).all()
            or (p < 0).any() or (p > 1).any()):
        raise ValueError("Profiles require verified float32 Markov probabilities")
    mass = p.sum(axis=1, dtype=np.float64)
    if not np.all((mass == 0) | np.isclose(mass, 1, rtol=0, atol=1e-6)):
        raise ValueError("Markov rows must sum to zero or one")
    active = mass > 0
    count = int(active.sum())
    entropy = -np.sum(p * np.log2(np.maximum(p, np.finfo(np.float32).tiny)), axis=1, dtype=np.float64)
    mean = lambda values: float(np.mean(values[active])) if count else 0.0
    values = [count / 256, np.count_nonzero(p) / 65536, mean(entropy),
        float(np.std(entropy[active])) if count else 0., float(entropy.max()),
        mean(p.max(axis=1)), mean(np.diag(p)), mean(np.square(p).sum(axis=1)),
        float(np.abs(p - p.T).mean())]
    values.extend(float(active[i * 64:(i + 1) * 64].mean()) for i in range(4))
    bands = p.reshape(4, 64, 4, 64).sum(axis=(1, 3), dtype=np.float64) / max(count, 1)
    values.extend(bands.ravel().tolist())
    values.extend(bands.sum(axis=0).tolist())
    result = np.asarray(values, dtype=np.float32)
    if result.shape != (len(MARKOV_PROFILE_FEATURES),) or not np.isfinite(result).all():
        raise ValueError("Invalid measured Markov profile")
    return result
