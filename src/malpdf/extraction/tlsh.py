from __future__ import annotations

from pathlib import Path
import re
import subprocess

DISTANCE_LIMIT = 30
TLSH_RE = re.compile(r"(?:T1)?[0-9A-F]{70}\Z")


def nearest_distances(executable, reference, queries, *, pass_fds=()):
    payload = f"{len(reference)} {len(queries)}\n" + "\n".join([*reference, *queries]) + "\n"
    result = subprocess.run(
        [str(Path(executable).absolute())], input=payload, text=True, check=True,
        capture_output=True, timeout=180, pass_fds=pass_fds,
    )
    distances = [int(value) for value in result.stdout.splitlines()]
    if len(distances) != len(queries) or any(distance < 0 for distance in distances):
        raise ValueError("invalid_TLSH_distance_results")
    return distances


def screen(reference, candidates, measure_distances):
    measured_reference = [digest for digest in reference.values() if digest is not None]
    reference_complete = bool(reference) and len(reference) == len(measured_reference)
    measurements = {}
    pending = {}
    for sha, digest in candidates.items():
        if sha in reference:
            measurements[sha] = {"disposition": "exact_duplicate", "distance": None}
        elif digest is None:
            measurements[sha] = {"disposition": "candidate_fingerprint_unavailable", "distance": None}
        else:
            pending[sha] = digest

    distances = (
        measure_distances(measured_reference, list(pending.values()))
        if measured_reference and pending else [None] * len(pending)
    )
    for sha, distance in zip(pending, distances, strict=True):
        if distance is not None and distance <= DISTANCE_LIMIT:
            disposition = "near_duplicate"
        elif reference_complete and distance is not None:
            disposition = "no_near_duplicate_in_reference"
        else:
            disposition = "reference_coverage_incomplete"
        measurements[sha] = {"disposition": disposition, "distance": distance}
    return measurements
