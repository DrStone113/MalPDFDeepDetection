"""Immutable, checksum-verified .npy caching for byte-transition matrices."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile

import numpy as np

from malpdf.data.manifest_validator import validate_sha256
from malpdf.static.markov import MARKOV_ALGORITHM, MARKOV_SHAPE, byte_transition_matrix
from malpdf.static.safety import read_bounded_bytes
from malpdf.data.markov_arrays import MAX_CACHE_BYTES, load_markov_npy


def _publish_new(path: Path, content: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".markov-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_cached_markov_pdf(pdf_sha256: str, *, cache_directory: Path) -> tuple[np.ndarray, dict]:
    """Read a verified cache without opening the original PDF or writing files."""
    pdf_sha256 = validate_sha256(pdf_sha256)
    path = cache_directory / f"{pdf_sha256}.npy"
    content = read_bounded_bytes(path, boundary=cache_directory, max_bytes=MAX_CACHE_BYTES)
    metadata = json.loads(read_bounded_bytes(path.with_suffix(".json"), boundary=cache_directory, max_bytes=4096))
    expected = {"algorithm": MARKOV_ALGORITHM, "pdf_sha256": pdf_sha256, "shape": list(MARKOV_SHAPE), "dtype": "float32"}
    if not isinstance(metadata, dict) or set(metadata) != {*expected, "pdf_bytes", "npy_sha256"}:
        raise ValueError("Cache metadata differs from the algorithm/source contract")
    if any(metadata[key] != value for key, value in expected.items()) or type(metadata["pdf_bytes"]) is not int or metadata["pdf_bytes"] < 2:
        raise ValueError("Cache metadata differs from the algorithm/source contract")
    if hashlib.sha256(content).hexdigest() != validate_sha256(metadata["npy_sha256"]):
        raise ValueError("Cache checksum differs from its provenance metadata")
    return load_markov_npy(content), metadata


def cache_markov_pdf(
    raw_path: Path,
    pdf_sha256: str,
    *,
    raw_boundary: Path,
    cache_directory: Path,
    max_pdf_bytes: int = 10 * 1024 * 1024,
) -> dict:
    """Validate source bytes even on cache hits; never repair or overwrite a cache."""
    pdf_sha256 = validate_sha256(pdf_sha256)
    if any(part.is_symlink() for part in (cache_directory, *cache_directory.parents)):
        raise ValueError("Cache directory must not contain symbolic links")
    data = read_bounded_bytes(raw_path, boundary=raw_boundary, max_bytes=max_pdf_bytes)
    if hashlib.sha256(data).hexdigest() != pdf_sha256 or len(data) < 2:
        raise ValueError("Source bytes differ from the locked PDF checksum")
    cache_directory.mkdir(parents=True, exist_ok=True)
    path = cache_directory / f"{pdf_sha256}.npy"
    metadata_path = cache_directory / f"{pdf_sha256}.json"
    expected = {"algorithm": MARKOV_ALGORITHM, "pdf_sha256": pdf_sha256, "pdf_bytes": len(data), "shape": list(MARKOV_SHAPE), "dtype": "float32"}
    if path.exists() or metadata_path.exists() or path.is_symlink() or metadata_path.is_symlink():
        _, metadata = load_cached_markov_pdf(pdf_sha256, cache_directory=cache_directory)
        if metadata["pdf_bytes"] != len(data):
            raise ValueError("Cache PDF byte count differs from its source")
        digest = metadata["npy_sha256"]
        status = "reused"
    else:
        matrix = byte_transition_matrix(data)
        buffer = io.BytesIO()
        np.save(buffer, matrix, allow_pickle=False)
        content = buffer.getvalue()
        load_markov_npy(content)
        digest = hashlib.sha256(content).hexdigest()
        metadata = {**expected, "npy_sha256": digest}
        _publish_new(path, content)
        _publish_new(metadata_path, (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode())
        status = "created"
    return {"path": path, "metadata_path": metadata_path, "npy_sha256": digest, "status": status, "pdf_bytes": len(data)}
