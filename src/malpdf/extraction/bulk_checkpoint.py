"""Verify published numeric artifacts before adopting or comparing them."""

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
from zipfile import ZipFile

from malpdf.data.graph_contract import index_measured_graphs_v2
from malpdf.extraction.graph_audit import canonical_bytes


TABULAR = "tabular_features_v2.jsonl.gz"
GRAPHS = "hetero_graphs_v2.jsonl.gz"
UNAVAILABLE = "unavailable_records.json"
MARKOV = "markov_f32.npz"
MARKOV_SHAS = "markov_shas.json"
CHUNK_FILES = {TABULAR, GRAPHS, UNAVAILABLE}
MARKOV_FILES = {MARKOV, MARKOV_SHAS}
FINAL_FILES = {TABULAR, GRAPHS, "unavailable_document_ledger.json", "corpus_metadata.csv",
               "markov_manifest.json", "summary.json"}
SHA = re.compile(r"[0-9a-f]{64}\Z")


def file_sha256(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def matches_checkpoint(directory, expected):
    marker = directory / "chunk_done.json"
    return (not directory.is_symlink() and not marker.is_symlink() and marker.is_file()
            and marker.stat().st_size <= 65536 and file_sha256(marker) == expected)


def replacement_archive(destination, expected):
    if not isinstance(expected, str) or not SHA.fullmatch(expected):
        raise ValueError("bulk_checkpoint_replacement_hash")
    return destination.with_name(f".{destination.name}.replaced-{expected}")


def verify_manifest(directory, marker, *, allowed):
    path = directory / marker
    if directory.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("bulk_checkpoint_marker")
    meta = json.loads(path.read_bytes())
    files = meta.get("files") if isinstance(meta, dict) else None
    if not isinstance(files, dict) or set(files) not in allowed:
        raise ValueError("bulk_checkpoint_files")
    for name, sha in files.items():
        payload = directory / name
        if (not isinstance(sha, str) or not SHA.fullmatch(sha) or payload.is_symlink()
                or not payload.is_file() or file_sha256(payload) != sha):
            raise ValueError(f"bulk_checkpoint_hash: {name}")
    return meta


def jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        yield from (json.loads(line) for line in stream if line.strip())


@dataclass
class Chunk:
    meta: dict
    tabular: list
    graphs: list
    unavailable: list
    markov_shas: list
    matrices: object


def read_chunk(directory, entries, *, chunk_id, include_markov, manifest=None):
    expected_files = CHUNK_FILES | (MARKOV_FILES if include_markov else set())
    if manifest is None:
        meta = verify_manifest(directory, "chunk_done.json", allowed=(expected_files,))
    else:
        meta = manifest
    if (meta.get("schema_version") != 1 or meta.get("chunk_id") != chunk_id
            or meta.get("count") != len(entries)):
        raise ValueError("bulk_checkpoint_identity")
    table = list(jsonl(directory / TABULAR))
    for entry, row in zip(entries, table, strict=True):
        if any(row[key] != getattr(entry, key) for key in ("sha256", "index", "source", "label", "label_source", "split")):
            raise ValueError("bulk_checkpoint_tabular_identity")
        if type(row["gnn_message_passing_eligible"]) is not bool:
            raise ValueError("bulk_checkpoint_eligibility")
    if Counter(row["status"] for row in table) != meta.get("status_counts"):
        raise ValueError("bulk_checkpoint_status_counts")

    eligible = [row for row in table if row["gnn_message_passing_eligible"]]
    other = [row for row in table if not row["gnn_message_passing_eligible"]]
    graphs = list(jsonl(directory / GRAPHS))
    unavailable = json.loads((directory / UNAVAILABLE).read_bytes())
    if (not isinstance(unavailable, list) or len(graphs) != meta.get("gnn_graphs")
            or len(unavailable) != meta.get("unavailable_graphs")):
        raise ValueError("bulk_checkpoint_partition_counts")
    index_measured_graphs_v2(graphs, {row["sha256"] for row in eligible})
    for graph, row in zip(graphs, eligible, strict=True):
        if any(graph.get(key) != row[key] for key in ("sha256", "index", "split", "label", "status")):
            raise ValueError("bulk_checkpoint_graph_identity")
    for missing, row in zip(unavailable, other, strict=True):
        fields = ("sha256", "index", "source", "label", "split", "sample_disposition", "evaluation_handling")
        if any(missing[key] != row[key] for key in fields) or missing["placeholder_nodes_inserted"] is not False:
            raise ValueError("bulk_checkpoint_unavailable_identity")

    shas, matrices = [], None
    if include_markov:
        import numpy as np

        shas = json.loads((directory / MARKOV_SHAS).read_bytes())
        if not isinstance(shas, list) or any(not isinstance(sha, str) for sha in shas):
            raise ValueError("bulk_checkpoint_markov_index")
        wanted = set(shas)
        if shas != [entry.sha256 for entry in entries if entry.sha256 in wanted]:
            raise ValueError("bulk_checkpoint_markov_identity")
        with ZipFile(directory / MARKOV) as container:
            if container.namelist() != ["matrices.npy"]:
                raise ValueError("bulk_checkpoint_markov_members")
            if container.getinfo("matrices.npy").file_size > len(shas) * 256 * 256 * 4 + 4096:
                raise ValueError("bulk_checkpoint_markov_size")
        with np.load(directory / MARKOV, allow_pickle=False) as archive:
            if archive.files != ["matrices"]:
                raise ValueError("bulk_checkpoint_markov_members")
            matrices = archive["matrices"]
        if matrices.shape != (len(shas), 256, 256) or matrices.dtype != np.float32:
            raise ValueError("bulk_checkpoint_markov_array")
        if not np.isfinite(matrices).all():
            raise ValueError("bulk_checkpoint_markov_nonfinite")
    if len(shas) != meta.get("markov_matrices"):
        raise ValueError("bulk_checkpoint_markov_count")
    return Chunk(meta, table, graphs, unavailable, shas, matrices)


def comparable_rows(chunk, selected):
    rows = {row["sha256"]: {"tabular": row, "graph": None, "unavailable": None, "markov": None}
            for row in chunk.tabular if row["sha256"] in selected}
    for key, records in (("graph", chunk.graphs), ("unavailable", chunk.unavailable)):
        for record in records:
            if record["sha256"] in rows:
                rows[record["sha256"]][key] = record
    for i, sha in enumerate(chunk.markov_shas):
        if sha in rows:
            rows[sha]["markov"] = chunk.matrices[i].tobytes()
    return rows


def different_artifacts(baseline, candidate):
    return [name for name in ("tabular", "graph", "unavailable", "markov")
            if ((baseline[name] != candidate[name]) if name == "markov"
                else (canonical_bytes(baseline[name]) != canonical_bytes(candidate[name])))]


@contextmanager
def output_lock(output):
    if any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError("bulk_output_symlink")
    output.mkdir(parents=True, exist_ok=True)
    path = output / ".writer.lock"
    if path.is_symlink():
        raise ValueError("bulk_output_lock_symlink")
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


@contextmanager
def publication(destination, *, replace_checkpoint=None):
    if destination.is_symlink():
        raise ValueError("bulk_output_symlink")
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent))
    yield staging
    if replace_checkpoint is not None:
        archive = replacement_archive(destination, replace_checkpoint)
        if destination.exists():
            if archive.exists() or archive.is_symlink() or not matches_checkpoint(destination, replace_checkpoint):
                raise ValueError("bulk_checkpoint_replacement_changed")
            destination.rename(archive)
        elif not matches_checkpoint(archive, replace_checkpoint):
            raise ValueError("bulk_checkpoint_replacement_missing")
    elif destination.exists():
        destination.rename(destination.with_name(f".{destination.name}.interrupted-{uuid.uuid4().hex}"))
    staging.rename(destination)
