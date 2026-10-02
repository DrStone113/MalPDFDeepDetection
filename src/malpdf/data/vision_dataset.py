"""Read-only Markov datasets and exact Protocol G sample-ID alignment."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
import hashlib
import io
from pathlib import Path, PurePosixPath

import pandas as pd
import torch
from torch.utils.data import Dataset

from malpdf.data.manifest_validator import validate_sha256
from malpdf.static.cache_manager import load_cached_markov_pdf
from malpdf.static.safety import read_bounded_bytes


@dataclass(frozen=True)
class VisionSample:
    sample_id: str
    label: int
    pdf_sha256: str
    related_group_id: str | None = None
    declared_split: str | None = None
    split: str | None = None
    npy_sha256: str | None = None


def load_vision_source_manifest(root: Path, path: Path, expected_sha256: str) -> list[VisionSample]:
    content = read_bounded_bytes(path, boundary=root / "data/processed", max_bytes=16 * 1024 * 1024)
    if hashlib.sha256(content).hexdigest() != validate_sha256(expected_sha256):
        raise ValueError("Vision source manifest differs from its checksum lock")
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig"), newline=""))
    header = reader.fieldnames or []
    if not {"sample_id", "Label", "pdf_relative_path", "pdf_sha256"}.issubset(header) or len(header) != len(set(header)):
        raise ValueError("Vision source manifest requires unique ID/label/PDF path/hash columns")
    result = []
    identifiers = set()
    hash_labels = {}
    for row in reader:
        if len(result) >= 100_000 or None in row or any(value is None for value in row.values()):
            raise ValueError("Invalid source manifest row or sample cap")
        identifier = row["sample_id"]
        if not identifier or identifier != identifier.strip() or identifier in identifiers or row["Label"] not in {"0", "1"}:
            raise ValueError("Source IDs must be unique and labels binary")
        identifiers.add(identifier)
        pdf_path = PurePosixPath(row["pdf_relative_path"])
        if pdf_path.is_absolute() or ".." in pdf_path.parts or "\\" in row["pdf_relative_path"] or pdf_path.suffix.lower() != ".pdf":
            raise ValueError("Source PDF paths must be safe repository-relative paths")
        pdf_sha = validate_sha256(row["pdf_sha256"])
        label = int(row["Label"])
        if pdf_sha in hash_labels and hash_labels[pdf_sha] != label:
            raise ValueError("Identical PDF hashes cannot have conflicting labels")
        hash_labels[pdf_sha] = label
        if "related_group_id" in row and not row["related_group_id"]:
            raise ValueError("Declared related groups must be nonempty")
        result.append(VisionSample(identifier, label, pdf_sha, row.get("related_group_id"), row.get("split")))
    if not result:
        raise ValueError("Vision source manifest cannot be empty")
    return result


def align_protocol_g_samples(samples: list[VisionSample], manifest: pd.DataFrame) -> tuple[dict | None, dict]:
    """Join by ID and label; reject partial mapping, PDF overlap and related leakage."""
    source_ids = {sample.sample_id for sample in samples}
    split_ids = set(manifest["sample_id"].astype(str))
    readiness = {"ready": False, "source_samples": len(samples), "protocol_g_samples": len(manifest), "matched_ids": len(source_ids & split_ids), "missing_source_ids": len(split_ids - source_ids), "foreign_source_ids": len(source_ids - split_ids)}
    if source_ids != split_ids:
        readiness["reason"] = "A complete PDF-to-Protocol-G ID mapping is unavailable"
        return None, readiness
    if not manifest.sample_id.is_unique or len(source_ids) != len(samples) or not manifest.split.isin(["train", "validation", "test"]).all():
        raise ValueError("Protocol G requires unique samples and known partitions")
    if "duplicate_group_id" not in manifest or (manifest.groupby("duplicate_group_id").split.nunique() > 1).any():
        raise ValueError("Feature-vector groups cross Protocol G partitions")
    mapping = manifest.set_index("sample_id")
    partitions = {name: [] for name in ("train", "validation", "test")}
    hash_partitions, related_partitions = {}, {}
    for sample in samples:
        row = mapping.loc[sample.sample_id]
        if sample.label != row["Label"] or sample.declared_split not in {None, row["split"]}:
            raise ValueError("Source label or partition contradicts Protocol G")
        split = str(row["split"])
        if sample.pdf_sha256 in hash_partitions and hash_partitions[sample.pdf_sha256] != split:
            raise ValueError("A duplicate PDF hash crosses Protocol G partitions")
        hash_partitions[sample.pdf_sha256] = split
        if sample.related_group_id is not None:
            if sample.related_group_id in related_partitions and related_partitions[sample.related_group_id] != split:
                raise ValueError("Related PDF samples cross Protocol G partitions")
            related_partitions[sample.related_group_id] = split
        partitions[split].append(replace(sample, split=split))
    if any({sample.label for sample in subset} != {0, 1} for subset in partitions.values()):
        raise ValueError("Official binary vision evaluation requires both classes in every partition")
    readiness.update({"ready": True, "reason": "Full ID/label match; PDF/related groups partition-disjoint", "partition_rows": {name: len(subset) for name, subset in partitions.items()}})
    return partitions, readiness


def verify_vision_caches(samples: list[VisionSample], cache_directory: Path) -> list[VisionSample]:
    verified = []
    for sample in samples:
        _, metadata = load_cached_markov_pdf(sample.pdf_sha256, cache_directory=cache_directory)
        verified.append(replace(sample, npy_sha256=metadata["npy_sha256"]))
    return verified


class MarkovCacheDataset(Dataset):
    """Lazy (1,256,256) tensors; cache integrity is checked on every access."""

    def __init__(self, samples: list[VisionSample], cache_directory: Path) -> None:
        if not samples or any(sample.npy_sha256 is None for sample in samples):
            raise ValueError("Dataset needs nonempty, preverified cache samples")
        self.samples = tuple(samples)
        self.cache_directory = cache_directory

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[index]
        matrix, metadata = load_cached_markov_pdf(sample.pdf_sha256, cache_directory=self.cache_directory)
        if metadata["npy_sha256"] != sample.npy_sha256:
            raise ValueError("Cache changed after vision preflight")
        return torch.from_numpy(matrix).unsqueeze(0), torch.tensor(sample.label, dtype=torch.float32)
