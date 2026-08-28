"""Protocol P data infrastructure for paper-aligned reproduction attempts.

Protocol P intentionally uses a row-level stratified random 75/25 split because
that is what the paper reports. It is not an exact reproduction: the paper does
not publish a random seed, complete preprocessing details, or hyperparameters.
The project default seed (42) is therefore a project choice, never a paper seed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_split import build_deterministic_sample_ids

TARGET_COLUMN = "Label"
DEFAULT_PROTOCOL_P_SEED = 42
PROTOCOL_P_TEST_PROPORTION = 0.25
PROTOCOL_P_CONSTANT_FEATURES = ("Acroform", "Colors", "BaseEncoding")


class ProtocolPSplitError(ValueError):
    """Raised when a Protocol P split or manifest violates an invariant."""


@dataclass(frozen=True)
class FeatureVariant:
    """A named, explicit feature set for Protocol P."""

    name: str
    description: str
    removed_columns: tuple[str, ...]


P_ALL41 = FeatureVariant(
    name="P-all41",
    description="All 41 published local non-hash predictive features; no feature removal.",
    removed_columns=(),
)
P_DROP3CONSTANT = FeatureVariant(
    name="P-drop3constant",
    description="Only the paper-described constant-zero columns are removed.",
    removed_columns=PROTOCOL_P_CONSTANT_FEATURES,
)
FEATURE_VARIANTS = {P_ALL41.name: P_ALL41, P_DROP3CONSTANT.name: P_DROP3CONSTANT}


def protocol_p_feature_columns(frame: pd.DataFrame, variant_name: str) -> list[str]:
    """Return an ordered, unmodified feature view for a named Protocol P variant."""
    if TARGET_COLUMN not in frame.columns:
        raise ProtocolPSplitError(f"Expected target column {TARGET_COLUMN!r} is absent")
    try:
        variant = FEATURE_VARIANTS[variant_name]
    except KeyError as error:
        raise ProtocolPSplitError(f"Unknown Protocol P feature variant: {variant_name}") from error

    all_features = [column for column in frame.columns if column != TARGET_COLUMN]
    if len(all_features) != 41:
        raise ProtocolPSplitError(
            f"Protocol P expects 41 predictive columns, found {len(all_features)}"
        )
    missing_constants = [column for column in variant.removed_columns if column not in all_features]
    if missing_constants:
        raise ProtocolPSplitError(f"Expected constant columns are absent: {missing_constants}")
    selected = [column for column in all_features if column not in variant.removed_columns]
    expected_count = 41 - len(variant.removed_columns)
    if len(selected) != expected_count:
        raise ProtocolPSplitError("Feature variant selection produced an unexpected column count")
    return selected


def protocol_p_feature_view(frame: pd.DataFrame, variant_name: str) -> pd.DataFrame:
    """Select features only; values, special signals, and row order are untouched."""
    return frame.loc[:, protocol_p_feature_columns(frame, variant_name)]


def _label_distribution(series: pd.Series) -> list[dict[str, Any]]:
    total = len(series)
    return [
        {
            "raw_label": int(label),
            "count": int(count),
            "percentage": 0.0 if total == 0 else round(int(count) * 100 / total, 6),
        }
        for label, count in series.value_counts(sort=False).items()
    ]


def _split_statistics(manifest: pd.DataFrame) -> dict[str, dict[str, Any]]:
    total_rows = len(manifest)
    result: dict[str, dict[str, Any]] = {}
    for split_name in ("train", "test"):
        subset = manifest.loc[manifest["split"] == split_name]
        result[split_name] = {
            "row_count": int(len(subset)),
            "percentage_of_rows": round(len(subset) * 100 / total_rows, 6),
            "label_distribution": _label_distribution(subset[TARGET_COLUMN]),
            "benign_label_0_count": int((subset[TARGET_COLUMN] == 0).sum()),
            "malicious_label_1_count": int((subset[TARGET_COLUMN] == 1).sum()),
        }
    return result


def validate_protocol_p_manifest(frame: pd.DataFrame, manifest: pd.DataFrame) -> dict[str, Any]:
    """Verify row-level assignment, disjointness, stratification, and label fidelity."""
    required = {"sample_id", "split", TARGET_COLUMN, "seed", "dataset_sha256"}
    missing = required.difference(manifest.columns)
    if missing:
        raise ProtocolPSplitError(f"Manifest is missing columns: {sorted(missing)}")
    if TARGET_COLUMN not in frame.columns:
        raise ProtocolPSplitError(f"Expected target column {TARGET_COLUMN!r} is absent")

    source_ids = build_deterministic_sample_ids(frame).astype(str)
    source = pd.DataFrame(
        {"sample_id": source_ids.to_numpy(copy=False), TARGET_COLUMN: frame[TARGET_COLUMN].to_numpy(copy=False)}
    )
    if not manifest["sample_id"].is_unique:
        raise ProtocolPSplitError("Manifest sample identifiers must be unique")
    if not manifest["split"].isin(("train", "test")).all():
        raise ProtocolPSplitError("Manifest split values must be exactly train or test")

    source_id_set = set(source["sample_id"])
    train_ids = set(manifest.loc[manifest["split"] == "train", "sample_id"].astype(str))
    test_ids = set(manifest.loc[manifest["split"] == "test", "sample_id"].astype(str))
    merged = source.merge(
        manifest.loc[:, ["sample_id", TARGET_COLUMN]],
        on="sample_id",
        how="outer",
        validate="one_to_one",
        suffixes=("_source", "_manifest"),
        indicator=True,
    )
    labels_preserved = bool(
        (merged["_merge"] == "both").all()
        and (merged[f"{TARGET_COLUMN}_source"] == merged[f"{TARGET_COLUMN}_manifest"]).all()
    )
    all_assigned = (
        len(manifest) == len(frame)
        and set(manifest["sample_id"].astype(str)) == source_id_set
        and len(train_ids) + len(test_ids) == len(frame)
    )
    split_statistics = _split_statistics(manifest)
    source_distribution = _label_distribution(frame[TARGET_COLUMN])
    class_proportions_approximately_preserved = all(
        abs(
            next(item["percentage"] for item in split_statistics[split_name]["label_distribution"] if item["raw_label"] == label)
            - next(item["percentage"] for item in source_distribution if item["raw_label"] == label)
        )
        <= 0.1
        for split_name in ("train", "test")
        for label in (0, 1)
    )
    validation = {
        "all_rows_assigned_exactly_once": {"is_valid": all_assigned, "source_row_count": int(len(frame)), "manifest_row_count": int(len(manifest))},
        "train_test_disjoint": {"is_valid": len(train_ids.intersection(test_ids)) == 0, "overlap_count": len(train_ids.intersection(test_ids))},
        "target_labels_preserved": {"is_valid": labels_preserved, "source_distribution": source_distribution, "manifest_distribution": _label_distribution(manifest[TARGET_COLUMN])},
        "stratification": {"is_valid": class_proportions_approximately_preserved, "tolerance_percentage_points": 0.1, "split_statistics": split_statistics},
    }
    if not all(item["is_valid"] for item in validation.values()):
        raise ProtocolPSplitError(f"Protocol P manifest validation failed: {validation}")
    return validation


def create_protocol_p_split(
    frame: pd.DataFrame,
    dataset_sha256: str,
    *,
    seed: int = DEFAULT_PROTOCOL_P_SEED,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Create the distinct Protocol P random 75/25 stratified split manifest.

    It intentionally does not group equal feature vectors, unlike Protocol G.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ProtocolPSplitError("Protocol P seed must be an integer")
    if TARGET_COLUMN not in frame.columns:
        raise ProtocolPSplitError(f"Expected target column {TARGET_COLUMN!r} is absent")
    if frame[TARGET_COLUMN].isna().any():
        raise ProtocolPSplitError("Protocol P requires non-missing labels for stratification")

    sample_ids = build_deterministic_sample_ids(frame).astype(str).to_numpy(copy=False)
    train_ids, test_ids = train_test_split(
        sample_ids,
        test_size=PROTOCOL_P_TEST_PROPORTION,
        random_state=seed,
        shuffle=True,
        stratify=frame[TARGET_COLUMN].to_numpy(copy=False),
    )
    train_id_set = set(train_ids)
    manifest = pd.DataFrame(
        {
            "sample_id": sample_ids,
            "split": ["train" if sample_id in train_id_set else "test" for sample_id in sample_ids],
            TARGET_COLUMN: frame[TARGET_COLUMN].to_numpy(copy=False),
            "seed": seed,
            "dataset_sha256": dataset_sha256,
        }
    )
    validation = validate_protocol_p_manifest(frame, manifest)
    result = {
        "protocol": "P",
        "purpose": "Paper-aligned reproduction attempt, not an exact paper reproduction.",
        "split_algorithm": "sklearn.model_selection.train_test_split with shuffle=True, stratify=Label, test_size=0.25, and project-selected random_state.",
        "paper_seed_status": "The paper does not publish a split seed; this seed is a project choice.",
        "seed": seed,
        "dataset_sha256": dataset_sha256,
        "split_proportions": {"train": 0.75, "test": 0.25},
        "split_statistics": _split_statistics(manifest),
        "validation": validation,
        "feature_variants": [asdict(variant) for variant in FEATURE_VARIANTS.values()],
    }
    return manifest, result


def _assert_protocol_p_destination(path: Path) -> None:
    normalized_parts = {part.casefold() for part in path.parts}
    if "protocol_p" not in normalized_parts:
        raise ProtocolPSplitError(
            "Protocol P outputs must be written below a protocol_p directory; refusing an ambiguous destination"
        )
    if "protocol_g" in normalized_parts or path.name == "rit-pdfmal-2026_split_manifest.csv":
        raise ProtocolPSplitError("Refusing to write a Protocol P artifact over a Protocol G path")


def write_protocol_p_manifest(manifest: pd.DataFrame, destination: str | Path) -> None:
    """Write a new Protocol P manifest only to a dedicated, non-existing path."""
    output = Path(destination)
    _assert_protocol_p_destination(output)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing Protocol P manifest: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.to_csv(output, index=False)


def create_protocol_p_split_from_file(
    dataset_path: str | Path, *, seed: int = DEFAULT_PROTOCOL_P_SEED
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load through the existing RIT loader and produce a Protocol P manifest in memory."""
    path = Path(dataset_path)
    return create_protocol_p_split(load_rit_pdfmal(path), sha256_file(path), seed=seed)
