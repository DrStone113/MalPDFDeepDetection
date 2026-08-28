import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from malpdf.data.rit_pdfmal_split import (
    SplitValidationError,
    build_duplicate_group_ids,
    create_rit_pdfmal_split,
    validate_split_manifest,
)


def _fixture_frame() -> pd.DataFrame:
    rows = []
    for label, base in [(0, 0), (1, 100)]:
        for feature in range(base, base + 10):
            rows.extend(
                [
                    {"feature_a": feature, "feature_b": feature % 3, "Label": label},
                    {"feature_a": feature, "feature_b": feature % 3, "Label": label},
                ]
            )
    frame = pd.DataFrame(rows)
    frame.index = range(500, 500 + len(frame))
    return frame


def test_duplicate_group_ids_depend_on_features_not_dataframe_index():
    frame = _fixture_frame()

    group_ids = build_duplicate_group_ids(frame)

    assert group_ids.iloc[0] == group_ids.iloc[1]
    assert group_ids.iloc[0] != group_ids.iloc[2]
    reindexed = frame.copy()
    reindexed.index = range(900, 900 + len(frame))
    assert group_ids.tolist() == build_duplicate_group_ids(reindexed).tolist()


def test_split_is_deterministic_and_preserves_every_row_and_label():
    frame = _fixture_frame()
    original = frame.copy(deep=True)

    manifest_one, result_one = create_rit_pdfmal_split(frame, seed=42)
    manifest_two, result_two = create_rit_pdfmal_split(frame, seed=42)

    assert_frame_equal(manifest_one, manifest_two)
    assert result_one["split_statistics"] == result_two["split_statistics"]
    assert len(manifest_one) == len(frame)
    assert manifest_one["sample_id"].is_unique
    assert manifest_one["Label"].value_counts().to_dict() == frame["Label"].value_counts().to_dict()
    assert_frame_equal(frame, original)


def test_split_has_no_group_or_duplicate_leakage_and_assigns_once():
    frame = _fixture_frame()
    manifest, _ = create_rit_pdfmal_split(frame, seed=42)
    validation = validate_split_manifest(frame, manifest)

    assert validation["zero_group_overlap"]["is_valid"]
    assert validation["zero_feature_vector_duplicate_leakage"]["is_valid"]
    assert validation["all_rows_assigned_exactly_once"]["is_valid"]
    assert validation["target_labels_preserved"]["is_valid"]
    assert (manifest.groupby("duplicate_group_id")["split"].nunique() == 1).all()


def test_conflicting_labels_inside_one_duplicate_group_are_rejected():
    frame = pd.DataFrame(
        {
            "feature_a": [1, 1],
            "feature_b": [2, 2],
            "Label": [0, 1],
        }
    )

    with pytest.raises(SplitValidationError, match="multiple target labels"):
        create_rit_pdfmal_split(frame)
