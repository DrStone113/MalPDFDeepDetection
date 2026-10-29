from pathlib import Path
import pytest
import pandas as pd
from malpdf.data.cross_dataset_loader import load_aligned_datasets, safe_div

REPO = Path(__file__).resolve().parents[1]


def test_safe_div():
    a = pd.Series([10.0, 5.0, 0.0])
    b = pd.Series([2.0, 0.0, 4.0])
    res = safe_div(a, b)
    assert res.iloc[0] == 5.0
    assert res.iloc[1] == 5.0
    assert res.iloc[2] == 0.0


def test_load_aligned_datasets_structure():
    rit_df, cic_df = load_aligned_datasets(REPO, include_ratios=True)
    assert len(rit_df) == 24337
    assert len(cic_df) == 1452
    assert "density_stream_ratio" in rit_df.columns
    assert "density_stream_ratio" in cic_df.columns
    assert "split" in rit_df.columns
    assert "split" in cic_df.columns
    assert set(rit_df["split"].unique()) == {"train", "test"}
    assert set(cic_df["split"].unique()) == {"train", "validation", "test"}


def test_load_aligned_datasets_no_startxref():
    rit_df, cic_df = load_aligned_datasets(REPO, include_ratios=True, exclude_startxref=True)
    assert "startxref" not in rit_df.columns
    assert "startxref" not in cic_df.columns
    assert "xref" not in rit_df.columns
    assert "xref" not in cic_df.columns

