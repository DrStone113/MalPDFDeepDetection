import pandas as pd

from malpdf.data.rit_pdfmal_paper_alignment import _special_value_audit, _stat_status


def test_statistic_status_classifies_exact_rounding_and_material_differences():
    assert _stat_status("minimum", 0.0, 0.0) == "exact match"
    assert _stat_status("mean", 1.004, 1.0) == "rounding-level difference"
    assert _stat_status("mean", 1.1, 1.0) == "material mismatch"
    assert _stat_status("standard_deviation", 2.0, 2.0, local_variance=4.0) == "exact match"


def test_special_value_audit_reports_documented_signals_without_transforming_values():
    frame = pd.DataFrame(
        {
            "contains_text": [-1, 0, 1],
            "images": [-1, 0, 2],
            "pages": [0, 1, 2],
            "pdf_ver": [0.0, 1.7, 5.0],
            "Label": [0, 0, 1],
        }
    )
    original = frame.copy(deep=True)

    audit = _special_value_audit(frame)

    assert audit["contains_text"]["local_counts"] == {"-1": 1, "0": 1, "1": 1}
    assert audit["contains_text"]["label_distribution_for_negative_one"] == {"0": 1}
    assert audit["images"]["local_negative_one_count"] == 1
    assert audit["pages"]["local_zero_count"] == 1
    assert audit["pdf_ver"]["local_greater_than_2_count"] == 1
    pd.testing.assert_frame_equal(frame, original)
