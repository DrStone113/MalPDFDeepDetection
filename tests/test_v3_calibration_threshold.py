import pytest

from malpdf.evaluation.operating_point import midpoint_macro_f1


def test_threshold_uses_midpoint_of_full_optimal_gap():
    result = midpoint_macro_f1([0, 0, 1, 1], [0.01, 0.2, 0.8, 0.9])
    assert result['interval'] == [0.2, 0.8]
    assert result['threshold'] == pytest.approx(0.5)
    assert result['f1_macro'] == 1.0


def test_tied_scores_cannot_be_split_between_classes():
    result = midpoint_macro_f1([0, 1, 0, 1], [0.1, 0.5, 0.5, 0.9])
    assert result['interval'] == [0.1, 0.9]
    assert result['threshold'] == pytest.approx(0.5)
    assert result['f1_macro'] == pytest.approx(11 / 15)


def test_invalid_calibration_input_is_rejected():
    with pytest.raises(ValueError, match='calibration'):
        midpoint_macro_f1([1, 1], [0.3, 0.9])
    with pytest.raises(ValueError, match='calibration'):
        midpoint_macro_f1([0, 1], [0.3, float('nan')])


def test_max_threshold_restricts_selection_without_changing_default():
    labels = [0, 0, 1, 0, 1, 1, 1, 1]
    scores = [0.01, 0.02, 0.20, 0.70, 0.90, 0.91, 0.92, 0.93]
    unbounded = midpoint_macro_f1(labels, scores)
    assert unbounded['interval'] == pytest.approx([0.70, 0.90])
    assert unbounded['threshold'] == pytest.approx(0.80)

    bounded = midpoint_macro_f1(labels, scores, max_threshold=0.50)
    assert bounded['interval'] == pytest.approx([0.02, 0.20])
    assert bounded['threshold'] == pytest.approx(0.11)

    clipped = midpoint_macro_f1([0, 0, 1, 1], [0.01, 0.02, 0.80, 0.90], max_threshold=0.50)
    assert clipped['interval'] == pytest.approx([0.02, 0.50])
    assert clipped['threshold'] == pytest.approx(0.26)

    for bad in (0.0, -0.1, 1.1, float('nan')):
        with pytest.raises(ValueError, match='invalid_max_threshold'):
            midpoint_macro_f1([0, 1], [0.1, 0.9], max_threshold=bad)
