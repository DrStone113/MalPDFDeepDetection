import pytest

from scripts.lab.screen_ember_pdf_near_duplicates import screen


def test_screen_excludes_boundary_matches_and_preserves_validation():
    validation = [{"label": "0", "sha256": "reference"}]
    test = [
        {"label": "0", "sha256": "same"},
        {"label": "1", "sha256": "near"},
        {"label": "1", "sha256": "retained"},
    ]

    retained, excluded = screen(validation, test, [0, 30, 31])

    assert retained == [validation[0], test[2]]
    assert excluded == {"0": 1, "1": 1}


@pytest.mark.parametrize("distances", [[], [-1], [31, 31]])
def test_screen_rejects_incomplete_or_invalid_distance_results(distances):
    with pytest.raises(ValueError, match="invalid_TLSH_distance_results"):
        screen([{"label": "0"}], [{"label": "1"}], distances)
