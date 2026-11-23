from scripts.lab.holdout_fingerprint_screen import screen


def test_definite_duplicates_are_filtered_with_incomplete_reference():
    a, b, c, d, e = (letter * 64 for letter in "abcde")
    known, query = "T1" + "0" * 70, "T1" + "1" * 70
    reference = {a: known, b: None}
    candidates = {b: None, c: query, d: query, e: None}

    result = screen(reference, candidates, lambda refs, queries: [30, 31])

    assert result == {
        b: {"disposition": "exact_duplicate", "distance": None},
        c: {"disposition": "near_duplicate", "distance": 30},
        d: {"disposition": "reference_coverage_incomplete", "distance": 31},
        e: {"disposition": "candidate_fingerprint_unavailable", "distance": None},
    }


def test_complete_reference_clears_only_candidates_above_threshold():
    a, b, c = (letter * 64 for letter in "abc")
    known, query = "T1" + "0" * 70, "T1" + "1" * 70

    result = screen({a: known}, {b: query, c: query}, lambda refs, queries: [0, 31])

    assert result[b]["disposition"] == "near_duplicate"
    assert result[c]["disposition"] == "no_near_duplicate_in_reference"


def test_empty_measured_reference_blocks_candidate_without_calling_engine():
    digest = "T1" + "1" * 70

    def unexpected(*args):
        raise AssertionError("No measured reference was supplied")

    result = screen({"a" * 64: None}, {"b" * 64: digest}, unexpected)

    assert result["b" * 64] == {"disposition": "reference_coverage_incomplete", "distance": None}
