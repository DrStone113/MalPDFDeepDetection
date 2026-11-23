import pytest

from scripts.lab.build_clean_splits import connected_groups, assign_roles, vector_key


def test_exact_vectors_connect_tls_components_even_through_an_unmeasured_record():
    vectors = [[0, 2], [-0.0, 2], [None, 2], [None, 2], [3, 4], [3, 4]]
    groups = connected_groups(vectors, [0, 2, 3, 4], [0, 1, 1, 1])
    assert groups[0] == groups[1]
    assert groups[2] == groups[3] == groups[4] == groups[5]
    assert groups[0] != groups[2]
    assert vector_key([None, None]) is None
    assert vector_key([None, 2]) != vector_key([0, 2])


def test_unlabeled_rows_related_to_evaluation_cannot_train():
    labels = [i % 2 for i in range(24)] + [None] * 25 + [0]
    groups = list(range(24)) + list(range(24)) + [24, 1]
    measured = set(range(len(labels) - 1))
    roles = assign_roles(labels, groups, measured, seed=42)
    for i in range(24):
        assert roles[i + 24] == ('train' if roles[i] == 'train' else 'held_out_unlabeled')
    assert roles[48:] == ['train', 'pending_fingerprint']
    assert set(roles[:24]) == {'train', 'val_select', 'val_calib', 'test_internal'}


def test_component_results_must_have_valid_length_and_representatives():
    with pytest.raises(ValueError, match='invalid_tls_components'):
        connected_groups([[0], [1]], [0, 1], [1])
    with pytest.raises(ValueError, match='invalid_tls_components'):
        connected_groups([[0], [1]], [0, 1], [1, 3])
