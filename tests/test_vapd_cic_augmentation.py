import numpy as np
import pytest

from scripts.lab.run_cic_vapd_augmentation import pick_supplement


def test_supplement_uses_balanced_complete_train_without_cic_aliases():
    ids = ["same_cic", "normal_a", "normal_b", "malicious_a", "malicious_b",
           "test_row", "partial_row", "same_features", "validation_row"]
    table = np.arange(9, dtype=np.float32).reshape(-1, 1)
    table[7, 0] = 20
    roles = np.array([0, 0, 0, 0, 0, 2, 0, 0, 1])
    labels = np.array([0, 0, 0, 1, 1, 0, 1, 1, 1])
    complete = np.array([True] * 6 + [False, True, True])
    cic = np.array([[20]], dtype=np.float32)
    chosen = pick_supplement(ids, table, roles, labels, complete, {"same_cic"}, cic, 1)
    assert {ids[i] for i in chosen} <= {"normal_a", "normal_b", "malicious_a", "malicious_b"}
    assert sorted(labels[chosen]) == [0, 1]
    order = np.arange(len(ids))[::-1]
    reversed_ids = [ids[i] for i in order]
    repeated = pick_supplement(reversed_ids, table[order], roles[order], labels[order],
                               complete[order], {"same_cic"}, cic, 1)
    assert [ids[i] for i in chosen] == [reversed_ids[i] for i in repeated]


def test_supplement_refuses_a_smaller_class_instead_of_silently_changing_dose():
    with pytest.raises(ValueError, match="class 1"):
        pick_supplement(["normal"], np.array([[0]], dtype=np.float32), np.array([0]),
                        np.array([0]), np.array([True]), set(), np.array([[1]], dtype=np.float32), 1)
