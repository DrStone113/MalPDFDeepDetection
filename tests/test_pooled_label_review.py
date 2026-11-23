import pytest

from scripts.lab.train_pooled_transgraph_label_review import reviewed_training_rows


def test_disputed_label_is_excluded_and_other_source_labels_are_preserved():
    samples = [
        dict(sha256="a" * 64, label=1, source="vapd_v5_d1_malicious"),
        dict(sha256="b" * 64, label=0, source="vapd_v5_d1_benign"),
    ]
    dispute = dict(sha256="a" * 64, pooled_label=1, cic_label=0, pooled_source="vapd_v5_d1_malicious")

    assert reviewed_training_rows(samples, [dispute]) == samples[1:]
    assert samples[0]["label"] == 1


@pytest.mark.parametrize("changes", [
    {"pooled_label": 0}, {"cic_label": 1}, {"pooled_source": "cic_protocol_g_verified"}, {"sha256": "c" * 64},
])
def test_dispute_must_match_existing_identity_and_source_label(changes):
    sample = dict(sha256="a" * 64, label=1, source="vapd_v5_d1_malicious")
    dispute = dict(sha256=sample["sha256"], pooled_label=1, cic_label=0, pooled_source=sample["source"])

    with pytest.raises(ValueError, match="label_dispute"):
        reviewed_training_rows([sample], [dispute | changes])


def test_repeated_dispute_cannot_silently_change_exclusion_count():
    sample = dict(sha256="a" * 64, label=1, source="vapd_v5_d1_malicious")
    dispute = dict(sha256=sample["sha256"], pooled_label=1, cic_label=0, pooled_source=sample["source"])

    with pytest.raises(ValueError, match="label_dispute"):
        reviewed_training_rows([sample], [dispute, dispute])
