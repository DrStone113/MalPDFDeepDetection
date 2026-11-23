from scripts.lab.export_pooled_bulk_inputs import TABULAR_FEATURES, pooled_table


def test_pool_retains_observed_zero_and_keeps_unmeasured_values_null():
    row = {
        "features": {
            TABULAR_FEATURES[0]: {"value": 0, "status": "absent_within_scope"},
            TABULAR_FEATURES[1]: {"value": 19, "status": "resource_limit"},
        },
        "sample_disposition": "graph_and_tabular",
    }
    assert pooled_table(row) == [0, *([None] * (len(TABULAR_FEATURES) - 1))]


def test_pool_rejects_inputs_with_unverified_worker_cleanup():
    row = {
        "features": {name: {"value": 1, "status": "observed"} for name in TABULAR_FEATURES},
        "sample_disposition": "rejected_unverified_cleanup",
    }
    assert pooled_table(row) == [None] * len(TABULAR_FEATURES)
