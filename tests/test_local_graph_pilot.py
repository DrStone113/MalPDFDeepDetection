from scripts.lab.run_local_graph_pilot import summarize_pilot


def test_pilot_counts_unlabeled_alerts_and_uses_the_fixed_cluster_representative():
    rows = [
        dict(sha256="a", cluster="a", group="govdocs1_review", label=None, status="encrypted"),
        dict(sha256="b", cluster="b", group="vapd_d1_positive", label=1, status="bounded_complete"),
        dict(sha256="c", cluster="b", group="vapd_d1_positive", label=1, status="unsupported"),
    ]

    assert summarize_pilot(rows, [0.5, 0.49, 0.99], 0.5) == {
        "govdocs1_review": {
            "n": 1, "alerts": 1, "representatives": 1, "representative_alerts": 1,
            "alerts_by_extraction_status": {"encrypted": 1},
        },
        "vapd_d1_positive": {
            "n": 2, "alerts": 1, "representatives": 1, "representative_alerts": 0,
            "alerts_by_extraction_status": {"unsupported": 1},
        },
    }
