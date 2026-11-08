from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from malpdf.extraction.contracts import feature


SAMPLE_SHA256 = "a" * 64
PRIVATE_SENTINEL = "SENSITIVE_SENTINEL_DO_NOT_EXPORT"


@pytest.fixture
def project():
    return importlib.import_module("malpdf.extraction.numeric_export").project_numeric_bundle


def _bundle() -> dict:
    return {
        "sample_sha256": SAMPLE_SHA256,
        "status": "partial",
        "feature_store": {
            "records": [
                feature("canonical_pdfsize", "raw_layout", 20.5, "observed", ["root"], PRIVATE_SENTINEL, complete=True),
                feature("lexical_JS", "javascript_xfa", 0, "absent_within_scope", ["root"], PRIVATE_SENTINEL, complete=True),
                feature("legacy_observed_ast_node_count", "javascript_xfa", None, "not_run", [], PRIVATE_SENTINEL),
            ],
            "raw_exception": PRIVATE_SENTINEL,
        },
        "evidence_store": {
            "records": [
                {
                    "evidence_id": "root",
                    "kind": "catalog",
                    "observation_status": "observed",
                    "details": {"size_bytes": None, "raw_text": PRIVATE_SENTINEL, "script": PRIVATE_SENTINEL},
                },
            ],
            "edges": [],
        },
        "coverage_report": {
            "worker": {"worker_cleanup_complete": False, "peak_rss_bytes": 1024, "raw_exception": PRIVATE_SENTINEL},
            "provenance": {"source_path": PRIVATE_SENTINEL},
        },
        "extracted_strings": [PRIVATE_SENTINEL],
        "payload": PRIVATE_SENTINEL,
    }


def test_numeric_projection_has_closed_schema_and_no_document_text(project) -> None:
    source = _bundle()
    before = deepcopy(source)
    exported = project(source, SAMPLE_SHA256)
    assert set(exported) == {"schema_version", "sample_sha256", "status", "features", "graph", "worker", "excluded_feature_count"}
    assert exported["sample_sha256"] == SAMPLE_SHA256
    assert exported["status"] == "partial"
    serialized = json.dumps(exported, allow_nan=False)
    assert PRIVATE_SENTINEL not in serialized
    for forbidden_key in ("raw_text", "script", "source_path", "raw_exception", "payload", "extracted_strings"):
        assert forbidden_key not in serialized
    for observation in exported["features"].values():
        assert set(observation) == {"value", "status", "scope_complete"}
    assert source == before


def test_numeric_projection_preserves_observed_absence_without_imputing_missing_values(project) -> None:
    exported = project(_bundle(), SAMPLE_SHA256)
    assert exported["features"]["canonical_pdfsize"] == {"value": 20.5, "status": "observed", "scope_complete": True}
    assert exported["features"]["lexical_JS"] == {"value": 0, "status": "absent_within_scope", "scope_complete": True}
    assert exported["features"]["legacy_observed_ast_node_count"] == {"value": None, "status": "not_run", "scope_complete": False}


def test_numeric_projection_does_not_promote_partial_observations(project) -> None:
    source = _bundle()
    source["feature_store"]["records"][0].update(value=12.5, observation_status="partial", scope_complete=False)
    exported = project(source, SAMPLE_SHA256)
    assert exported["features"]["canonical_pdfsize"] == {"value": 12.5, "status": "partial", "scope_complete": False}


def test_unknown_node_size_stays_unknown_and_blocks_model_inputs(project) -> None:
    exported = project(_bundle(), SAMPLE_SHA256)
    assert exported["graph"]["node_types"] == [0]
    assert exported["graph"]["node_sizes_bytes"] == [None]
    assert exported["graph"]["edge_src"] == []
    assert exported["graph"]["edge_dst"] == []
    assert exported["graph"]["edge_rel"] == []
    assert exported["graph"]["model_input_ready"] is False


@pytest.mark.parametrize("size", [True, False, float("nan"), float("inf")])
def test_invalid_node_sizes_remain_unknown_instead_of_numeric_zero(project, size) -> None:
    source = _bundle()
    source["evidence_store"]["records"][0]["details"]["size_bytes"] = size
    exported = project(source, SAMPLE_SHA256)
    assert exported["graph"]["node_sizes_bytes"] == [None]
    assert exported["graph"]["model_input_ready"] is False


def test_worker_projection_preserves_cleanup_failure_and_numeric_metrics(project) -> None:
    exported = project(_bundle(), SAMPLE_SHA256)
    assert exported["worker"]["worker_cleanup_complete"] is False
    assert exported["worker"]["peak_rss_bytes"] == 1024
    assert all(type(value) in (int, float, bool, type(None)) for value in exported["worker"].values())


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), "unreviewed text"])
def test_invalid_numeric_feature_values_are_rejected(project, value) -> None:
    source = _bundle()
    source["feature_store"]["records"][0]["value"] = value
    with pytest.raises(ValueError):
        project(source, SAMPLE_SHA256)


def test_numeric_projection_is_bound_to_expected_document_hash(project) -> None:
    with pytest.raises(ValueError):
        project(_bundle(), "b" * 64)


def test_dynamic_feature_names_are_excluded_from_the_export_schema(project) -> None:
    source = _bundle()
    dynamic_name = "script:payload:ast:node_count"
    source["feature_store"]["records"].append(feature(dynamic_name, "javascript_xfa", 12, "observed", ["root"], PRIVATE_SENTINEL))
    exported = project(source, SAMPLE_SHA256)
    assert dynamic_name not in exported["features"]
    assert exported["excluded_feature_count"] == 1


def test_safe_looking_feature_prefix_cannot_export_arbitrary_source_text(project) -> None:
    source = _bundle()
    name = "raw_" + PRIVATE_SENTINEL
    source["feature_store"]["records"].append(feature(name, "raw_layout", 1, "observed", ["root"], PRIVATE_SENTINEL))
    exported = project(source, SAMPLE_SHA256)
    assert name not in exported["features"]
    assert PRIVATE_SENTINEL not in json.dumps(exported)
    assert exported["excluded_feature_count"] == 1


def test_received_projection_rejects_arbitrary_prefixed_feature_names(project) -> None:
    exported = project(_bundle(), SAMPLE_SHA256)
    exported["features"]["raw_" + PRIVATE_SENTINEL] = {"value": 1, "status": "observed", "scope_complete": True}
    validate = importlib.import_module("malpdf.extraction.numeric_export").validate_numeric_projection
    with pytest.raises(ValueError):
        validate(exported, SAMPLE_SHA256)


def test_unknown_node_kind_cannot_become_a_fabricated_zero_graph(project) -> None:
    source = _bundle()
    source["evidence_store"]["records"][0].update(kind="unknown_node")
    exported = project(source, SAMPLE_SHA256)
    assert exported["graph"]["node_types"] == []
    assert exported["graph"]["node_sizes_bytes"] == []
    assert exported["graph"]["model_input_ready"] is False


def test_unavailable_nodes_cannot_be_exported_as_observed_model_nodes(project) -> None:
    source = _bundle()
    source["evidence_store"]["records"][0].update(observation_status="unsupported")
    source["evidence_store"]["records"][0]["details"]["size_bytes"] = 128
    exported = project(source, SAMPLE_SHA256)
    assert exported["graph"]["node_types"] == []
    assert exported["graph"]["model_input_ready"] is False


def test_observed_graph_edges_keep_their_real_numeric_endpoints(project) -> None:
    source = _bundle()
    source["evidence_store"]["records"].append({
        "evidence_id": "page",
        "kind": "page",
        "observation_status": "observed",
        "details": {"size_bytes": 128},
    })
    source["evidence_store"]["edges"].append({
        "id": "root-to-page",
        "source": "root",
        "target": "page",
        "kind": "pdf_reference",
        "status": "derived",
        "raw_text": PRIVATE_SENTINEL,
    })
    exported = project(source, SAMPLE_SHA256)
    assert exported["graph"]["node_types"] == [0, 2]
    assert exported["graph"]["node_sizes_bytes"] == [None, 128]
    assert exported["graph"]["edge_src"] == [0]
    assert exported["graph"]["edge_dst"] == [1]
    assert len(exported["graph"]["edge_rel"]) == 1
    assert type(exported["graph"]["edge_rel"][0]) is int
    assert 0 <= exported["graph"]["edge_rel"][0] < 8
    assert PRIVATE_SENTINEL not in json.dumps(exported)


@pytest.fixture
def postrun_export(monkeypatch: pytest.MonkeyPatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts" / "lab"
    monkeypatch.syspath_prepend(str(scripts))
    module = importlib.import_module("export_numeric_postrun")
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="linux"))
    return module


def _postrun_source(tmp_path: Path, label=1) -> tuple[dict, Path, Path]:
    jobs = importlib.import_module("lab_jobs")
    job = jobs.make_job("a" * 40, "b" * 64, "c" * 64, mode="offline", kind="pdf-static-cve", attempt="1" * 32)
    job_root, export_root = tmp_path / "jobs", tmp_path / "exports"
    directory = job_root / job["job_id"]
    directory.mkdir(parents=True)
    (directory / "job.json").write_bytes(jobs.encoded(job))
    rows = [{"pdf_sha256": f"{index:064x}", "split": "train", "Label": label} for index in range(job["limits"]["samples"])]
    selection = {"job_id": job["job_id"], "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))}
    (directory / "selection.json").write_bytes(jobs.encoded(selection))
    summary = {"planned": len(rows), "completed": 0, "observed": 0, "bounded_complete": 0, "partial": 0, "failed": 0,
               "primary_available": 0, "timeout": 0, "elapsed_ms": 0, "peak_rss_bytes": 0, "status_counts": {}}
    environment = {"mode": "offline", "guest_network_checked": True, "stdlib_dependencies_checked": True, "hypervisor_controls_attested": True}
    result = jobs.result(job, "partial", summary=summary, environment=environment)
    (directory / "result.json").write_bytes(jobs.encoded(result))
    return job, job_root, export_root


def test_postrun_export_keeps_missing_samples_without_fabricating_measurements(postrun_export, tmp_path: Path) -> None:
    job, job_root, export_root = _postrun_source(tmp_path)
    result = postrun_export.export_job(job["job_id"], job_root=job_root, export_root=export_root)
    assert result["records"] == 5
    assert result["availability"] == {"missing": 5}
    assert result["model_input_ready"] is False
    assert result["raw_pdf_processing"] is False


@pytest.mark.parametrize("label", [1.9, 0.9, True, False])
def test_postrun_export_never_coerces_fractional_or_boolean_labels(postrun_export, tmp_path: Path, label) -> None:
    job, job_root, export_root = _postrun_source(tmp_path, label=label)
    with pytest.raises(ValueError):
        postrun_export.export_job(job["job_id"], job_root=job_root, export_root=export_root)


def test_postrun_export_requires_validated_result_schema(postrun_export, tmp_path: Path) -> None:
    job, job_root, export_root = _postrun_source(tmp_path)
    path = job_root / job["job_id"] / "result.json"
    path.write_text(json.dumps({"job": job}), encoding="utf-8")
    with pytest.raises(ValueError):
        postrun_export.export_job(job["job_id"], job_root=job_root, export_root=export_root)
    assert not (export_root / job["job_id"]).exists()
