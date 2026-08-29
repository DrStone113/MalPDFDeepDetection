"""Synthetic-only regression tests for the offline dynamic-report contract."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

from malpdf.cli import main
from malpdf.dynamic import BEHAVIORAL_FEATURES, DYNAMIC_SCHEMA_VERSION, extract_behavioral_features, summarize_behavior
from malpdf.dynamic.adapters import CapeV2ReportAdapter, SandboxClient, SandboxReportAdapter
from malpdf.dynamic.adapters.cape import parse_cape_report_file
from malpdf.dynamic.result import unavailable_hybrid_result
from malpdf.dynamic.routing import RoutingPolicy, RoutingPolicyConfig, route_static_result


def _empty_report() -> dict[str, object]:
    return {
        "info": {"id": "synthetic-empty", "status": "completed", "duration": 1.25},
        "behavior": {"processes": [], "summary": {"files": [], "modified_files": [], "deleted_files": [], "keys": [], "modified_keys": [], "executed_commands": []}},
        "dropped": [],
        "network": {"dns": [], "tcp": [], "udp": [], "http": []},
        "signatures": [],
        "pdf_effects": {"external_application_spawned": False, "embedded_content_written": False},
    }


def _combined_report() -> dict[str, object]:
    report = _empty_report()
    report.update({
        "behavior": {
            "processes": [
                {"pid": 1, "process_name": "mock-process"},
                {"pid": 2, "parent_id": 1, "process_name": "mock-process"},
                {"pid": 3, "parent_id": 2, "process_name": "mock-process"},
            ],
            "summary": {
                "files": [{"name": "example.txt"}, {"name": "second.txt"}],
                "modified_files": [{"name": "example.txt"}],
                "deleted_files": [],
                "keys": [{"key": "redacted"}],
                "modified_keys": [{"key": "redacted"}],
                "executed_commands": [{"command": "NEVER_SERIALIZE_THIS_COMMAND"}],
            },
        },
        "dropped": [{"name": "example.exe", "type": "PE32 executable"}, {"name": "note.txt"}],
        "network": {
            "dns": [{"request": "example.invalid"}, {"request": "example.invalid"}],
            "tcp": [{"dst": "redacted"}], "udp": [], "http": [{"host": "redacted"}],
        },
        "signatures": [{"name": "persistence"}, {"name": "process injection"}, {"name": "anti-analysis"}],
        "pdf_effects": {"external_application_spawned": True, "embedded_content_written": True},
    })
    return report


def _features(report: dict[str, object]):
    return extract_behavioral_features(CapeV2ReportAdapter().normalize(report))


def test_schema_is_versioned_compact_and_has_traceable_features() -> None:
    assert DYNAMIC_SCHEMA_VERSION == "dynamic-schema-v1"
    assert len(BEHAVIORAL_FEATURES) == 21
    assert {item.name for item in BEHAVIORAL_FEATURES} >= {"process_count", "network_activity_indicator"}
    assert all(item.source_evidence and "null" in item.unavailable_semantics for item in BEHAVIORAL_FEATURES)


def test_empty_available_report_preserves_observed_zero() -> None:
    features = _features(_empty_report())
    assert features.values["process_count"] == 0
    assert features.values["dropped_file_count"] == 0
    assert features.values["dns_query_count"] == 0
    assert features.values["network_activity_indicator"] is False
    assert features.values["persistence_indicator"] is False


def test_process_files_registry_network_and_indicators_are_extracted() -> None:
    features = _features(_combined_report())
    assert features.values["process_count"] == 3
    assert features.values["child_process_count"] == 2
    assert features.values["max_process_tree_depth"] == 3
    assert features.values["file_created_count"] == 2
    assert features.values["dropped_file_count"] == 2
    assert features.values["dropped_executable_count"] == 1
    assert features.values["registry_create_count"] == 1
    assert features.values["dns_query_count"] == 2
    assert features.values["unique_domain_count"] == 1
    assert features.values["network_connection_count"] == 1
    assert features.values["http_request_count"] == 1
    assert features.values["shell_activity_indicator"] is True
    assert features.values["process_injection_indicator"] is True
    assert features.values["anti_analysis_indicator"] is True
    assert features.values["embedded_content_written_indicator"] is True
    assert features.sources["child_process_count"] == "behavior.processes"


def test_missing_and_malformed_sections_are_unavailable_with_warnings() -> None:
    missing = _features({"info": {"status": "completed"}})
    assert missing.values["process_count"] is None
    assert missing.values["network_activity_indicator"] is None
    malformed_report = {"info": {"status": "completed"}, "behavior": "not-an-object", "network": {"dns": "bad"}}
    malformed = _features(malformed_report)
    assert malformed.values["process_count"] is None
    assert malformed.values["dns_query_count"] is None
    assert {warning.code for warning in malformed.warnings} >= {"MALFORMED_SECTION"}


def test_failed_analysis_makes_all_features_unavailable() -> None:
    report = _empty_report()
    report["info"] = {"id": "synthetic-failure", "status": "failed"}
    normalized = CapeV2ReportAdapter().normalize(report)
    features = extract_behavioral_features(normalized)
    assert normalized.status == "failed"
    assert all(value is None for value in features.values.values())
    assert any(warning.code == "ANALYSIS_FAILED" for warning in normalized.warnings)


def test_output_is_deterministic_redacted_and_descriptive_only() -> None:
    normalized = CapeV2ReportAdapter().normalize(_combined_report())
    first, second = normalized.to_json(), normalized.to_json()
    feature_json = extract_behavioral_features(normalized).to_json()
    assert first == second
    assert "NEVER_SERIALIZE_THIS_COMMAND" not in first + feature_json
    assert "example.invalid" not in first + feature_json
    assert "malicious" not in summarize_behavior(extract_behavioral_features(normalized)).lower()


def test_cape_adapter_reads_already_produced_json_only(tmp_path: Path) -> None:
    report_path = tmp_path / "synthetic_report.json"
    report_path.write_text(json.dumps(_empty_report()), encoding="utf-8")
    normalized = parse_cape_report_file(report_path)
    assert isinstance(CapeV2ReportAdapter(), SandboxReportAdapter)
    assert normalized.provider == "CAPEv2"
    with pytest.raises(ValueError, match="object"):
        bad_path = tmp_path / "bad.json"
        bad_path.write_text("[]", encoding="utf-8")
        parse_cape_report_file(bad_path)


def test_sandbox_client_is_explicitly_non_operational() -> None:
    client = SandboxClient()
    for method in (client.submit, client.status, client.fetch_report):
        with pytest.raises(NotImplementedError, match="intentionally not implemented"):
            method("synthetic")


def test_routing_requires_explicit_uncertainty_bounds_and_never_executes() -> None:
    with pytest.raises(ValueError, match="requires explicit"):
        route_static_result(prediction_available=True, malicious_probability=0.5, static_verdict="MALICIOUS", config=RoutingPolicyConfig(policy=RoutingPolicy.UNCERTAINTY_BAND))
    uncertainty = route_static_result(
        prediction_available=True, malicious_probability=0.52, static_verdict="MALICIOUS",
        config=RoutingPolicyConfig(policy=RoutingPolicy.UNCERTAINTY_BAND, uncertainty_lower=0.50, uncertainty_upper=0.55),
    )
    assert uncertainty.dynamic_required is True
    assert uncertainty.reason == "STATIC_UNCERTAIN"
    confident = route_static_result(
        prediction_available=True, malicious_probability=0.9, static_verdict="MALICIOUS",
        config=RoutingPolicyConfig(policy=RoutingPolicy.UNCERTAINTY_BAND, uncertainty_lower=0.50, uncertainty_upper=0.55),
    )
    assert confident.dynamic_required is False and confident.reason == "STATIC_CONFIDENT"


def test_static_unavailable_always_and_suspicious_routing() -> None:
    unavailable = route_static_result(
        prediction_available=False, malicious_probability=None, static_verdict=None,
        config=RoutingPolicyConfig(policy=RoutingPolicy.ALWAYS_SANDBOX),
    )
    assert unavailable.dynamic_required and unavailable.reason == "STATIC_EXTRACTION_INCOMPLETE"
    static_only = route_static_result(
        prediction_available=False, malicious_probability=None, static_verdict=None,
        config=RoutingPolicyConfig(policy=RoutingPolicy.STATIC_ONLY),
    )
    assert not static_only.dynamic_required
    suspicious = route_static_result(
        prediction_available=True, malicious_probability=0.1, static_verdict="MALICIOUS",
        config=RoutingPolicyConfig(policy=RoutingPolicy.STATIC_SUSPICIOUS),
    )
    assert suspicious.dynamic_required and suspicious.reason == "STATIC_SUSPICIOUS"


def test_hybrid_is_explicitly_unavailable_without_a_validated_method() -> None:
    routing = route_static_result(
        prediction_available=True, malicious_probability=0.2, static_verdict="BENIGN",
        config=RoutingPolicyConfig(),
    )
    result = unavailable_hybrid_result(static={"probability": 0.2, "verdict": "BENIGN"}, routing=routing.to_dict())
    assert result.to_dict()["hybrid"] == {"available": False, "verdict": None, "method": None}


def test_dynamic_modules_have_no_live_execution_or_network_clients() -> None:
    import malpdf.dynamic.adapters.cape as cape_module
    import malpdf.dynamic.routing as routing_module

    tree = ast.parse(inspect.getsource(cape_module) + "\n" + inspect.getsource(routing_module))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {"subprocess", "requests", "urllib", "socket"}
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not called & {"eval", "exec"}
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "startfile"
        for node in ast.walk(tree)
    )


def test_cli_parses_synthetic_json_without_a_sandbox(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report_path = tmp_path / "synthetic_report.json"
    report_path.write_text(json.dumps(_empty_report()), encoding="utf-8")
    assert main(["dynamic", "parse", str(report_path)]) == 0
    output = capsys.readouterr().out
    assert "Sandbox provider: CAPEv2" in output
    assert "offline report parsing only" in output
