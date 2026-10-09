"""Synthetic-only tests for the static deployment inference contract."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import pymupdf

from malpdf.cli import main
from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.inference import deployment
from malpdf.inference.deployment import (
    DeploymentError,
    DeploymentPreflight,
    build_deployment_model,
    load_deployment_manifest,
    load_verified_deployment_model,
    preflight_deployment_build,
)
from malpdf.inference.predictor import local_treeshap_explanation, scan_pdf, verdict_from_probability
from malpdf.inference.schema import (
    DEPLOYMENT_FEATURE_ORDER,
    DEPLOYMENT_FEATURE_SCHEMA,
    DEPLOYMENT_MODEL_FILENAME,
    DEPLOYMENT_THRESHOLD,
    EXPECTED_CLASS_COUNTS,
    EXPECTED_DATASET_SHA256,
    EXPECTED_TRAINING_ROWS,
    EXCLUDED_CONSTANT_FEATURES,
    MODEL_RANDOM_STATE,
    deployment_analysis_path,
    deployment_artifact_path,
    deployment_manifest_path,
)
from malpdf.models.classical import create_model, model_configurations
from malpdf.static.result import StaticInspectionResult
from malpdf.static.schema import RIT_FEATURES, implementation_statuses


def _synthetic_features(rows: int = 40) -> pd.DataFrame:
    generator = np.random.default_rng(20260829)
    values = generator.normal(size=(rows, len(DEPLOYMENT_FEATURE_ORDER)))
    values[:, 0] += np.arange(rows) % 2 * 2.0
    return pd.DataFrame(values, columns=DEPLOYMENT_FEATURE_ORDER)


def _trained_model(rows: int = 40):
    features = _synthetic_features(rows)
    labels = pd.Series(np.arange(rows) % 2, name=TARGET_COLUMN)
    model = create_model("xgboost", MODEL_RANDOM_STATE)
    model.fit(features, labels)
    return model, features, labels


def _passing_static_result() -> StaticInspectionResult:
    return StaticInspectionResult(
        input={"sha256": "a" * 64, "size_bytes": 123, "path": "synthetic.pdf"},
        parser={"success": True},
        features={feature: 0 for feature in RIT_FEATURES},
        compatibility=dict(implementation_statuses()),
        diagnostics={},
    )


def _write_verified_artifact(root: Path) -> tuple[object, pd.DataFrame]:
    model, features, _labels = _trained_model()
    artifact = deployment_artifact_path(root)
    artifact.parent.mkdir(parents=True)
    model.save_model(str(artifact))
    manifest = {
        "model_id": "xgb-rit-full-drop3constant-v1",
        "model_family": "XGBoost XGBClassifier",
        "artifact_filename": DEPLOYMENT_MODEL_FILENAME,
        "artifact_relative_path": f"artifacts/models/{DEPLOYMENT_MODEL_FILENAME}",
        "artifact_sha256": deployment.sha256_file(artifact),
        "training_dataset": {
            "filename": "rit-pdfmal-2026.csv",
            "sha256": EXPECTED_DATASET_SHA256,
            "training_rows": EXPECTED_TRAINING_ROWS,
            "class_counts": EXPECTED_CLASS_COUNTS,
            "target_column": TARGET_COLUMN,
        },
        "feature_schema": DEPLOYMENT_FEATURE_SCHEMA,
        "feature_variant": "drop3constant",
        "feature_order": list(DEPLOYMENT_FEATURE_ORDER),
        "excluded_constant_features": list(EXCLUDED_CONSTANT_FEATURES),
        "model_random_state": MODEL_RANDOM_STATE,
        "threshold": DEPLOYMENT_THRESHOLD,
        "model_configuration": deployment.deployment_model_configuration(),
    }
    manifest_path = deployment_manifest_path(root)
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return model, features


def _small_preflight(root: Path) -> DeploymentPreflight:
    features = _synthetic_features()
    frame = features.copy()
    for constant in EXCLUDED_CONSTANT_FEATURES:
        frame[constant] = 0
    frame[TARGET_COLUMN] = np.arange(len(frame)) % 2
    return DeploymentPreflight(
        repository_root=root,
        dataset_path=root / "synthetic.csv",
        dataset_sha256=EXPECTED_DATASET_SHA256,
        frame=frame,
        feature_order=DEPLOYMENT_FEATURE_ORDER,
        class_counts=EXPECTED_CLASS_COUNTS,
        artifact_path=deployment_artifact_path(root),
        manifest_path=deployment_manifest_path(root),
        analysis_path=deployment_analysis_path(root),
        code_commit_sha="b" * 40,
        environment={"python_version": "3.11-test", "git_commit_sha": "b" * 40},
    )


def test_deployment_schema_is_exact_protocol_g_drop3constant() -> None:
    assert len(DEPLOYMENT_FEATURE_ORDER) == 38
    assert EXCLUDED_CONSTANT_FEATURES == ("Acroform", "Colors", "BaseEncoding")
    assert not set(DEPLOYMENT_FEATURE_ORDER) & set(EXCLUDED_CONSTANT_FEATURES)
    assert EXPECTED_TRAINING_ROWS == 24_337
    assert EXPECTED_CLASS_COUNTS == {"0": 13_235, "1": 11_102}


def test_deployment_uses_fixed_existing_xgboost_configuration() -> None:
    configuration = deployment.deployment_model_configuration()
    assert configuration == model_configurations(42)["xgboost"]
    assert configuration["parameters"]["random_state"] == 42
    assert configuration["parameters"]["n_estimators"] == 200
    assert configuration["parameters"]["tree_method"] == "hist"


def test_fixed_threshold_treats_label_one_as_malicious_at_exactly_point_five() -> None:
    assert verdict_from_probability(0.499999) == (0, "BENIGN")
    assert verdict_from_probability(0.5) == (1, "MALICIOUS")
    assert verdict_from_probability(1.0) == (1, "MALICIOUS")
    with pytest.raises(DeploymentError, match="within"):
        verdict_from_probability(float("nan"))


def test_xgboost_fixed_seed_is_prediction_deterministic_on_synthetic_data() -> None:
    features = _synthetic_features()
    labels = pd.Series(np.arange(len(features)) % 2)
    first = create_model("xgboost", 42).fit(features, labels)
    second = create_model("xgboost", 42).fit(features, labels)
    assert np.allclose(first.predict_proba(features)[:, 1], second.predict_proba(features)[:, 1])


def test_preflight_enforces_approved_dataset_identity_without_external_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    frame = _small_preflight(tmp_path).frame
    frame = pd.concat([frame] * ((EXPECTED_TRAINING_ROWS // len(frame)) + 1), ignore_index=True).iloc[:EXPECTED_TRAINING_ROWS].copy()
    frame[TARGET_COLUMN] = np.array([0] * EXPECTED_CLASS_COUNTS["0"] + [1] * EXPECTED_CLASS_COUNTS["1"])
    monkeypatch.setattr(deployment, "load_rit_pdfmal", lambda _path: frame)
    monkeypatch.setattr(deployment, "sha256_file", lambda _path: EXPECTED_DATASET_SHA256)
    monkeypatch.setattr(deployment, "repository_git_state", lambda _root: {"status": "clean"})
    monkeypatch.setattr(deployment, "collect_environment_metadata", lambda _path, _root: {"git_commit_sha": "c" * 40})
    preflight = preflight_deployment_build(tmp_path, tmp_path / "synthetic.csv")
    assert len(preflight.frame) == EXPECTED_TRAINING_ROWS
    assert preflight.class_counts == EXPECTED_CLASS_COUNTS
    assert preflight.feature_order == DEPLOYMENT_FEATURE_ORDER
    monkeypatch.setattr(deployment, "sha256_file", lambda _path: "wrong")
    with pytest.raises(DeploymentError, match="SHA-256"):
        preflight_deployment_build(tmp_path, tmp_path / "synthetic.csv")


def test_build_writes_manifest_once_and_refuses_overwrite(tmp_path: Path) -> None:
    preflight = _small_preflight(tmp_path)
    manifest = build_deployment_model(preflight, command="synthetic test")
    assert preflight.manifest_path.is_file()
    assert preflight.analysis_path.is_file()
    assert manifest["training_dataset"]["training_rows"] == EXPECTED_TRAINING_ROWS
    assert manifest["feature_order"] == list(DEPLOYMENT_FEATURE_ORDER)
    assert len(manifest["artifact_sha256"]) == 64
    with pytest.raises(DeploymentError, match="overwrite"):
        build_deployment_model(preflight, command="synthetic test")


def test_loader_verifies_artifact_checksum_and_feature_order(tmp_path: Path) -> None:
    _write_verified_artifact(tmp_path)
    model, manifest = load_verified_deployment_model(tmp_path)
    assert manifest["model_id"] == "xgb-rit-full-drop3constant-v1"
    assert tuple(model.get_booster().feature_names) == DEPLOYMENT_FEATURE_ORDER
    artifact = deployment_artifact_path(tmp_path)
    artifact.write_bytes(artifact.read_bytes() + b"corrupt")
    with pytest.raises(DeploymentError, match="SHA-256"):
        load_deployment_manifest(tmp_path)


def test_gate_failure_never_loads_or_predicts(tmp_path: Path) -> None:
    static_result = _passing_static_result()
    static_result.features[DEPLOYMENT_FEATURE_ORDER[0]] = None
    called = False

    def forbidden_loader(_root):
        nonlocal called
        called = True
        raise AssertionError("model must not load after gate failure")

    result = scan_pdf(
        "synthetic.pdf",
        repository_root=tmp_path,
        inspector=lambda _path, limits=None: static_result,
        model_loader=forbidden_loader,
    )
    assert not result.prediction["available"]
    assert not result.compatibility["passed"]
    assert not called
    assert result.compatibility["blockers"][0]["feature"] == DEPLOYMENT_FEATURE_ORDER[0]


def test_scan_uses_verified_model_probability_threshold_and_treeshap(tmp_path: Path) -> None:
    model, _features = _write_verified_artifact(tmp_path)
    result = scan_pdf(
        "synthetic.pdf",
        repository_root=tmp_path,
        inspector=lambda _path, limits=None: _passing_static_result(),
    )
    assert result.prediction["available"]
    assert 0.0 <= result.prediction["malicious_probability"] <= 1.0
    assert result.prediction["predicted_label"] == int(result.prediction["malicious_probability"] >= 0.5)
    assert result.model["name"] == "xgb-rit-full-drop3constant-v1"
    assert result.explanation["available"]
    assert result.explanation["margin_reconstruction_error"] <= 2e-5
    assert result.explanation["probability_reconstruction_error"] <= 2e-6
    assert all(item["contribution"] > 0 for item in result.explanation["top_positive_contributions"])
    assert all(item["contribution"] < 0 for item in result.explanation["top_negative_contributions"])
    assert result.safety == {
        "active_content_executed": False,
        "external_resources_followed": False,
        "embedded_payload_executed": False,
    }
    assert model is not None


def test_harmless_synthetic_pdf_runs_full_static_gate_model_and_treeshap_path(tmp_path: Path) -> None:
    """Exercise the actual bounded extractor; the fixture's predicted class is immaterial."""
    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((36, 72), "This is a harmless synthetic test fixture.")
    fixture = tmp_path / "harmless.pdf"
    document.save(fixture)
    document.close()
    _write_verified_artifact(tmp_path)
    result = scan_pdf(fixture, repository_root=tmp_path)
    assert result.compatibility["passed"]
    assert result.prediction["available"]
    assert result.explanation["available"]
    assert result.safety["active_content_executed"] is False


def test_local_treeshap_has_expected_dimensions_and_identity() -> None:
    model, features, _labels = _trained_model()
    probability = float(model.predict_proba(features.iloc[:1])[:, 1][0])
    explanation = local_treeshap_explanation(model, features.iloc[:1], probability)
    assert explanation["available"]
    assert explanation["base_value"] is not None
    assert explanation["margin_reconstruction_error"] <= 2e-5
    assert explanation["probability_reconstruction_error"] <= 2e-6


def test_missing_model_returns_structured_error_after_passing_gate(tmp_path: Path) -> None:
    result = scan_pdf(
        "synthetic.pdf",
        repository_root=tmp_path,
        inspector=lambda _path, limits=None: _passing_static_result(),
    )
    assert result.compatibility["passed"]
    assert not result.prediction["available"]
    assert "not installed/built" in str(result.prediction["error"])
    assert json.loads(json.dumps(result.to_dict()))["prediction"]["available"] is False


def test_inspect_command_does_not_call_scan_or_load_a_model(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    static_result = _passing_static_result()
    static_result.diagnostics = {"file_header": {"header_version_string": "1.7"}}
    monkeypatch.setattr("malpdf.cli.inspect_pdf", lambda _path, limits=None: static_result)
    monkeypatch.setattr("malpdf.cli.scan_pdf", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scan should not run")))
    assert main(["inspect", "synthetic.pdf", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"]["sha256"] == "a" * 64


def test_inference_source_does_not_introduce_dangerous_pdf_operations() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "malpdf" / "inference"
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_root.glob("*.py"))
    forbidden = ("subprocess", "os.startfile", "webbrowser", "requests", "urllib", "socket", "eval(", "exec(")
    assert not [term for term in forbidden if term in source]


def test_restore_exact_saved_json_without_fitting_or_overwriting(tmp_path, monkeypatch):
    _write_verified_artifact(tmp_path)
    target = deployment_artifact_path(tmp_path)
    source = tmp_path / "saved_model.json"
    target.rename(source)
    monkeypatch.setattr(deployment, "create_model", lambda *args, **kwargs: pytest.fail("Restoration fitted a model"))
    first = deployment.restore_verified_deployment_model(tmp_path, source)
    assert first["status"] == "restored" and first["fitting"] is False
    assert target.read_bytes() == source.read_bytes()
    again = deployment.restore_verified_deployment_model(tmp_path, source)
    assert again["status"] == "already_verified"


def test_restore_checks_checksum_before_loading_and_preserves_existing_file(tmp_path, monkeypatch):
    _write_verified_artifact(tmp_path)
    target = deployment_artifact_path(tmp_path)
    original = target.read_bytes()
    source = tmp_path / "wrong_model.json"; source.write_text('{"fixture":"wrong checksum"}')
    monkeypatch.setattr(deployment, "load_verified_deployment_model", lambda *args: pytest.fail("Loaded before checksum guard"))
    with pytest.raises(DeploymentError) as caught:
        deployment.restore_verified_deployment_model(tmp_path, source)
    assert caught.value.code == "deployment_artifact_checksum_mismatch"
    assert target.read_bytes() == original


def test_restore_rolls_back_new_artifact_when_manifest_schema_invalid(tmp_path):
    _write_verified_artifact(tmp_path)
    target = deployment_artifact_path(tmp_path)
    source = tmp_path / "saved_model.json"; target.rename(source)
    manifest_path = deployment_manifest_path(tmp_path)
    manifest = json.loads(manifest_path.read_text()); manifest["feature_order"] = ["invalid"]
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(DeploymentError, match="feature_order"):
        deployment.restore_verified_deployment_model(tmp_path, source)
    assert not target.exists() and source.exists()
    assert not list(target.parent.glob(".deployment-*"))
