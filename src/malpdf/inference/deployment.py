"""Immutable full-RIT build and integrity loading for deployment detector v1.

The full-data fit is a deployment artifact, not an evaluation experiment.  It
uses the already selected Protocol G XGBoost configuration but is never called
"Protocol G", since all verified RIT rows participate in this separate fit.
"""

from __future__ import annotations

import json
import hashlib
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import numpy as np
import pandas as pd

from malpdf.data.rit_pdfmal import load_rit_pdfmal, sha256_file
from malpdf.data.rit_pdfmal_paper_alignment import TARGET_COLUMN
from malpdf.experiments.protocol_g_benchmark import G_DROP3CONSTANT, protocol_g_feature_columns, protocol_g_feature_view
from malpdf.experiments.protocol_p import collect_environment_metadata, repository_git_state
from malpdf.models.classical import create_model, model_configurations
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes

from malpdf.inference.schema import (
    DEPLOYMENT_FEATURE_ORDER,
    DEPLOYMENT_FEATURE_SCHEMA,
    DEPLOYMENT_MODEL_ID,
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


class DeploymentError(RuntimeError):
    """Raised when an immutable deployment model cannot safely be used."""

    def __init__(self, message, *, code="deployment_error"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DeploymentPreflight:
    """Validated inputs and controlled outputs for the one official build."""

    repository_root: Path
    dataset_path: Path
    dataset_sha256: str
    frame: pd.DataFrame
    feature_order: tuple[str, ...]
    class_counts: dict[str, int]
    artifact_path: Path
    manifest_path: Path
    analysis_path: Path
    code_commit_sha: str
    environment: dict[str, Any]


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json_new(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise DeploymentError(f"Refusing to overwrite immutable deployment output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _assert_official_dataset(frame: pd.DataFrame, dataset_sha256: str) -> dict[str, int]:
    if dataset_sha256 != EXPECTED_DATASET_SHA256:
        raise DeploymentError("RIT dataset SHA-256 does not match the approved deployment dataset")
    if len(frame) != EXPECTED_TRAINING_ROWS:
        raise DeploymentError(f"Expected {EXPECTED_TRAINING_ROWS} RIT rows, found {len(frame)}")
    if TARGET_COLUMN not in frame.columns:
        raise DeploymentError(f"Required target column {TARGET_COLUMN!r} is absent")
    values = frame[TARGET_COLUMN]
    if values.isna().any() or not values.isin((0, 1)).all():
        raise DeploymentError("Deployment target must contain only Label=0 and Label=1")
    observed = {str(label): int((values == label).sum()) for label in (0, 1)}
    if observed != EXPECTED_CLASS_COUNTS:
        raise DeploymentError(f"RIT class counts do not match the approved identity: {observed}")
    return observed


def _assert_feature_contract(frame: pd.DataFrame) -> tuple[str, ...]:
    columns = tuple(protocol_g_feature_columns(frame, G_DROP3CONSTANT))
    if columns != DEPLOYMENT_FEATURE_ORDER:
        raise DeploymentError("Protocol G drop3constant feature order does not match deployment schema")
    if len(columns) != 38 or set(EXCLUDED_CONSTANT_FEATURES) & set(columns):
        raise DeploymentError("Deployment feature schema is not exactly 38 features with only the three constants excluded")
    selected = protocol_g_feature_view(frame, G_DROP3CONSTANT)
    if not all(pd.api.types.is_numeric_dtype(selected[column]) for column in columns):
        raise DeploymentError("Deployment features must be numeric without coercion")
    values = selected.to_numpy(dtype=float, copy=False)
    if not np.isfinite(values).all():
        raise DeploymentError("Deployment features contain non-finite values; refusing to impute or alter data")
    return columns


def preflight_deployment_build(
    repository_root: str | Path,
    dataset_path: str | Path,
    *,
    require_clean_git: bool = True,
) -> DeploymentPreflight:
    """Validate the approved full-RIT build without fitting or writing a model."""
    root = Path(repository_root).resolve()
    data_path = Path(dataset_path).resolve()
    state = repository_git_state(root)
    if require_clean_git and state.get("status") != "clean":
        raise DeploymentError("Refusing deployment build because the repository is not clean")
    frame = load_rit_pdfmal(data_path)
    dataset_sha256 = sha256_file(data_path)
    class_counts = _assert_official_dataset(frame, dataset_sha256)
    feature_order = _assert_feature_contract(frame)
    artifact = deployment_artifact_path(root)
    manifest = deployment_manifest_path(root)
    analysis = deployment_analysis_path(root)
    for protected in (artifact, manifest, analysis):
        if protected.exists():
            raise DeploymentError(f"Refusing to overwrite existing deployment output: {protected}")
    environment = collect_environment_metadata(data_path, root)
    environment["git_working_tree"] = state
    code_commit = str(environment.get("git_commit_sha", "unavailable"))
    if require_clean_git and len(code_commit) != 40:
        raise DeploymentError("Refusing deployment build because the current Git commit SHA is unavailable")
    return DeploymentPreflight(
        repository_root=root,
        dataset_path=data_path,
        dataset_sha256=dataset_sha256,
        frame=frame,
        feature_order=feature_order,
        class_counts=class_counts,
        artifact_path=artifact,
        manifest_path=manifest,
        analysis_path=analysis,
        code_commit_sha=code_commit,
        environment=environment,
    )


def deployment_model_configuration() -> dict[str, Any]:
    """Return the frozen existing Protocol G XGBoost configuration by value."""
    return model_configurations(MODEL_RANDOM_STATE)["xgboost"]


def _manifest_from_preflight(
    preflight: DeploymentPreflight,
    artifact_sha256: str,
    command: str,
    training_seconds: float,
) -> dict[str, Any]:
    return {
        "model_id": DEPLOYMENT_MODEL_ID,
        "model_family": "XGBoost XGBClassifier",
        "artifact_filename": DEPLOYMENT_MODEL_FILENAME,
        "artifact_relative_path": str(preflight.artifact_path.relative_to(preflight.repository_root)).replace("\\", "/"),
        "artifact_sha256": artifact_sha256,
        "training_dataset": {
            "filename": preflight.dataset_path.name,
            "sha256": preflight.dataset_sha256,
            "training_rows": EXPECTED_TRAINING_ROWS,
            "class_counts": preflight.class_counts,
            "target_column": TARGET_COLUMN,
            "target_semantics": {"0": "benign", "1": "malicious"},
        },
        "feature_schema": DEPLOYMENT_FEATURE_SCHEMA,
        "feature_variant": "drop3constant",
        "feature_order": list(preflight.feature_order),
        "excluded_constant_features": list(EXCLUDED_CONSTANT_FEATURES),
        "model_random_state": MODEL_RANDOM_STATE,
        "threshold": DEPLOYMENT_THRESHOLD,
        "model_configuration": deployment_model_configuration(),
        "model_configuration_source": "malpdf.models.classical.model_configurations(42)['xgboost']; the fixed established Protocol G configuration, reused without tuning.",
        "preprocessing": {"name": None, "note": "No scaling, imputation, normalization, encoding, clipping, or feature selection is applied."},
        "environment": preflight.environment,
        "python_version": preflight.environment.get("python_version", "unavailable"),
        "xgboost_version": preflight.environment.get("library_versions", {}).get("xgboost", "unavailable"),
        "deployment_code_commit_sha": preflight.code_commit_sha,
        "build_command": command,
        "built_at_utc": _timestamp_utc(),
        "training_seconds": training_seconds,
        "purpose": "Full-data deployment model after separate model-family evaluation; this artifact is not a performance benchmark.",
        "safety": {
            "pdf_content_executed": False,
            "external_resources_followed": False,
            "embedded_payloads_executed": False,
        },
    }


def _analysis_markdown(manifest: dict[str, Any]) -> str:
    return "\n".join([
        "# Static XGBoost deployment detector v1",
        "",
        "## Objective and scope",
        "",
        "This is a reproducible static-only deployment/demo detector, not a new benchmark. It reads a local PDF as untrusted bytes through the bounded non-executing extractor, requires the 38-feature gate, and then returns an ML prediction plus a local TreeSHAP explanation.",
        "",
        "## Deployment model versus benchmark evidence",
        "",
        "The frozen XGBoost family/configuration was selected and evaluated separately by the committed Protocol G, multi-seed, and reproduction work. This detector fits all approved RIT rows only to create a final deployment artifact. It reports no full-data training accuracy and makes no new generalization claim.",
        "",
        "## Training data and schema",
        "",
        f"- RIT-PDFMal-2026 SHA-256: `{manifest['training_dataset']['sha256']}`.",
        f"- Rows: {manifest['training_dataset']['training_rows']}; Label=0 benign: {manifest['training_dataset']['class_counts']['0']}; Label=1 malicious: {manifest['training_dataset']['class_counts']['1']}.",
        f"- Schema: `{manifest['feature_schema']}` with 38 ordered features; only `Acroform`, `Colors`, and `BaseEncoding` are excluded as known constants.",
        "- Semantic sentinel values are preserved. No imputation, clipping, normalization, encoding, or further feature selection occurs.",
        "",
        "## Static compatibility and inference flow",
        "",
        "`malpdf scan` performs bounded static extraction, then invokes `StaticInspectionResult.protocol_g_drop3constant_gate()`. Every required feature must be present, `IMPLEMENTED_VERIFIED_SEMANTICS`, numeric, and finite. Any blocker refuses inference; no partial vector is scored. The model receives the explicit saved feature order, never document-controlled ordering.",
        "",
        "## Model, threshold, and integrity",
        "",
        f"- Model ID: `{manifest['model_id']}`; random state: {manifest['model_random_state']}; threshold: {manifest['threshold']}. Probability >= threshold produces model verdict `MALICIOUS`; otherwise `BENIGN`.",
        "- Configuration is the existing fixed Protocol G XGBoost factory configuration, reused without tuning. The deployment model is not itself called a Protocol G model.",
        "- Loading requires the controlled local artifact, SHA-256 match, model type, saved feature count/order, feature schema, and manifest configuration identity. Artifacts and manifests are immutable by default.",
        "",
        "## Local explanation",
        "",
        "Native XGBoost `pred_contribs=True` produces feature contributions plus a separate bias. The scanner verifies contribution-sum plus bias against raw margin and sigmoid(margin) against malicious probability. If either check fails, prediction remains separately available but explanation is reported unavailable rather than shown incorrectly. Contributions are model associations, not causal reasons.",
        "",
        "## Safety and limitations",
        "",
        "No JavaScript, Launch action, attachment, URI, payload, viewer, external application, or network action is executed or followed. The model receives only numeric static features. It is trained on RIT static features; arbitrary real-world PDFs may differ in distribution. Exact record-level equality with the unavailable original RIT PDFs cannot be demonstrated. Static analysis cannot observe runtime behavior; malformed or encrypted files can yield incomplete extraction; a malicious probability is a model score rather than proof. No sandbox or dynamic analysis is included. Future routing can use the exposed probability and prediction-availability fields without defining an unvalidated uncertainty band.",
        "",
        "## Provenance",
        "",
        f"- Deployment code commit: `{manifest['deployment_code_commit_sha']}`.",
        f"- Artifact SHA-256: `{manifest['artifact_sha256']}`.",
        f"- Build command: `{manifest['build_command']}`.",
        "",
    ])


def build_deployment_model(preflight: DeploymentPreflight, *, command: str) -> dict[str, Any]:
    """Fit once on all validated RIT rows and write new immutable outputs.

    Callers must invoke :func:`preflight_deployment_build` immediately before
    this function.  The small post-fit probability check is an artifact sanity
    check only and is intentionally not reported as a performance metric.
    """
    for protected in (preflight.artifact_path, preflight.manifest_path, preflight.analysis_path):
        if protected.exists():
            raise DeploymentError(f"Refusing to overwrite existing deployment output: {protected}")
    set_random_seed(MODEL_RANDOM_STATE)
    features = protocol_g_feature_view(preflight.frame, G_DROP3CONSTANT)
    if tuple(features.columns) != preflight.feature_order:
        raise DeploymentError("Deployment feature view changed ordering after preflight")
    estimator = create_model("xgboost", MODEL_RANDOM_STATE)
    training_started = perf_counter()
    estimator.fit(features, preflight.frame[TARGET_COLUMN])
    training_seconds = perf_counter() - training_started
    sanity_probabilities = np.asarray(estimator.predict_proba(features.iloc[:8])[:, 1], dtype=float)
    if sanity_probabilities.shape != (min(8, len(features)),) or not np.isfinite(sanity_probabilities).all() or (sanity_probabilities < 0).any() or (sanity_probabilities > 1).any():
        raise DeploymentError("Frozen deployment model failed finite-probability sanity validation")
    preflight.artifact_path.parent.mkdir(parents=True, exist_ok=True)
    estimator.save_model(str(preflight.artifact_path))
    artifact_sha256 = sha256_file(preflight.artifact_path)
    manifest = _manifest_from_preflight(preflight, artifact_sha256, command, training_seconds)
    _write_json_new(preflight.manifest_path, manifest)
    if preflight.analysis_path.exists():
        raise DeploymentError(f"Refusing to overwrite immutable deployment analysis: {preflight.analysis_path}")
    preflight.analysis_path.parent.mkdir(parents=True, exist_ok=True)
    preflight.analysis_path.write_text(_analysis_markdown(manifest), encoding="utf-8")
    return manifest


def load_deployment_manifest(repository_root: str | Path) -> tuple[dict[str, Any], Path, Path]:
    """Load and validate tracked metadata before any model artifact is loaded."""
    root = Path(repository_root).resolve()
    manifest_path = deployment_manifest_path(root)
    if not manifest_path.is_file():
        raise DeploymentError(
            "Deployment model is not installed/built. Build it explicitly with: "
            ".\\.venv\\Scripts\\python.exe scripts\\build_deployment_model.py --execute",
            code="deployment_manifest_missing",
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DeploymentError(f"Deployment manifest is unreadable: {error}", code="deployment_manifest_unreadable") from error
    expected = {
        "model_id": DEPLOYMENT_MODEL_ID,
        "feature_schema": DEPLOYMENT_FEATURE_SCHEMA,
        "feature_order": list(DEPLOYMENT_FEATURE_ORDER),
        "excluded_constant_features": list(EXCLUDED_CONSTANT_FEATURES),
        "model_random_state": MODEL_RANDOM_STATE,
        "threshold": DEPLOYMENT_THRESHOLD,
        "model_configuration": deployment_model_configuration(),
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise DeploymentError(f"Deployment manifest does not match required {key}")
    training = manifest.get("training_dataset")
    if (
        not isinstance(training, dict)
        or training.get("sha256") != EXPECTED_DATASET_SHA256
        or training.get("training_rows") != EXPECTED_TRAINING_ROWS
        or training.get("class_counts") != EXPECTED_CLASS_COUNTS
        or training.get("target_column") != TARGET_COLUMN
    ):
        raise DeploymentError("Deployment manifest has an unexpected training dataset identity")
    if manifest.get("artifact_filename") != DEPLOYMENT_MODEL_FILENAME:
        raise DeploymentError("Deployment manifest artifact filename is not the controlled detector-v1 filename")
    relative = manifest.get("artifact_relative_path")
    if relative != f"artifacts/models/{DEPLOYMENT_MODEL_FILENAME}":
        raise DeploymentError("Deployment manifest artifact path is not the controlled detector-v1 path")
    artifact_path = deployment_artifact_path(root)
    if not artifact_path.is_file():
        raise DeploymentError(
            "Deployment model artifact is missing. Build it explicitly with: "
            ".\\.venv\\Scripts\\python.exe scripts\\build_deployment_model.py --execute",
            code="deployment_artifact_missing",
        )
    expected_hash = manifest.get("artifact_sha256")
    if not isinstance(expected_hash, str) or sha256_file(artifact_path) != expected_hash:
        raise DeploymentError("Deployment model artifact SHA-256 does not match its manifest", code="deployment_artifact_checksum_mismatch")
    return manifest, manifest_path, artifact_path


def _assert_saved_xgboost_structure(model: Any) -> None:
    """Check the stable structure exposed by a portable XGBoost JSON artifact.

    XGBoost 3.2 resets construction-only settings (seed, thread count, tree
    method, learning rate) to loader defaults after portable-model loading.
    The immutable manifest's exact configuration plus artifact checksum bind
    those build settings; this verifies the fields the library preserves.
    """
    try:
        learner = json.loads(model.get_booster().save_config())["learner"]
        tree = learner["gradient_booster"]["tree_train_param"]
        booster = learner["gradient_booster"]
        model_parameters = learner["learner_model_param"]
        train = learner["learner_train_param"]
        objective = learner["objective"]
        configured = deployment_model_configuration()["parameters"]
        expected_text = {
            "booster.name": str(configured["booster"]),
            "model.num_trees": str(configured["n_estimators"]),
            "model.num_feature": str(len(DEPLOYMENT_FEATURE_ORDER)),
            "train.objective": str(configured["objective"]),
            "objective.name": str(configured["objective"]),
            "tree.max_depth": str(configured["max_depth"]),
        }
        observed_text = {
            "booster.name": booster["name"],
            "model.num_trees": booster["gbtree_model_param"]["num_trees"],
            "model.num_feature": model_parameters["num_feature"],
            "train.objective": train["objective"],
            "objective.name": objective["name"],
            "tree.max_depth": tree["max_depth"],
        }
        for name, expected in expected_text.items():
            if observed_text[name] != expected:
                raise DeploymentError(f"Deployment model configuration mismatch for {name}")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise DeploymentError(f"Deployment model configuration metadata is unreadable: {error}") from error


def load_verified_deployment_model(repository_root: str | Path) -> tuple[Any, dict[str, Any]]:
    """Load the controlled JSON artifact only after manifest and checksum checks."""
    manifest, _manifest_path, artifact_path = load_deployment_manifest(repository_root)
    try:
        from xgboost import XGBClassifier
    except ImportError as error:
        raise DeploymentError("XGBoost is required for deployment inference") from error
    model = XGBClassifier()
    try:
        model.load_model(str(artifact_path))
    except Exception as error:
        raise DeploymentError(f"Deployment model artifact could not be loaded: {error}") from error
    booster = model.get_booster()
    if booster is None or tuple(booster.feature_names or ()) != DEPLOYMENT_FEATURE_ORDER:
        raise DeploymentError("Deployment model feature names/order do not match the required 38-feature schema")
    if len(booster.feature_names or ()) != 38:
        raise DeploymentError("Deployment model does not expose exactly 38 feature names")
    _assert_saved_xgboost_structure(model)
    return model, manifest


def restore_verified_deployment_model(repository_root: str | Path, source: str | Path) -> dict:
    """Install the exact saved JSON; no fitting, overwrite or pickle loading."""
    root, source = Path(repository_root).absolute(), Path(source).absolute()
    manifest = json.loads(read_bounded_bytes(deployment_manifest_path(root), boundary=root / "reports/deployment", max_bytes=64 * 1024))
    if source.suffix.lower() != ".json":
        raise DeploymentError("Only the saved deployment JSON is accepted", code="deployment_source_invalid")
    content = read_bounded_bytes(source, boundary=source.parent, max_bytes=64 * 1024**2)
    if hashlib.sha256(content).hexdigest() != manifest.get("artifact_sha256"):
        raise DeploymentError("Saved deployment copy differs from manifest", code="deployment_artifact_checksum_mismatch")
    target = deployment_artifact_path(root)
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise DeploymentError("Deployment destination contains a symbolic link", code="deployment_destination_invalid")
    created = False
    temporary = None
    try:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(prefix=".deployment-", dir=target.parent)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, target)
            created = True
        _model, verified = load_verified_deployment_model(root)
        return {"status": "restored" if created else "already_verified", "model_id": verified["model_id"],
                "artifact_sha256": verified["artifact_sha256"], "artifact_path": str(target.relative_to(root)), "fitting": False}
    except Exception:
        if created:
            target.unlink()
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
