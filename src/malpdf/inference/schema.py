"""Frozen schema and provenance constants for deployment detector v1."""

from __future__ import annotations

from pathlib import Path

from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES, PROTOCOL_G_REQUIRED_FEATURES

DEPLOYMENT_MODEL_ID = "xgb-rit-full-drop3constant-v1"
DEPLOYMENT_MODEL_FILENAME = "xgb_rit_full_drop3constant.json"
DEPLOYMENT_MANIFEST_FILENAME = "xgb_rit_full_drop3constant_manifest.json"
DEPLOYMENT_ANALYSIS_FILENAME = "deployment_xgb_static_detector.md"
DEPLOYMENT_FEATURE_SCHEMA = "rit-pdfmal-2026/G-drop3constant/38/v1"
DEPLOYMENT_THRESHOLD = 0.5
MODEL_RANDOM_STATE = 42
EXPECTED_DATASET_SHA256 = "2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623"
EXPECTED_TRAINING_ROWS = 24_337
EXPECTED_CLASS_COUNTS = {"0": 13_235, "1": 11_102}

DEPLOYMENT_FEATURE_ORDER = tuple(PROTOCOL_G_REQUIRED_FEATURES)
EXCLUDED_CONSTANT_FEATURES = tuple(PROTOCOL_G_DROPPED_CONSTANT_FEATURES)

if len(DEPLOYMENT_FEATURE_ORDER) != 38 or set(DEPLOYMENT_FEATURE_ORDER) & set(EXCLUDED_CONSTANT_FEATURES):
    raise RuntimeError("Deployment schema must be exactly the Protocol G 38-feature drop3constant schema")


def deployment_artifact_path(repository_root: str | Path) -> Path:
    """Return the controlled, local-only artifact location for detector v1."""
    return Path(repository_root).resolve() / "artifacts" / "models" / DEPLOYMENT_MODEL_FILENAME


def deployment_manifest_path(repository_root: str | Path) -> Path:
    """Return the tracked immutable manifest location for detector v1."""
    return Path(repository_root).resolve() / "reports" / "deployment" / DEPLOYMENT_MANIFEST_FILENAME


def deployment_analysis_path(repository_root: str | Path) -> Path:
    """Return the tracked deployment-methodology report location."""
    return Path(repository_root).resolve() / "reports" / "analysis" / DEPLOYMENT_ANALYSIS_FILENAME
