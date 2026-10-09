"""Safe, static-only deployment inference for the frozen RIT XGBoost model.

This package never executes, renders, or extracts active PDF content.  A PDF
path is handed only to :mod:`malpdf.static`; the model sees a finite numeric
38-feature vector after the strict compatibility gate passes.
"""

from malpdf.inference.deployment import (
    DEPLOYMENT_MODEL_ID,
    DeploymentError,
    build_deployment_model,
    preflight_deployment_build,
)
from malpdf.inference.predictor import StaticScanSession, scan_pdf

__all__ = [
    "DEPLOYMENT_MODEL_ID",
    "DeploymentError",
    "build_deployment_model",
    "preflight_deployment_build",
    "scan_pdf",
    "StaticScanSession",
]
