"""Safe, static-only deployment inference for the frozen RIT XGBoost model.

This package never executes, renders, or extracts active PDF content.  A PDF
path is handed only to :mod:`malpdf.static`; the model sees a finite numeric
38-feature vector after the strict compatibility gate passes.
"""

__all__ = [
    "DEPLOYMENT_MODEL_ID",
    "DeploymentError",
    "build_deployment_model",
    "preflight_deployment_build",
    "scan_pdf",
    "StaticScanSession",
]


def __getattr__(name: str):
    if name in {
        "DEPLOYMENT_MODEL_ID",
        "DeploymentError",
        "build_deployment_model",
        "preflight_deployment_build",
    }:
        from malpdf.inference import deployment

        return getattr(deployment, name)
    if name in {"StaticScanSession", "scan_pdf"}:
        from malpdf.inference import predictor

        return getattr(predictor, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
