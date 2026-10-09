"""Safe, non-executing static PDF inspection utilities.

The package reads PDF bytes and parser metadata only.  It never opens a viewer,
follows a URI, evaluates JavaScript, extracts payloads, or loads a model.
"""

from malpdf.static.result import FeatureCompatibilityGate, FeatureStatus, StaticInspectionResult
from malpdf.static.safety import StaticInspectionLimits

__all__ = [
    "FeatureCompatibilityGate",
    "FeatureStatus",
    "StaticInspectionLimits",
    "StaticInspectionResult",
    "StaticPDFAnalyzer",
    "inspect_pdf",
]


def __getattr__(name):
    """Load PDF parsers only when the inspection API is actually requested."""
    if name not in {"StaticPDFAnalyzer", "inspect_pdf"}:
        raise AttributeError(name)
    from malpdf.static import analyzer
    value = getattr(analyzer, name)
    globals()[name] = value
    return value
