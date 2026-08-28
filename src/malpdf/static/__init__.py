"""Safe, non-executing static PDF inspection utilities.

The package reads PDF bytes and parser metadata only.  It never opens a viewer,
follows a URI, evaluates JavaScript, extracts payloads, or loads a model.
"""

from malpdf.static.analyzer import StaticPDFAnalyzer, inspect_pdf
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
