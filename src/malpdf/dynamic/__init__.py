"""Offline behavioral-report contracts for a future isolated dynamic stage."""

from malpdf.dynamic.features import extract_behavioral_features, summarize_behavior
from malpdf.dynamic.result import BehavioralFeatureSet, HybridAnalysisResult, NormalizedBehavioralReport
from malpdf.dynamic.routing import RoutingPolicy, RoutingPolicyConfig, route_static_result
from malpdf.dynamic.schema import BEHAVIORAL_FEATURES, DYNAMIC_SCHEMA_VERSION

__all__ = [
    "BEHAVIORAL_FEATURES",
    "BehavioralFeatureSet",
    "DYNAMIC_SCHEMA_VERSION",
    "HybridAnalysisResult",
    "NormalizedBehavioralReport",
    "RoutingPolicy",
    "RoutingPolicyConfig",
    "extract_behavioral_features",
    "route_static_result",
    "summarize_behavior",
]
