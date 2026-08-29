"""Versioned, compact contract for offline sandbox-behaviour reports.

This module deliberately defines data semantics only.  It does not contact a
sandbox, submit files, or execute any input.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

DYNAMIC_SCHEMA_VERSION = "dynamic-schema-v1"


@dataclass(frozen=True)
class BehavioralFeatureDefinition:
    """One stable, non-payload behavioural feature definition."""

    name: str
    dtype: str
    unit: str
    source_evidence: str
    description: str
    unavailable_semantics: str
    adapter_support: tuple[str, ...] = ("capev2-report-json",)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_UNAVAILABLE = "0 means observed absence after the source section was available; null means unavailable, missing, malformed, or failed analysis."

BEHAVIORAL_FEATURES: tuple[BehavioralFeatureDefinition, ...] = (
    BehavioralFeatureDefinition("process_count", "integer", "count", "behavior.processes", "Observed process records.", _UNAVAILABLE),
    BehavioralFeatureDefinition("child_process_count", "integer", "count", "behavior.processes", "Observed process records with a known parent or explicit child relation.", _UNAVAILABLE),
    BehavioralFeatureDefinition("max_process_tree_depth", "integer", "levels", "behavior.processes", "Maximum observed process-tree depth; a root process has depth one.", _UNAVAILABLE),
    BehavioralFeatureDefinition("file_created_count", "integer", "count", "behavior.summary.files", "Observed created filesystem entries.", _UNAVAILABLE),
    BehavioralFeatureDefinition("file_modified_count", "integer", "count", "behavior.summary.modified_files", "Observed modified filesystem entries.", _UNAVAILABLE),
    BehavioralFeatureDefinition("file_deleted_count", "integer", "count", "behavior.summary.deleted_files", "Observed deleted filesystem entries.", _UNAVAILABLE),
    BehavioralFeatureDefinition("dropped_file_count", "integer", "count", "dropped", "Observed dropped-file records.", _UNAVAILABLE),
    BehavioralFeatureDefinition("dropped_executable_count", "integer", "count", "dropped", "Observed dropped files classified by the report as executable.", _UNAVAILABLE),
    BehavioralFeatureDefinition("registry_create_count", "integer", "count", "behavior.summary.keys", "Observed registry keys created by the report.", _UNAVAILABLE),
    BehavioralFeatureDefinition("registry_modify_count", "integer", "count", "behavior.summary.modified_keys", "Observed registry keys modified by the report.", _UNAVAILABLE),
    BehavioralFeatureDefinition("persistence_indicator", "boolean", "indicator", "signatures / behaviour categories", "Provider-reported persistence category, if exposed.", _UNAVAILABLE),
    BehavioralFeatureDefinition("dns_query_count", "integer", "count", "network.dns", "Observed DNS query records.", _UNAVAILABLE),
    BehavioralFeatureDefinition("unique_domain_count", "integer", "count", "network.dns", "Distinct normalized domain values internally counted without retaining them.", _UNAVAILABLE),
    BehavioralFeatureDefinition("network_connection_count", "integer", "count", "network.tcp / network.udp", "Observed TCP plus UDP connection records.", _UNAVAILABLE),
    BehavioralFeatureDefinition("http_request_count", "integer", "count", "network.http", "Observed HTTP request records.", _UNAVAILABLE),
    BehavioralFeatureDefinition("shell_activity_indicator", "boolean", "indicator", "behavior.summary.executed_commands", "Whether the provider reported shell/command activity; command bodies are never retained.", _UNAVAILABLE),
    BehavioralFeatureDefinition("external_process_spawn_indicator", "boolean", "indicator", "behavior.processes", "Whether an observed child process or explicit external-spawn signal exists.", _UNAVAILABLE),
    BehavioralFeatureDefinition("process_injection_indicator", "boolean", "indicator", "signatures / behaviour categories", "Provider-reported injection category, if exposed.", _UNAVAILABLE),
    BehavioralFeatureDefinition("anti_analysis_indicator", "boolean", "indicator", "signatures / behaviour categories", "Provider-reported anti-analysis category, if exposed.", _UNAVAILABLE),
    BehavioralFeatureDefinition("embedded_content_written_indicator", "boolean", "indicator", "pdf_effects.embedded_content_written", "Provider-reported embedded-content write effect.", _UNAVAILABLE),
    BehavioralFeatureDefinition("network_activity_indicator", "boolean", "indicator", "network", "Whether any observed DNS, connection, or HTTP activity exists.", _UNAVAILABLE),
)

FEATURE_NAMES: tuple[str, ...] = tuple(feature.name for feature in BEHAVIORAL_FEATURES)


def feature_schema_dict() -> dict[str, Any]:
    """Return the immutable schema metadata in deterministic feature order."""
    return {
        "schema_version": DYNAMIC_SCHEMA_VERSION,
        "feature_count": len(BEHAVIORAL_FEATURES),
        "features": [feature.to_dict() for feature in BEHAVIORAL_FEATURES],
    }
