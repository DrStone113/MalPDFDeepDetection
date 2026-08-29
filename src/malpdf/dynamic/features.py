"""Feature extraction and descriptive summaries for normalized sandbox reports."""

from __future__ import annotations

from typing import Any

from malpdf.dynamic.result import BehavioralFeatureSet, DynamicWarning, NormalizedBehavioralReport
from malpdf.dynamic.schema import BEHAVIORAL_FEATURES


_SECTION_BY_FEATURE = {
    **{name: "processes" for name in ("process_count", "child_process_count", "max_process_tree_depth")},
    **{name: "filesystem" for name in ("file_created_count", "file_modified_count", "file_deleted_count", "dropped_file_count", "dropped_executable_count")},
    **{name: "registry" for name in ("registry_create_count", "registry_modify_count", "persistence_indicator")},
    **{name: "network" for name in ("dns_query_count", "unique_domain_count", "network_connection_count", "http_request_count", "network_activity_indicator")},
    **{name: "behavior" for name in ("shell_activity_indicator", "process_injection_indicator", "anti_analysis_indicator")},
    **{name: "pdf_effects" for name in ("external_process_spawn_indicator", "embedded_content_written_indicator")},
}


def extract_behavioral_features(report: NormalizedBehavioralReport) -> BehavioralFeatureSet:
    """Return every v1 feature, keeping unavailable data as ``None`` rather than zero."""
    sources = {definition.name: definition.source_evidence for definition in BEHAVIORAL_FEATURES}
    values: dict[str, int | bool | None] = {}
    for definition in BEHAVIORAL_FEATURES:
        section = _SECTION_BY_FEATURE[definition.name]
        section_values: dict[str, Any]
        if definition.name in report.observations["processes"]:
            section_values = report.observations["processes"]
        elif definition.name in report.observations["filesystem"]:
            section_values = report.observations["filesystem"]
        elif definition.name in report.observations["registry"]:
            section_values = report.observations["registry"]
        elif definition.name in report.observations["network"]:
            section_values = report.observations["network"]
        else:
            section_values = report.observations["indicators"]
        value = section_values.get(definition.name)
        values[definition.name] = value if report.section_availability.get(section, False) or value is not None else None
    return BehavioralFeatureSet(values=values, sources=sources, warnings=report.warnings)


def summarize_behavior(features: BehavioralFeatureSet) -> str:
    """Produce a descriptive-only summary; it never supplies a malware verdict."""
    values = features.values
    def display(name: str) -> str:
        value = values[name]
        return "unavailable" if value is None else str(value).lower() if isinstance(value, bool) else str(value)

    return "\n".join((
        "Dynamic Behavioral Summary (descriptive only)",
        "Processes: " + display("process_count") + " processes; " + display("child_process_count") + " child processes.",
        "Filesystem: " + display("file_created_count") + " created; " + display("dropped_executable_count") + " executable drops.",
        "Network: " + display("dns_query_count") + " DNS queries; " + display("network_connection_count") + " connections.",
        "Indicators: external process spawn=" + display("external_process_spawn_indicator") + "; network activity=" + display("network_activity_indicator") + ".",
    ))
