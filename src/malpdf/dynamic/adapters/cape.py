"""CAPEv2-like *offline JSON* adapter.

It intentionally accepts reports already produced elsewhere.  This module has
no submission, URL, subprocess, or file-execution capability.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from malpdf.dynamic.adapters.base import SandboxReportAdapter
from malpdf.dynamic.result import DynamicWarning, NormalizedBehavioralReport


def _mapping(value: Any, path: str, warnings: list[DynamicWarning]) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    warnings.append(DynamicWarning("MALFORMED_SECTION", "Expected an object; section is unavailable.", path))
    return None


def _records(value: Any, path: str, warnings: list[DynamicWarning]) -> list[Mapping[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        warnings.append(DynamicWarning("MALFORMED_SECTION", "Expected a list; section is unavailable.", path))
        return None
    records: list[Mapping[str, Any]] = []
    for item in value:
        if isinstance(item, Mapping):
            records.append(item)
        else:
            warnings.append(DynamicWarning("MALFORMED_RECORD", "Ignoring a non-object record.", path))
    return records


def _nonnegative_number(value: Any, path: str, warnings: list[DynamicWarning]) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or float(value) < 0:
        warnings.append(DynamicWarning("MALFORMED_VALUE", "Expected a finite non-negative number; value is unavailable.", path))
        return None
    return float(value)


def _optional_records(section: Mapping[str, Any] | None, key: str, path: str, warnings: list[DynamicWarning]) -> list[Mapping[str, Any]] | None:
    if section is None or key not in section:
        return None
    return _records(section[key], path, warnings)


def _explicit_indicator(section: Mapping[str, Any] | None, key: str, path: str, warnings: list[DynamicWarning]) -> bool | None:
    if section is None or key not in section:
        return None
    value = section[key]
    if isinstance(value, bool):
        return value
    warnings.append(DynamicWarning("MALFORMED_VALUE", "Expected a boolean indicator; value is unavailable.", path))
    return None


def _signature_indicator(signatures: list[Mapping[str, Any]] | None, terms: tuple[str, ...]) -> bool | None:
    if signatures is None:
        return None
    names = " ".join(
        str(item.get("name", "")).lower() + " " + str(item.get("description", "")).lower()
        for item in signatures
    )
    return any(term in names for term in terms)


def _is_executable_drop(record: Mapping[str, Any]) -> bool:
    """Classify only a provider's type/name metadata; no file content is read."""
    name = str(record.get("name", record.get("filename", ""))).lower()
    kind = str(record.get("type", record.get("file_type", ""))).lower()
    return name.endswith((".exe", ".dll", ".scr", ".com")) or "executable" in kind or "pe32" in kind


def _process_stats(records: list[Mapping[str, Any]] | None) -> tuple[int | None, int | None, int | None]:
    if records is None:
        return None, None, None
    if not records:
        return 0, 0, 0
    parent_links: dict[str, str] = {}
    child_count = 0
    for index, item in enumerate(records):
        child_id = str(item.get("process_id", item.get("pid", index)))
        parent = item.get("parent_id", item.get("ppid"))
        explicit_children = item.get("children")
        if parent is not None:
            child_count += 1
            parent_links[child_id] = str(parent)
        if isinstance(explicit_children, Sequence) and not isinstance(explicit_children, (str, bytes, bytearray)):
            child_count += len(explicit_children)

    maximum_depth = 1
    for child in parent_links:
        depth, current, seen = 1, child, {child}
        while current in parent_links and parent_links[current] not in seen:
            current = parent_links[current]
            seen.add(current)
            depth += 1
        maximum_depth = max(maximum_depth, depth)
    return len(records), child_count, maximum_depth


class CapeV2ReportAdapter(SandboxReportAdapter):
    """Normalize a small, documented CAPEv2-like JSON subset without retaining payloads."""

    provider = "CAPEv2"
    adapter_version = "capev2-json-adapter-v1"

    def normalize(self, report: Mapping[str, Any]) -> NormalizedBehavioralReport:
        if not isinstance(report, Mapping):
            raise TypeError("Sandbox report must be a JSON object mapping")
        warnings: list[DynamicWarning] = []
        info = _mapping(report.get("info"), "info", warnings)
        status_value = (info or {}).get("status", report.get("status", "unknown"))
        status = str(status_value).lower() if isinstance(status_value, str) else "unknown"
        if status not in {"completed", "reported", "success", "failed", "error", "incomplete", "unknown"}:
            warnings.append(DynamicWarning("UNKNOWN_STATUS", "Unrecognized analysis status was normalized to unknown.", "info.status"))
            status = "unknown"
        normalized_status = "completed" if status in {"completed", "reported", "success"} else status
        analysis_id_value = (info or {}).get("id", report.get("analysis_id"))
        analysis_id = str(analysis_id_value) if isinstance(analysis_id_value, (str, int)) else None
        duration_value = (info or {}).get("duration", report.get("duration"))
        duration = None if duration_value is None else _nonnegative_number(duration_value, "info.duration", warnings)

        failed = normalized_status in {"failed", "error"}
        behavior = _mapping(report.get("behavior"), "behavior", warnings)
        summary = _mapping((behavior or {}).get("summary"), "behavior.summary", warnings)
        network = _mapping(report.get("network"), "network", warnings)
        pdf_effects = _mapping(report.get("pdf_effects"), "pdf_effects", warnings)
        processes = _records((behavior or {}).get("processes"), "behavior.processes", warnings) if behavior and "processes" in behavior else None
        dropped = _records(report.get("dropped"), "dropped", warnings) if "dropped" in report else None
        signatures = _records(report.get("signatures"), "signatures", warnings) if "signatures" in report else None

        created = _optional_records(summary, "files", "behavior.summary.files", warnings)
        modified = _optional_records(summary, "modified_files", "behavior.summary.modified_files", warnings)
        deleted = _optional_records(summary, "deleted_files", "behavior.summary.deleted_files", warnings)
        keys_created = _optional_records(summary, "keys", "behavior.summary.keys", warnings)
        keys_modified = _optional_records(summary, "modified_keys", "behavior.summary.modified_keys", warnings)
        commands = _optional_records(summary, "executed_commands", "behavior.summary.executed_commands", warnings)
        dns = _optional_records(network, "dns", "network.dns", warnings)
        tcp = _optional_records(network, "tcp", "network.tcp", warnings)
        udp = _optional_records(network, "udp", "network.udp", warnings)
        http = _optional_records(network, "http", "network.http", warnings)
        process_count, child_count, process_depth = _process_stats(processes)

        unique_domains: int | None = None
        if dns is not None:
            values = {str(item[key]).lower() for item in dns for key in ("request", "domain", "hostname") if item.get(key) is not None}
            unique_domains = len(values)

        explicit_spawn = _explicit_indicator(pdf_effects, "external_application_spawned", "pdf_effects.external_application_spawned", warnings)
        embedded_written = _explicit_indicator(pdf_effects, "embedded_content_written", "pdf_effects.embedded_content_written", warnings)
        indicators = {
            "persistence_indicator": _signature_indicator(signatures, ("persist", "autorun", "run key")),
            "process_injection_indicator": _signature_indicator(signatures, ("inject", "process hollow")),
            "anti_analysis_indicator": _signature_indicator(signatures, ("anti-analysis", "anti analysis", "anti-vm", "anti vm", "sandbox")),
            "shell_activity_indicator": None if commands is None else bool(commands),
            "external_process_spawn_indicator": explicit_spawn if explicit_spawn is not None else (None if child_count is None else child_count > 0),
            "embedded_content_written_indicator": embedded_written,
        }
        connection_count = None if tcp is None and udp is None else (len(tcp or []) + len(udp or []))
        activity_inputs = [value for value in (None if dns is None else len(dns), connection_count, None if http is None else len(http))]
        indicators["network_activity_indicator"] = True if any(value is not None and value > 0 for value in activity_inputs) else (False if all(value is not None for value in activity_inputs) else None)

        availability = {
            "processes": processes is not None,
            "filesystem": any(value is not None for value in (created, modified, deleted, dropped)),
            "registry": any(value is not None for value in (keys_created, keys_modified, signatures)),
            "network": any(value is not None for value in (dns, tcp, udp, http)),
            "behavior": any(value is not None for value in (commands, signatures)),
            "pdf_effects": pdf_effects is not None,
        }
        observations: dict[str, Any] = {
            "processes": {"process_count": process_count, "child_process_count": child_count, "max_process_tree_depth": process_depth},
            "filesystem": {
                "file_created_count": None if created is None else len(created),
                "file_modified_count": None if modified is None else len(modified),
                "file_deleted_count": None if deleted is None else len(deleted),
                "dropped_file_count": None if dropped is None else len(dropped),
                "dropped_executable_count": None if dropped is None else sum(_is_executable_drop(item) for item in dropped),
            },
            "registry": {
                "registry_create_count": None if keys_created is None else len(keys_created),
                "registry_modify_count": None if keys_modified is None else len(keys_modified),
            },
            "network": {
                "dns_query_count": None if dns is None else len(dns),
                "unique_domain_count": unique_domains,
                "network_connection_count": connection_count,
                "http_request_count": None if http is None else len(http),
            },
            "indicators": indicators,
        }
        if failed:
            warnings.append(DynamicWarning("ANALYSIS_FAILED", "Analysis failed; behavioral values are unavailable.", "info.status"))
            availability = {key: False for key in availability}
            for section in observations.values():
                for key in section:
                    section[key] = None
        return NormalizedBehavioralReport(
            provider=self.provider,
            analysis_id=analysis_id,
            status=normalized_status,
            duration_seconds=duration,
            section_availability=availability,
            observations=observations,
            warnings=tuple(warnings),
            adapter_version=self.adapter_version,
            raw_report_type="capev2-like-json",
        )


def parse_cape_report_file(path: str | Path) -> NormalizedBehavioralReport:
    """Read a local JSON report as inert data, then normalize its compact evidence."""
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError("Sandbox report JSON must contain an object")
    return CapeV2ReportAdapter().normalize(payload)
