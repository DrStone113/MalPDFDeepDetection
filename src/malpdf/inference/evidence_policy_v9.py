"""Frozen LAB C1 eligibility with explicit model and graph dependencies.

This module does not fit, calibrate, add model predictors, execute PDF content,
or treat an action graph as a malware rule. Its label needs the unchanged ML
score as well as verified evidence under the locked input contract.
"""

from __future__ import annotations

from collections import deque
import hashlib
import json
import math
import re

POLICY_ID = "c1-v9-frozen-ml-linked-evidence-v1"
SCHEMA = "pdf-evidence-v9"
MANDATORY_CAPABILITIES = ("catalog", "actions", "scripts", "xfa", "embedded")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERIFIED = frozenset({"verified", "complete", "observed", "absent_after_complete_check"})
_COMPLETE = frozenset({"complete", "not_applicable"})


def _missing_names(missing_supported):
    if isinstance(missing_supported, dict):
        if any(type(value) is not bool for value in missing_supported.values()):
            raise ValueError("Frozen missingness support must contain booleans")
        return {name for name, value in missing_supported.items() if value}
    return set(missing_supported or ())


def _id_list(value):
    return isinstance(value, list) and all(isinstance(identifier, str) for identifier in value)


def frozen_feature_order():
    """Reuse the v8 adapter; the graph never adds or redefines model columns."""
    from malpdf.experiments.cic_v8 import v8_feature_values
    return tuple(v8_feature_values({}))


def build_dependency_ledger(feature_names, *, missing_supported=None):
    """Describe the original semantics of every requested frozen predictor.

    Missingness support is an immutable property of the fitted imputer's
    indicator columns, supplied only after guarded loading of the frozen model.
    Preparation can describe the ledger without loading that binary artifact.
    """
    from malpdf.static.schema import RIT_FEATURES, _VERIFIED_RAW_FEATURES
    names = tuple(feature_names)
    expected = set(frozen_feature_order())
    if len(names) != len(set(names)) or any(name not in expected for name in names):
        raise ValueError("Unknown or duplicate frozen C1 feature")
    supported = None if missing_supported is None else _missing_names(missing_supported)
    if (supported is not None and not supported <= expected
            or isinstance(missing_supported, dict) and not set(missing_supported) <= expected):
        raise ValueError("Unknown frozen imputer missingness feature")
    output = []
    for name in names:
        backend, completion, meaning, scope = "primary", False, "observed_lower_bound", "contributing_verified_observations"
        if name in RIT_FEATURES:
            if name in _VERIFIED_RAW_FEATURES or name == "pdfsize":
                meaning, scope = "original_raw_measurement", "immutable_original_bytes"
            else:
                meaning, scope, completion = "original_reference_measurement", "original_reference_method", True
                backend = "PyMuPDF-reference"
        elif name.startswith(("structure_", "ast_", "call_")) or name == "scripts_found":
            meaning, scope, completion = "complete_total", "primary_complete_structure_or_script_analysis", True
            if name == "ast_complete":
                meaning, scope, completion = "recorded_stage_outcome", "primary_code_stage", False
        elif name.startswith(("parser_", "code_")) or name in {
                "traversal_complete", "script_extraction_complete", "reference_parser_repaired"}:
            meaning, scope = "recorded_stage_outcome", "recorded_primary_stage"
        elif name.startswith(("v8_action_", "v8_embedded_")):
            meaning, scope = "observed_count_or_checked_absence", "selected_v8_backend_enumeration"
        elif name.startswith("v8_"):
            backend = "MuPDF" if name.startswith("v8_MuPDF_") else "pypdf"
            scope = "completed_script_summaries_in_recorded_backend"
        output.append({"feature": name, "source": backend, "scope": scope,
            "meaning": meaning, "completion_required": completion,
            "zero_requires_completed_enumeration": meaning == "observed_count_or_checked_absence",
            "supported_missingness": "not_verified_until_offline_frozen_load" if supported is None else name in supported,
            "preprocessing": "unchanged Train-only median and original missing indicators",
            "contract": "original v8 value; no total-to-lower-bound conversion"})
    return output


def _index_analysis(analysis):
    """Validate referential integrity before following user-derived objects."""
    if not isinstance(analysis, dict) or analysis.get("schema_version") != SCHEMA:
        return {}, {}, {}, ["v9_evidence_unavailable"]
    digest = analysis.get("document_sha256")
    if not isinstance(digest, str) or not _HASH.fullmatch(digest):
        return {}, {}, {}, ["document_identity_unverified"]
    observations, edges, checks, all_ids, reasons = {}, {}, {}, set(), []
    if analysis.get("original_bytes_changed") is not False or analysis.get("active_content_executed") is not False:
        reasons.append("immutable_nonexecuting_analysis_unverified")
    for key, destination in (("observations", observations), ("edges", edges), ("capability_checks", checks)):
        values = analysis.get(key)
        if not isinstance(values, list):
            reasons.append("evidence_graph_malformed")
            continue
        for value in values:
            if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"] or value["id"] in all_ids:
                reasons.append("evidence_graph_malformed")
                continue
            all_ids.add(value["id"])
            destination[value["id"]] = value
    for value in observations.values():
        if value.get("document_sha256") != digest or not isinstance(value.get("backend"), str):
            reasons.append("observation_provenance_unverified")
    for edge in edges.values():
        if (not isinstance(edge.get("source"), str) or not isinstance(edge.get("target"), str)
                or edge["source"] not in observations or edge["target"] not in observations):
            reasons.append("edge_target_unverified")
        elif (observations[edge["source"]].get("backend") != observations[edge["target"]].get("backend")
                and not (observations[edge["source"]].get("kind") == "document"
                    and observations[edge["source"]].get("backend") == "original"
                    and observations[edge["source"]].get("immutable") is True
                    and edge.get("kind") in {"document_catalog", "document_acroform", "document_page"})):

            reasons.append("cross_backend_identity_unverified")
        support = edge.get("supporting_ids", [])
        if not _id_list(support) or any(identifier not in all_ids for identifier in support):
            reasons.append("edge_dependency_provenance_unverified")
        elif any(identifier in observations and observations[identifier].get("status") not in _VERIFIED for identifier in support):
            reasons.append("edge_dependency_provenance_unverified")
    for check in checks.values():
        for field in ("scope_ids", "required_ids", "reason_codes"):
            if not _id_list(check.get(field, [])):
                reasons.append("evidence_graph_malformed")
        if (_id_list(check.get("required_ids", []))
                and any(identifier not in all_ids for identifier in check.get("required_ids", []))):
            reasons.append("capability_provenance_unverified")
        if check.get("status") == "not_applicable" and not check.get("required_ids"):
            reasons.append("capability_nonapplicability_unverified")
    return observations, edges, checks, sorted(set(reasons))


def derive_feature_provenance(profile, analysis):
    """Project immutable original measurements into per-column provenance.

    The checkpoint digest covers the *entire* legacy numeric source. It is not
    a new measurement or a replacement for missing extraction. Backend object
    dependencies are added only when the same original projection is verified;
    cross-backend number/generation equality never establishes identity.
    """
    from malpdf.experiments.cic_v8 import v8_feature_values
    static, code, legacy = profile.get("static") or {}, profile.get("code") or {}, profile.get("analysis_v8")
    serialized = json.dumps({"static": profile.get("static"), "code": profile.get("code"), "analysis_v8": legacy},
                            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    digest = hashlib.sha256(serialized).hexdigest()
    checkpoints = [item for item in analysis.get("observations", []) if item.get("kind") == "primary_model_inputs"
                   and item.get("status") == "verified" and item.get("measurement_sha256") == digest]
    if len(checkpoints) != 1:
        return {}
    checkpoint = checkpoints[0]
    if static.get("input", {}).get("sha256") != analysis.get("document_sha256"):
        return {}
    all_nodes = {item["id"]: item for item in analysis.get("observations", [])}
    objects = {(item.get("backend"), item.get("object_number"), item.get("generation")): item
               for item in all_nodes.values() if type(item.get("object_number")) is int and "projection" in item}
    legacy_views = {item["backend"]: item for item in (legacy or {}).get("backends", [])}
    check_by_backend = {(check.get("backend"), check.get("capability")): check
                        for check in analysis.get("capability_checks", [])}
    values = v8_feature_values(profile)
    provenance = {}
    ast_dependencies = {}
    def completed_ast_sources(backend, view):
        key = backend, id(view)
        if key in ast_dependencies:
            return ast_dependencies[key]
        identifiers, failures = set(), []
        completed = [source for source in view.get("script_sources", []) if source.get("ast_status") == "complete"]
        if type(view.get("scripts_parsed")) is not int or len(completed) != view["scripts_parsed"]:
            failures.append("model_script_ast_provenance_unverified")
        for source in completed:
            digest, summary = source.get("decoded_sha256"), source.get("ast_summary")
            if (source.get("decoded_validated") is not True or not isinstance(digest, str)
                    or not _HASH.fullmatch(digest) or not isinstance(summary, dict)):
                failures.append("model_script_ast_provenance_unverified")
                continue
            candidates = [item for item in all_nodes.values() if item.get("backend") == backend and item.get("kind") == "script"
                and item.get("ast_status") == "complete" and item.get("decoded_validated") is True
                and item.get("decoded_sha256") == digest and item.get("ast_summary") == summary]
            if not candidates:
                failures.append("model_script_ast_provenance_unverified")
            for item in candidates:
                identifiers.add(item["id"])
                for field in ("extraction_evidence_id", "source_object_id"):
                    if item.get(field) in all_nodes:
                        identifiers.add(item[field])
        ast_dependencies[key] = sorted(identifiers), sorted(set(failures))
        return ast_dependencies[key]
    metadata_failures = {
        "metadata size": {"reference_metadata_unavailable"}, "title length": {"reference_metadata_unavailable"},
        "pdf_ver": {"reference_pdf_version_unavailable"}, "isEncrypted": {"reference_encryption_unavailable"},
        "xref length": {"reference_xref_length_unavailable", "reference_object_limit"},
        "pages": {"reference_page_count_unavailable", "reference_page_limit"},
        "images": {"reference_image_count_failure"},
        "contains_text": {"reference_text_or_attachment_failure", "reference_page_text_partial"},
        "embedded files": {"reference_text_or_attachment_failure"}}
    errors = {item.get("code") for item in static.get("errors", []) if isinstance(item, dict)} | set(static.get("warnings", []))
    for entry in build_dependency_ledger(values):
        name, value = entry["feature"], values[entry["feature"]]
        missing = value is None
        source_ids, required_check_ids, reasons = [checkpoint["id"]], [], []
        complete = False
        if name in metadata_failures:
            complete = not errors & metadata_failures[name] and value is not None
        elif entry["meaning"] == "complete_total":
            complete = code.get("traversal_complete") is True if name == "scripts_found" or name.startswith("structure_") else code.get("ast_complete") is True
        elif entry["meaning"] == "observed_count_or_checked_absence" and not missing:
            original_name = name.removeprefix("v8_")
            facts = [fact for fact in (legacy or {}).get("features", []) if fact.get("name") == original_name
                     and fact.get("status") in {"observed", "absent_after_complete_check"}]
            selected = next((fact for fact in facts if fact.get("source") == "pypdf"), facts[0] if facts else None)
            if selected is None or selected.get("value") != value:
                reasons.append("original_feature_measurement_unverified")
            else:
                backend = selected["source"]
                complete = selected.get("complete") is True
                for identifier in selected.get("evidence_ids", []):
                    parts = identifier.split(":")
                    if len(parts) != 3 or parts[0] != backend or not all(part.isdigit() for part in parts[1:]):
                        continue
                    key = backend, int(parts[1]), int(parts[2])
                    candidate = objects.get(key)
                    projection = legacy_views.get(backend, {}).get("graph", {}).get("objects", {}).get(identifier)
                    if candidate and projection == candidate.get("projection"):
                        source_ids.append(candidate["id"])
                    elif candidate:
                        reasons.append("original_feature_object_projection_conflict")
                if value == 0:
                    check = check_by_backend.get((backend, "embedded" if "embedded" in name else "actions"))
                    if check:
                        required_check_ids.append(check["id"])
        elif entry["scope"] == "immutable_original_bytes":
            source = all_nodes.get(checkpoint.get("source_object_id"))
            if source and source.get("kind") == "document" and source.get("immutable") is True:
                source_ids.append(source["id"])
            else:
                reasons.append("original_byte_provenance_unverified")
        ast_source = None
        if name != "ast_complete" and name.startswith(("ast_", "call_", "observed_ast_", "observed_call_")) or name == "observed_scripts_parsed":
            ast_source = "pypdf", code
        elif name.startswith(("v8_pypdf_ast_", "v8_pypdf_call_")) or name == "v8_pypdf_scripts_parsed":
            ast_source = "pypdf", legacy_views.get("pypdf", {}).get("code") or {}
        elif name.startswith(("v8_MuPDF_ast_", "v8_MuPDF_call_")) or name == "v8_MuPDF_scripts_parsed":
            ast_source = "MuPDF", legacy_views.get("MuPDF", {}).get("code") or {}
        if not missing and ast_source:
            identifiers, failures = completed_ast_sources(*ast_source)
            source_ids.extend(identifiers)
            reasons.extend(failures)
        provenance[name] = {"status": "unknown" if missing else "verified", "value": value,
            "source_ids": sorted(set(source_ids)), "required_check_ids": required_check_ids,
            "completion_status": "complete" if complete else "partial", "reason_codes": reasons,
            "source_measurement_sha256": digest}
    return provenance


def verify_model_inputs(profile, feature_names, analysis, *, missing_supported=None):
    """Verify each original input, including explicit supported unknown values.

    The extractor records provenance separately from the legacy numeric view.
    No numeric sentinel is silently replaced, and a recorded missing input needs
    both its stage evidence and a frozen imputer column that saw missingness.
    """
    from malpdf.experiments.cic_v8 import v8_feature_values
    names = tuple(feature_names)
    reasons, dependencies, required_ids, required_checks = [], [], set(), set()
    observations, edges, checks, graph_reasons = _index_analysis(analysis)
    reasons.extend(graph_reasons)
    if names != frozen_feature_order():
        reasons.append("model_feature_order_unverified")
    try:
        ledger = build_dependency_ledger(names, missing_supported=missing_supported)
        values = v8_feature_values(profile)
    except (ValueError, TypeError, KeyError, OverflowError):
        return {"verified": False, "reason_codes": ["model_contract_unverified"], "required_ids": [],
                "required_checks": [], "dependencies": [], "feature_order": list(names), "profile_complete": False}
    static, code = profile.get("static") or {}, profile.get("code") or {}
    digest = (static.get("input") or {}).get("sha256")
    if digest != (analysis or {}).get("document_sha256") or digest != profile.get("pdf_sha256"):
        reasons.append("model_snapshot_identity_unverified")
    provenance = (analysis or {}).get("feature_provenance") or {}
    if "primary_model_inputs" in provenance and not any(name in provenance for name in names):
        provenance = derive_feature_provenance(profile, analysis)
    all_ids = observations.keys() | edges.keys() | checks.keys()
    supported = _missing_names(missing_supported)
    for entry in ledger:
        name, value = entry["feature"], values.get(entry["feature"])
        fact = provenance.get(name)
        feature_reasons = []
        if not isinstance(fact, dict):
            fact = {}
            feature_reasons.append("model_input_provenance_unverified")
        feature_reasons.extend(fact.get("reason_codes", []))
        ids = fact.get("source_ids", fact.get("evidence_ids", []))
        check_ids = fact.get("required_check_ids", [])
        if (not _id_list(ids) or not ids or any(identifier not in all_ids for identifier in ids)
                or not _id_list(check_ids) or any(identifier not in checks for identifier in check_ids)):
            feature_reasons.append("model_input_provenance_unverified")
            ids, check_ids = [], []
        if any(identifier in observations and observations[identifier].get("status") not in _VERIFIED for identifier in ids):
            feature_reasons.append("model_input_observation_unverified")
        missing = value is None or type(value) in (float, int) and math.isnan(float(value))
        if missing:
            if name not in supported:
                feature_reasons.append("model_missingness_unsupported")
            if fact.get("status") != "unknown":
                feature_reasons.append("model_unknown_input_unverified")
        else:
            if type(value) not in (int, float, bool) or not math.isfinite(float(value)):
                feature_reasons.append("model_input_invalid")
            if fact.get("status") not in _VERIFIED:
                feature_reasons.append("model_input_provenance_unverified")
            must_complete = entry["completion_required"] or entry["zero_requires_completed_enumeration"] and value == 0
            if must_complete and ((fact.get("completion_status") != "complete" and not check_ids)
                    or any(checks[identifier].get("status") not in _COMPLETE for identifier in check_ids)):
                feature_reasons.append("model_input_completion_unverified")
            if fact.get("value") is not None and fact["value"] != value:
                feature_reasons.append("model_input_value_conflict")
        dependencies.append({**entry, "value_status": "unknown" if missing else "measured",
            "required_ids": ids, "required_checks": check_ids, "reason_codes": sorted(set(feature_reasons))})
        reasons.extend(feature_reasons)
        required_ids.update(ids)
        required_checks.update(check_ids)
    primary_complete = bool(profile.get("primary_status", profile.get("status")) == "complete"
        and static.get("parser", {}).get("success") is True
        and static.get("parser", {}).get("structural_complete") is True
        and not static.get("parser", {}).get("resource_limit_reached")
        and not static.get("errors") and code.get("complete") is True
        and code.get("ast_complete") is True and code.get("script_extraction_complete") is True
        and code.get("traversal_complete") is True)
    return {"verified": not reasons, "reason_codes": sorted(set(reasons)), "required_ids": sorted(required_ids),
        "required_checks": sorted(required_checks), "dependencies": dependencies, "feature_order": list(names),
        "profile_complete": primary_complete, "provenance": "immutable primary measurements and recorded v8 backend inputs"}


def _valid_identity(identity):
    if not isinstance(identity, dict):
        return False
    names = identity.get("feature_order")
    count = identity.get("feature_count", len(names) if isinstance(names, (list, tuple)) else 0)
    return bool(isinstance(identity, dict) and identity.get("model_id") == "c1-v8-fixed-rf-evidence-v1"
        and identity.get("train_rows", identity.get("training_rows")) == 31
        and count == 173
        and identity.get("threshold") == 0.5 and isinstance(identity.get("artifact_sha256"), str)
        and _HASH.fullmatch(identity["artifact_sha256"]))


def _closure_blockers(analysis, ids, feature_names, checks):
    reasons, resources = [], []
    conflicts = analysis.get("conflicts", [])
    if not isinstance(conflicts, list):
        return ["conflict_provenance_unverified"], []
    for conflict in conflicts:
        if not isinstance(conflict, dict) or conflict.get("localized") is not True:
            reasons.append("unlocalized_backend_conflict")
            continue
        affected, fields = conflict.get("affected_ids", []), conflict.get("fields", [])
        if not _id_list(affected) or not _id_list(fields) or not affected and not fields:
            reasons.append("conflict_provenance_unverified")
        elif set(affected) & ids or set(fields) & feature_names:
            reasons.append("dependency_backend_conflict")
    for check in checks.values():
        if check.get("status") in _COMPLETE:
            continue
        scope = set(check.get("scope_ids", [])) | set(check.get("required_ids", []))
        codes = check.get("reason_codes", [])
        limited = check.get("status") == "resource_limited" or any("limit" in code for code in codes if isinstance(code, str))
        if limited:
            resources.extend(codes or ["resource_limit"])
        if check["id"] in ids or scope & ids:
            reasons.append("dependency_resource_limit" if limited else "dependency_check_incomplete")
        elif limited and not scope:
            reasons.append("unlocalized_resource_limit")
    return sorted(set(reasons)), sorted(set(resources))


def _eligible_witnesses(observations, edges):
    """Follow legal typed paths rather than trusting a cached witness flag."""
    adjacency = {}
    for edge in edges.values():
        if edge.get("status") == "verified" and not edge.get("reason_codes"):
            adjacency.setdefault(edge["source"], []).append(edge)
    verified = lambda node: node.get("status") in _VERIFIED
    def step(path, edge, target):
        return path + [edge["id"], target["id"]] + edge.get("supporting_ids", [])
    documents = [node["id"] for node in observations.values() if node.get("kind") == "document" and verified(node)]

    contain = {"document_catalog": ({"document"}, {"catalog"}),
               "catalog_pages": ({"catalog"}, {"pages"}),
               "pages_child": ({"pages"}, {"pages", "page"}),
               "page_annotation": ({"page"}, {"annotation"}),
               "document_acroform": ({"document", "catalog"}, {"form"}),
               "form_field": ({"form", "field"}, {"field"})}
    legal_origins, action_paths = {}, {}
    pending = deque((identifier, [identifier]) for identifier in documents)
    while pending:
        identifier, path = pending.popleft()
        if identifier in legal_origins:
            continue
        legal_origins[identifier] = path
        for edge in adjacency.get(identifier, []):
            target = observations[edge["target"]]
            relationship = contain.get(edge.get("kind"))
            if (relationship and observations[identifier].get("kind") in relationship[0]
                    and target.get("kind") in relationship[1] and verified(target)):
                pending.append((target["id"], step(path, edge, target)))
    for identifier, path in legal_origins.items():
        origin = observations[identifier]
        expected = {"catalog": "catalog_action", "page": "page_action", "annotation": "annotation_action",
                    "form": "form_action", "field": "field_action"}.get(origin.get("kind"))
        for edge in adjacency.get(identifier, []):
            target = observations[edge["target"]]
            if expected is not None and edge.get("kind") == expected and target.get("kind") == "action" and verified(target):
                pending.append((target["id"], step(path, edge, target)))
    while pending:
        identifier, path = pending.popleft()
        if identifier in action_paths:
            continue
        action_paths[identifier] = path
        for edge in adjacency.get(identifier, []):
            target = observations[edge["target"]]
            if edge.get("kind") == "action_Next" and target.get("kind") == "action" and verified(target):
                pending.append((target["id"], step(path, edge, target)))
    def script_complete(node):
        return bool(verified(node) and node.get("kind") == "script" and node.get("extraction_status") == "complete"
            and node.get("ast_status") == "complete" and isinstance(node.get("ast_summary"), dict)
            and node.get("decoded_validated") is True and isinstance(node.get("raw_sha256"), str)
            and _HASH.fullmatch(node["raw_sha256"]) and isinstance(node.get("decoded_sha256"), str)
            and _HASH.fullmatch(node["decoded_sha256"]))
    witnesses = []
    for identifier, path in action_paths.items():
        action = observations[identifier]
        if action.get("action_kind") == "/JavaScript":
            for edge in adjacency.get(identifier, []):
                target = observations[edge["target"]]
                if edge.get("kind") == "action_JS" and script_complete(target):
                    witnesses.append({"family": "pdf_javascript", "terminal_id": target["id"],
                        "supporting_ids": step(path, edge, target)})
        if action.get("action_kind") == "/Launch":
            for edge in adjacency.get(identifier, []):
                filespec = observations[edge["target"]]
                if edge.get("kind") != "Launch_filespec" or filespec.get("kind") != "filespec" or not verified(filespec):
                    continue
                for embedded in adjacency.get(filespec["id"], []):
                    payload = observations[embedded["target"]]
                    if (embedded.get("kind") == "filespec_EF" and payload.get("kind") == "payload" and verified(payload)
                            and payload.get("extraction_status") == "complete" and payload.get("decoded_validated") is True
                            and payload.get("magic") in {"pe", "elf"} and isinstance(payload.get("decoded_sha256"), str)
                            and _HASH.fullmatch(payload["decoded_sha256"])):
                        witnesses.append({"family": "embedded_launch", "terminal_id": payload["id"],
                            "supporting_ids": step(step(path, edge, filespec), embedded, payload)})
    for identifier, path in legal_origins.items():
        if observations[identifier].get("kind") != "form":
            continue
        packets = []
        for packet_edge in adjacency.get(identifier, []):
            packet = observations[packet_edge["target"]]
            if packet_edge.get("kind") != "acroform_xfa" or not verified(packet):
                continue
            if packet.get("kind") == "xfa_packet":
                packets.append((packet, step([], packet_edge, packet)))
            for child in adjacency.get(packet["id"], []):
                target = observations[child["target"]]
                if child.get("kind") == "xfa_packet" and target.get("kind") == "xfa_packet" and verified(target):
                    packets.append((target, step(step([], packet_edge, packet), child, target)))
        for packet, packet_path in packets:
            for event_edge in adjacency.get(packet["id"], []):
                event = observations[event_edge["target"]]
                if event_edge.get("kind") != "XFA_event" or event.get("kind") != "xfa_event" or not verified(event):
                    continue
                for script_edge in adjacency.get(event["id"], []):
                    script = observations[script_edge["target"]]
                    if script_edge.get("kind") == "event_script" and script_complete(script):
                        witnesses.append({"family": "xfa_javascript", "terminal_id": script["id"],
                            "supporting_ids": step(step(path + packet_path, event_edge, event), script_edge, script)})
    return witnesses


def evidence_decision_v9(probability, analysis, *, input_available, model_identity, model_contract):
    """Return an actual ML label or abstention with the selected dependency set."""
    observations, edges, checks, reasons = _index_analysis(analysis)
    graph_invalid = bool(reasons)
    if not isinstance(analysis, dict):
        analysis = {}
    score_available = type(probability) in (int, float) and math.isfinite(probability) and 0 <= probability <= 1
    if not score_available:
        reasons.append("model_score_unavailable")
    if input_available is not True:
        reasons.append("verified_input_unavailable")
    if not _valid_identity(model_identity):
        reasons.append("frozen_model_identity_unverified")
    contract = model_contract if isinstance(model_contract, dict) else {}
    if contract.get("verified") is not True:
        codes = contract.get("reason_codes")
        reasons.extend(codes if _id_list(codes) and codes else ["model_contract_unverified"])
    if contract.get("feature_order") != list(frozen_feature_order()):
        reasons.append("model_feature_order_unverified")
    all_ids = observations.keys() | edges.keys() | checks.keys()
    required_ids, required_checks = contract.get("required_ids", []), contract.get("required_checks", [])
    if (not _id_list(required_ids) or not required_ids or any(identifier not in all_ids for identifier in required_ids)
            or not _id_list(required_checks) or any(identifier not in checks for identifier in required_checks)):
        reasons.append("model_input_provenance_unverified")
        required_ids, required_checks = [], []
    closure = set(required_ids) | set(required_checks)
    feature_names = set(frozen_feature_order())
    blockers, resources = ([], []) if graph_invalid else _closure_blockers(analysis, closure, feature_names, checks)
    reasons.extend(blockers)
    primary_complete = contract.get("profile_complete") is True and (analysis or {}).get("primary_profile_complete") is True
    mandatory = {cap: [check for check in checks.values() if check.get("capability") == cap
                       and check.get("backend", "pypdf") == "pypdf"]
                 for cap in MANDATORY_CAPABILITIES}
    complete_checks = all(values and all(check.get("status") in _COMPLETE for check in values) for values in mandatory.values())
    selected = None
    if not reasons and score_available:
        if probability < 0.5:
            if not primary_complete:
                reasons.append("incomplete_negative")
            if not complete_checks:
                reasons.append("mandatory_checks_incomplete")
            else:
                for values in mandatory.values():
                    closure.update(check["id"] for check in values)
                    closure.update(identifier for check in values for identifier in check.get("required_ids", []))
        elif not primary_complete or not complete_checks:
            candidates = _eligible_witnesses(observations, edges)
            candidate_reasons = []
            for witness in candidates:
                candidate_closure = closure | set(witness["supporting_ids"])
                blocked, _ = _closure_blockers(analysis, candidate_closure, feature_names, checks)
                if not blocked:
                    selected, closure = witness, candidate_closure
                    break
                candidate_reasons.extend(blocked)
            if selected is None:
                reasons.extend(candidate_reasons or ["linked_evidence_unavailable"])
        else:
            closure.update(check["id"] for values in mandatory.values() for check in values)
        final_blockers, _ = _closure_blockers(analysis, closure, feature_names, checks)
        reasons.extend(final_blockers)
    reasons = sorted(set(reasons))
    label = None if reasons else int(probability >= 0.5)
    return {"policy": POLICY_ID, "decision": "Inconclusive" if label is None else "Malicious" if label else "Benign",
        "predicted_label": label, "malicious_probability": probability if score_available else None, "threshold": 0.5,
        "model_identity": model_identity, "required_checks": sorted(identifier for identifier in closure if identifier in checks),
        "supporting_evidence_ids": sorted(closure), "evidence_ids": sorted(closure), "selected_witness": selected,
        "blocking_reason_codes": reasons, "reasons": reasons, "resource_error_codes": resources,
        "worker_failure_codes": (analysis or {}).get("worker_failure_codes", []),
        "explanation_scope": "verified eligibility for frozen ML; not proof of malware behavior or execution",
        "operational_action": "allow" if label == 0 else "quarantine", "deployment": False}
