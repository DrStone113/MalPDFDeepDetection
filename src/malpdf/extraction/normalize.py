"""Adapt immutable v9 checkpoints to three linked, coverage-aware stores."""

from collections import Counter
from copy import deepcopy

from malpdf.extraction.contracts import GROUPS, VERSION, feature, validate_bundle
from malpdf.static.raw_scan import RAW_DIRECT_TOKENS


def failure_status(reasons, default="partial"):
    """Keep missing-data causes distinct; do not expose parser exception text."""
    reasons = " ".join(reasons).lower()
    if "encrypt" in reasons:
        return "encrypted"
    if "timeout" in reasons:
        return "timeout"
    if any(word in reasons for word in ("limit", "budget", "memory", "signal")):
        return "resource_limit"
    if "unsupported" in reasons:
        return "unsupported"
    if any(word in reasons for word in ("decode", "flate")):
        return "decode_error"
    return default


def _record(identifier, kind, backend, status="observed", *, details=None, **locator):
    return {"evidence_id": identifier, "kind": kind, "backend": backend,
            "observation_status": status, "object_number": None, "generation": None,
            "revision": None, "byte_offset_start": None, "byte_offset_end": None,
            "filter_chain": None, "is_synthetic_repaired": False, "details": details or {}, **locator}


def _group(name):
    if name.startswith(("ast_", "call_", "observed_ast_", "observed_call_", "v8_pypdf_ast_",
                        "v8_MuPDF_ast_", "v8_pypdf_call_", "v8_MuPDF_call_")) or "scripts_" in name:
        return "javascript_xfa"
    if name.startswith("v8_action_"):
        return "actions"
    if name.startswith("v8_embedded_"):
        return "embedded_artifacts"
    if name.startswith("structure_"):
        return "object_graph"
    if name in {"obj", "endobj", "ObjStm"}:
        return "objects"
    if name in {"xref", "startxref", "trailer", "xref length"}:
        return "xref_history"
    if name in {"stream", "endstream"}:
        return "streams_filters"
    if name in {"JS", "JavaScript", "XFA"}:
        return "javascript_xfa"
    if name in {"AA", "OpenAction", "Launch", "URI"}:
        return "actions"
    if name in {"EmbeddedFile", "embedded files"}:
        return "embedded_artifacts"
    if name in {"images", "JBIG2Decode", "RichMedia", "BitsPerComponent", "Colors"}:
        return "fonts_images_multimedia"
    if name in {"pages", "contains_text", "page_command"}:
        return "page_visual"
    if name in {"metadata size", "title length", "isEncrypted", "Encrypt", "pdf_ver"}:
        return "metadata_encryption_signatures"
    if name == "pdfsize":
        return "raw_layout"
    return "syntax_tokens"


def normalize_profile(profile, digest, extraction_profile, *, provenance=None):
    """Preserve primary values verbatim and separately describe their scopes.

    A complete lexical check is not a complete semantic check. Unknown offsets
    and historical revisions remain null. Cross-parser observations stay apart.
    """
    profile = deepcopy(profile)
    reasons = sorted(set(profile.get("errors", []) + profile.get("reasons", [])))
    static, raw = profile.get("static") or {}, profile.get("raw_evidence") or {}
    layout, analysis = profile.get("raw_layout") or {}, profile.get("analysis_v9") or {}
    streams = profile.get("stream_analysis") or {}
    for identity in (static.get("input", {}).get("sha256"), raw.get("sha256"),
                     layout.get("sha256"), analysis.get("document_sha256"), streams.get("document_sha256")):
        if identity is not None and identity != digest:
            raise ValueError("extraction_checkpoint_identity_mismatch")
    records, features, edges = [], [], []
    for index, failure in enumerate(profile.get('stage_failures', [])):
        records.append(_record('pipeline-failure:' + str(digest) + ':' + str(index),
            'pipeline_stage_failure', 'static_pipeline', failure['status'], details=failure))
    original_id = "original:" + str(digest)
    original_available = bool(layout or raw or static)
    if original_available:
        records.append(_record(original_id, "document", "original", details={"sha256": digest,
            "size_bytes": layout.get("size_bytes", raw.get("size_bytes", static.get("input", {}).get("size_bytes"))),
            "immutable": True}))
    primary_id = "primary:" + str(digest)
    if static:
        records.append(_record(primary_id, "primary_checkpoint", "legacy", details={
            "features": static.get("features", {}), "parser": static.get("parser", {}),
            "errors": static.get("errors", []), "warnings": static.get("warnings", []),
            "profile_status": profile.get("primary_status", profile.get("status")),
            "source_profile": {"static": static, "code": profile.get("code"), "analysis_v8": profile.get("analysis_v8")}}))
    for item in analysis.get("observations", []):
        status = "observed" if item.get("status") in {"observed", "verified"} else failure_status(item.get("reason_codes", []))
        offset = item.get("offset")
        records.append(_record(item["id"], item["kind"], item["backend"], status, details=item,
            object_number=item.get("object_number"), generation=item.get("generation"),
            byte_offset_start=offset if type(offset) is int and offset >= 0 else None,

            is_synthetic_repaired=item["backend"] == "MuPDF"))
    edges.extend(analysis.get("edges", []))
    for check in analysis.get("capability_checks", []):
        records.append(_record(check["id"], "capability_check", check["backend"],
            "observed" if check["status"] == "complete" else failure_status(check.get("reason_codes", [])), details=check))
    ids = {item["evidence_id"] for item in records}
    if layout:
        layout_id = "layout:" + digest
        records.append(_record(layout_id, "raw_layout", "raw_forensic", details=layout))
        ids.add(layout_id)
        for name in ("size_bytes", "entropy", "header_offset", "last_eof_offset", "prefix_bytes",
                     "prefix_entropy", "suffix_bytes", "suffix_entropy", "escaped_name_candidates"):
            value = layout[name]
            complete = name != "escaped_name_candidates" or layout["name_scan_complete"]
            features.append(feature("raw_" + name, "syntax_tokens" if name == "escaped_name_candidates" else "raw_layout",
                value, "partial" if value is None or not complete else "observed", [layout_id],
                "original-byte lexical measurement; names/markers may occur inside strings or streams",
                ["lexical_name_scan_limit"] if not complete else [], complete=complete))
        for value, count in enumerate(layout["byte_histogram"]):
            features.append(feature(f"raw_byte_{value:03d}_count", "raw_layout", count,
                "observed" if count else "absent_within_scope", [layout_id],
                "all immutable original bytes", complete=True))
    raw_values = layout.get("token_counts", raw.get("features", {}))
    canonical = static.get("features", {})
    lexical = set(RAW_DIRECT_TOKENS) | {"obj", "endobj", "stream", "endstream", "xref", "startxref", "page_command"}

    for name, value in raw_values.items():
        features.append(feature("lexical_" + name, _group(name), value,
            "observed" if value else "absent_within_scope", [original_id],
            "exact PDFMalExtract raw byte-count convention; no semantic absence claim", complete=True))
    ledger = analysis.get("feature_provenance", {})
    for name, raw_value in canonical.items():
        value = None if raw_value == -1 else raw_value
        entry = ledger.get(name, {})
        raw_agrees = name in lexical and name in raw_values and value == raw_values[name]
        complete = raw_agrees or entry.get("completion_status") == "complete"
        limitations = list(entry.get("reason_codes", []))
        if name in raw_values and value != raw_values[name]:
            complete = False
            limitations.append("primary_raw_measurement_conflict")
        status = ("partial" if value is None or not complete else
                  "absent_within_scope" if value == 0 else "observed")
        features.append(feature("canonical_" + name, _group(name), value, status, [primary_id],
            "immutable primary measurement; exact legacy value retained in primary_checkpoint; no refit",
            limitations, complete=bool(complete)))
    for name, entry in ledger.items():
        if name in canonical:
            continue
        refs = [ref for ref in entry.get("source_ids", []) if ref in ids]
        value, complete = entry.get("value"), entry.get("completion_status") == "complete"

        if value is not None and not refs:
            value = None
        status = "partial" if value is None or not complete else "absent_within_scope" if value == 0 else "observed"
        features.append(feature("legacy_" + name, _group(name), value, status, refs,
            "v9 dependency ledger over the original primary/checkpoint measurements",
            entry.get("reason_codes", []), complete=complete))

    for item in analysis.get("observations", []):
        if item.get("kind") != "script" or item.get("ast_status") != "complete":
            continue
        summary = item.get("ast_summary") or {}
        for name in ("node_count", "max_depth", "loops", "computed_members"):
            if type(summary.get(name)) is int:
                features.append(feature(item["id"] + ":ast:" + name, "javascript_xfa", summary[name],
                    "observed", [item["id"]], "one extracted script; syntax only; no code execution", complete=True))
    for backend in analysis.get("backend_results", []):
        backend_name = backend["backend"]
        observed = [item["id"] for item in analysis.get("observations", []) if item["backend"] == backend_name]
        if observed:
            features.append(feature("observed_graph_nodes_" + backend_name, "object_graph", len(observed),
                "partial", observed, "v9 graph observation count/lower bound; includes direct/synthetic/failure records"))
    if analysis.get("backend_results"):
        features.append(feature("observed_parser_conflicts", "parser_coverage", len(analysis.get("conflicts", [])),
            "partial", [original_id], "compared v9 projections only; parser absence/unread objects do not establish agreement"))
    if streams:
        summary_id = "stream-analysis:" + str(digest)
        storage = profile.get("raw_stream_storage") or {"records": [], "verified_bytes": 0, "unfinished_stream": False}
        storage_index = {entry["sha256"]: entry for entry in storage["records"]}
        summary = {key: value for key, value in streams.items() if key not in {"records", "active_stream"}}
        summary['active_stream_id'] = (streams.get('active_stream') or {}).get('id')
        summary["storage"] = storage
        records.append(_record(summary_id, "stream_analysis", "bounded_filters", streams.get("status", "partial"), details=summary))
        stream_entries = list(streams.get("records", []))
        if streams.get('active_stream'):
            if any(item['id'] == streams['active_stream']['id'] for item in stream_entries):
                raise ValueError('duplicate_stream_checkpoint_identity')
            stream_entries.append(streams['active_stream'])
        for entry in stream_entries:
            source_id = entry["source_id"]
            if source_id not in ids:
                raise ValueError("stream_source_observation_missing")
            details = deepcopy(entry)
            decode = details.get("decode") or {}
            retention = [decode.get("raw_retention")]
            for step in decode.get("steps", []):
                retention.extend([step.get("retention"), step.get("predictor_input_retention")])
                retention.append((step.get('trailing_data') or {}).get('retention'))
            for item in retention:
                if isinstance(item, dict) and item.get("sha256"):
                    parent = storage_index.get(item["sha256"])
                    item["parent_verification_status"] = parent["status"] if parent else "unverified"
            source = next(item for item in records if item["evidence_id"] == source_id)
            if (entry["backend"] != source["backend"]
                    or entry["object_number"] != source["object_number"]
                    or entry["generation"] != source["generation"]
                    or decode and (decode.get("raw_sha256") != source["details"].get("raw_sha256")
                                   or decode.get("filters") != entry["filters"])):
                raise ValueError("stream_source_identity_mismatch")
            records.append(_record(entry["id"], "stream_decode", "bounded_filters", entry["status"], details=details,
                object_number=entry["object_number"], generation=entry["generation"], filter_chain=entry["filters"],
                byte_offset_start=entry["offset"] if type(entry["offset"]) is int else None,
                is_synthetic_repaired=source["is_synthetic_repaired"]))
            edges.append({"id": entry["id"] + ":source", "source": source_id, "target": entry["id"],
                          "kind": "stream_decode_source", "status": "verified"})
            complete = decode.get("complete") is True
            output_complete = complete or decode.get('output_complete') is True
            features.append(feature(entry["id"] + ":decoded_bytes", "streams_filters",
                decode.get("decoded_bytes") if output_complete else None, "observed" if complete else entry["status"],
                [entry["id"]], "one v9-discovered stream; all declared supported filters completed only when observed",
                entry["reason_codes"], complete=complete))
            previous = entry["id"]
            for step in decode.get("steps", []):
                step_id = entry["id"] + ":filter:" + str(step["index"])
                records.append(_record(step_id, "stream_filter_stage", "bounded_filters", step["status"], details=step,
                    filter_chain=[step["filter"]], is_synthetic_repaired=source["is_synthetic_repaired"]))
                edges.append({"id": step_id + ":previous", "source": previous, "target": step_id,
                              "kind": "stream_filter_order", "status": "verified"})
                if step.get("output_bytes") is not None:
                    features.append(feature(step_id + ":output_bytes", "streams_filters", step["output_bytes"],
                        "observed" if step["complete"] else "partial", [step_id],
                        "completed filter output or explicitly partial prefix; never fed to the next filter after failure",
                        step["reason_codes"], complete=step["complete"]))
                previous = step_id
        counts = Counter(entry["status"] for entry in stream_entries)
        for status in ("observed", "partial", "decode_error", "unsupported", "encrypted", "resource_limit"):
            features.append(feature("observed_stream_status_" + status, "streams_filters", counts[status],
                "partial", [summary_id], "count/lower bound within the catalog-discovered stream supplement; no whole-file absence claim"))
    from malpdf.extraction.artifact_exports import append_artifacts
    append_artifacts(profile, digest, records, features, edges)
    from malpdf.extraction.parser_exports import append_parser_views
    parser_conflicts = append_parser_views(profile,digest,records,features,edges)
    inventory = profile.get('parser_analysis') or {}
    from malpdf.extraction.forensic_exports import append_forensic
    forensic_conflicts = append_forensic(profile,digest,records,features,edges)
    forensic = profile.get('raw_forensic') or {}
    from malpdf.extraction.arlington_exports import append_arlington
    append_arlington(profile,digest,records,features,edges)
    arlington=profile.get('arlington_analysis') or {}
    from malpdf.extraction.script_semantics import append_script_semantics
    append_script_semantics(profile,digest,records,features,edges)
    script_semantics=profile.get('script_semantics') or {}
    from malpdf.extraction.byte_image_exports import append_byte_images
    append_byte_images(profile,digest,records,features,edges)
    byte_images=profile.get('byte_images') or {}
    from malpdf.extraction.plugin_features import append_plugin_features,plugin_backends
    append_plugin_features(profile,digest,records,features,edges)
    plugin_features=profile.get('plugin_features') or {}
    code = profile.get("code") or {}
    carving = profile.get('carving') or {}
    flag_decompression_ratio_exceeded = bool(
        streams.get("flag_decompression_ratio_exceeded")
        or profile.get("flag_decompression_ratio_exceeded")
        or "decoded_byte_or_expansion_limit" in reasons
        or "decoded_byte_limit" in reasons
    )
    is_truncated_stream = bool(
        streams.get("is_truncated_stream")
        or profile.get("is_truncated_stream")
        or flag_decompression_ratio_exceeded
    )
    flag_spec_violation_flood = bool(
        arlington.get("flag_spec_violation_flood")
        or profile.get("flag_spec_violation_flood")
        or "arlington_metadata_limit" in reasons
        or "arlington_flood" in reasons
    )
    flag_ast_complexity_truncated = bool(
        code.get("flag_ast_complexity_truncated")
        or analysis.get("flag_ast_complexity_truncated")
        or carving.get("flag_ast_complexity_truncated")
        or script_semantics.get("flag_ast_complexity_truncated")
        or profile.get("flag_ast_complexity_truncated")
        or any(r in reasons for r in ("ast_node_limit", "ast_depth_limit", "artifact_ast_limit", "artifact_ast_or_script_limit"))
    )
    flag_excessive_object_graph = bool(
        code.get("flag_excessive_object_graph")
        or analysis.get("flag_excessive_object_graph")
        or profile.get("flag_excessive_object_graph")
        or any(r in reasons for r in ("pdf_structure_limit", "graph_object_limit", "graph_depth_limit"))
    )
    evasion_flags = {
        "flag_decompression_ratio_exceeded": flag_decompression_ratio_exceeded,
        "flag_spec_violation_flood": flag_spec_violation_flood,
        "flag_ast_complexity_truncated": flag_ast_complexity_truncated,
        "is_truncated_stream": is_truncated_stream,
        "flag_excessive_object_graph": flag_excessive_object_graph,
        "evasive_timeout_anomaly": bool(
            "timeout" in reasons
            or "wall_timeout" in reasons
            or profile.get("status") in ("timeout", "timeout_partial")
            or "wall_timeout" in profile.get("errors", [])
        ),
    }
    flag_refs = [primary_id] if bool(static) else [original_id] if original_available else []
    for flag_name, flag_value in evasion_flags.items():
        if flag_refs:
            features.append(feature(
                flag_name, "parser_coverage", 1 if flag_value else 0, "observed", flag_refs,
                "defense and evasion indicator", complete=True
            ))
        else:
            features.append(feature(
                flag_name, "parser_coverage", None, "not_run", [],
                "defense and evasion indicator", limitations=["original_evidence_unavailable"], complete=False
            ))
    arlington_violations = int(arlington.get("total_violations", 0))
    checks_count = int(arlington.get("checks_count") or arlington.get("objects_checked") or (len(arlington.get("checks", [])) + len(arlington.get("binding_reuses", []))))
    violation_rate = (arlington_violations / max(1, checks_count)) if checks_count else (1.0 if arlington_violations else 0.0)
    discovered_streams = int(streams.get("discovered_streams") or streams.get("total_streams", 0))
    truncated_streams = int(streams.get("truncated_stream_count") or streams.get("truncated_streams", 1 if is_truncated_stream else 0))
    stream_ratio = (truncated_streams / max(1, discovered_streams)) if discovered_streams else (1.0 if is_truncated_stream else 0.0)
    budget_usage = analysis.get("budget_usage") or code.get("budget_usage") or {}
    visited_objs = int(budget_usage.get("objects_visited", 0))
    graph_ratio = min(1.0, visited_objs / 10000.0)
    continuous_ratios = {
        "arlington_violation_rate": round(float(violation_rate), 4),
        "stream_truncation_ratio": round(float(stream_ratio), 4),
        "object_graph_visited_ratio": round(float(graph_ratio), 4),
    }
    for ratio_name, ratio_value in continuous_ratios.items():
        if flag_refs:
            features.append(feature(
                ratio_name, "parser_coverage", ratio_value, "observed", flag_refs,
                "continuous anomaly and quota intensity ratio", complete=True
            ))
        else:
            features.append(feature(
                ratio_name, "parser_coverage", None, "not_run", [],
                "continuous anomaly and quota intensity ratio", limitations=["original_evidence_unavailable"], complete=False
            ))
    groups = {}
    for group in GROUPS:
        members = [item for item in features if item["feature_group"] == group]
        status = "partial" if members else "not_run"
        if group == "raw_layout" and layout:
            status = "observed"
        groups[group] = {"observation_status": status, "feature_count": len(members),
                         "scope": "see individual feature scopes; not whole-format completeness",
                         "limitations": [] if group == "raw_layout" and layout else ["comprehensive_group_coverage_unverified"]}
    backend_results = analysis.get("backend_results", [])
    backends = {name: {"observation_status": "not_run", "limitations": ["profile_does_not_run_this_backend"]}
                for name in ("raw_forensic", "pypdf", "MuPDF", "qpdf")}
    if layout:
        backends["raw_forensic"] = {"observation_status": "observed", "limitations": ["lexical_hints_only"]}
    for backend in backend_results:
        backends[backend["backend"]] = {"observation_status": "observed" if backend["status"] == "observed" else
            failure_status(backend.get("reason_codes", [])), "limitations": backend.get("reason_codes", [])}
    if extraction_profile == "deep-static":
        backends['qpdf'] = {'observation_status':'not_run','limitations':['native_inventory_not_run']}
    for view in inventory.get('views',[]):
        name = 'qpdf' if view['backend'] == 'QPDF' else view['backend']
        previous = backends.get(name,{})
        backends[name] = {'observation_status':view['status'],'limitations':view['reason_codes'],
                          'version':view['version'],'scope':'current native object inventory; graph/revisions remain separate',
                          'graph_observation_status':previous.get('observation_status','not_run'),
                          'graph_limitations':previous.get('limitations',[])}
    for name, group in (("render_ocr_qr", "page_visual"),
                        ("dynamic", "dynamic_telemetry")):
        groups[group]["limitations"].append(name + "_not_run")
    backends['arlington']={'observation_status':arlington.get('status','not_run'),
        'limitations':arlington.get('reason_codes',['arlington_not_configured']),
        'model':arlington.get('model',{'status':'unavailable'}),
        'scope':arlington.get('scope','configured local TSV rules only')}
    groups['parser_coverage']['limitations'].extend(arlington.get('reason_codes',['arlington_not_run']))
    backends['script_semantics']={'observation_status':script_semantics.get('status','not_run'),
        'limitations':script_semantics.get('reason_codes',['static_script_semantics_not_run']),
        'scope':script_semantics.get('scope','captured script ASTs only; no runtime behavior proof')}
    groups['javascript_xfa']['limitations'].extend(backends['script_semantics']['limitations'])
    backends['byte_images']={'observation_status':byte_images.get('status','not_run'),
        'limitations':byte_images.get('reason_codes',['byte_images_not_run']),
        'scope':byte_images.get('scope','raw bytes only; no page rendering')}
    backends.update(plugin_backends(profile))
    for failure in profile.get('stage_failures', []):
        backends['pipeline:' + failure['stage']] = {'observation_status': failure['status'],
            'limitations': [failure['reason_code']], 'scope': 'failed VM supplement; sibling/primary evidence retained'}
    if byte_images:
        groups['raw_layout']['observation_status']='partial'
        groups['raw_layout']['limitations'].extend(['byte_rasters_have_separate_scopes_and_optional_persistence']+byte_images.get('reason_codes',[]))
    if forensic:
        backends['raw_forensic']={'observation_status':forensic['status'],'limitations':forensic['reason_codes'],
            'scope':forensic['scope'],'lexical_observation_status':backends['raw_forensic']['observation_status']}
    groups['embedded_artifacts']['limitations'].append('recognized_candidates_only' if carving else 'recursive_carving_not_run')
    state = "observed" if profile.get("status") == "complete" else failure_status(reasons)
    if streams and streams.get("complete") is not True:
        reasons = sorted(set(reasons + streams.get("reason_codes", []) + streams.get("worker_failure_codes", [])))
        state = failure_status(reasons)
    if carving and carving.get('complete') is not True:
        reasons = sorted(set(reasons + carving.get('reason_codes', []) + carving.get('worker_failure_codes', [])))
        state = failure_status(reasons)
    if inventory and inventory.get('complete') is not True:
        reasons = sorted(set(reasons + inventory.get('reason_codes',[]) + inventory.get('worker_failure_codes',[])))
        state = failure_status(reasons)
    if forensic and forensic.get('complete') is not True:
        reasons = sorted(set(reasons+forensic.get('reason_codes',[])+forensic.get('worker_failure_codes',[])))
        state = failure_status(reasons)
    if arlington and arlington.get('complete') is not True:
        reasons=sorted(set(reasons+arlington.get('reason_codes',[])+arlington.get('worker_failure_codes',[])))
        state=failure_status(reasons)
    if script_semantics and script_semantics.get('complete') is not True:
        reasons=sorted(set(reasons+script_semantics.get('reason_codes',[])+script_semantics.get('worker_failure_codes',[])))
        state=failure_status(reasons)
    if byte_images and byte_images.get('complete') is not True:
        reasons=sorted(set(reasons+byte_images.get('reason_codes',[])+byte_images.get('worker_failure_codes',[])))
        state=failure_status(reasons)
    if plugin_features and plugin_features.get('complete') is not True:
        reasons=sorted(set(reasons+plugin_features.get('reason_codes',[])+plugin_features.get('worker_failure_codes',[])))
        state=failure_status(reasons)
    has_primary = bool(static)
    is_timeout = "timeout" in reasons or state == "timeout"
    is_failed = not has_primary or "sigkill" in " ".join(reasons).lower() or (profile.get("worker_exit_code") not in (0, None) and not has_primary)
    has_bounded_defense = any(evasion_flags.values()) or state == "resource_limit" or any("limit" in r or "budget" in r for r in reasons)
    if is_failed:
        extraction_status = "failed"
    elif is_timeout:
        extraction_status = "timeout_partial" if has_primary else "failed"
    elif has_bounded_defense and has_primary:
        extraction_status = "bounded_complete"
        state = "bounded_complete"
    elif state == "observed" or profile.get("status") == "complete":
        extraction_status = "complete"
    else:
        extraction_status = "complete" if has_primary and not reasons else "bounded_complete" if has_primary else "failed"
    output = {"schema_version": VERSION, "sample_sha256": digest,
        "extraction_profile": extraction_profile, "status": state,
        "extraction_status": extraction_status,
        "evasion_or_quota_flags": evasion_flags,
        "safety": {"active_content_executed": False, "rendering_performed": False,
                   "external_uri_followed": False, "original_bytes_changed": False},
        "evidence_store": {"schema_version": "pdf-evidence-store-v1", "sample_sha256": digest,
                           "records": records, "edges": edges,
                           "capability_checks": analysis.get("capability_checks", []),
                           "conflicts": analysis.get("conflicts", []) + parser_conflicts + forensic_conflicts},
        "feature_store": {"schema_version": "pdf-feature-store-v1", "sample_sha256": digest, "records": features},
        "coverage_report": {"schema_version": "pdf-coverage-report-v1", "sample_sha256": digest,
            "groups": groups, "backends": backends, "limitations": reasons,
            "observation_status_counts": dict(Counter(item["observation_status"] for item in features)),
            "whole_document_complete": False,
            "extraction_status": extraction_status,
            "evasion_or_quota_flags": evasion_flags,
            "worker": {name: profile.get(name) for name in ("status", "worker_seconds", "worker_exit_code", "worker_cleanup_complete",
                "peak_rss_bytes", "rss_quality", "resource_limits", "last_stage", "timings")},
            "provenance": provenance or {}}}
    if "worker_result_received" in profile:
        output["coverage_report"]["worker"]["worker_result_received"] = profile["worker_result_received"]
    if 'diagnostic' in profile:
        output['coverage_report']['worker']['diagnostic'] = profile['diagnostic']
    return validate_bundle(output)
