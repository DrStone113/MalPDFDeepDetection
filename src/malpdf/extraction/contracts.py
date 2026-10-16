"""Small explicit export contracts; missing observations never imply absence."""

from enum import StrEnum
from collections import Counter
import json
import math
import re


class ObservationStatus(StrEnum):
    OBSERVED = "observed"
    ABSENT = "absent_within_scope"
    PARTIAL = "partial"
    DECODE_ERROR = "decode_error"
    UNSUPPORTED = "unsupported"
    ENCRYPTED = "encrypted"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    NOT_RUN = "not_run"


GROUPS = (
    "raw_layout", "syntax_tokens", "objects", "xref_history", "object_graph",
    "streams_filters", "actions", "javascript_xfa", "embedded_artifacts",
    "fonts_images_multimedia", "page_visual", "metadata_encryption_signatures",
    "dynamic_telemetry", "parser_coverage",
)
VERSION = "pdf-extraction-v1"
HASH = re.compile(r"[a-f0-9]{64}\Z")
UNAVAILABLE = frozenset({"decode_error", "unsupported", "encrypted", "timeout",
                         "resource_limit", "not_run"})


def feature(name, group, value, status, refs, scope, limitations=(), *, complete=False):
    """Construct a record without rounding, imputation or model-side changes."""
    return {"feature_name": name, "feature_group": group, "value": value,
            "observation_status": str(status), "evidence_refs": list(refs), "scope": scope,
            "scope_complete": complete, "coverage_ratio": None,
            "limitations": sorted(set(limitations))}


def validate_bundle(bundle):
    """Validate our versioned contracts and cross-store semantic invariants.

    This is an explicit validator for this export, not a general JSON Schema
    engine. The distributable schemas describe the same three public stores.
    Legacy details stay opaque so their immutable source representation survives.
    """
    def mapping(value, required, code, *, closed=False, optional=()):
        if (not isinstance(value, dict) or not set(required) <= value.keys()
                or closed and set(value)-set(required)-set(optional)):
            raise ValueError(code)

    def strings(value,code):
        if not isinstance(value,list) or any(not isinstance(item,str) for item in value):
            raise ValueError(code)

    statuses = {str(value) for value in ObservationStatus}
    mapping(bundle, ("schema_version", "extraction_profile", "status", "sample_sha256", "safety",
                     "evidence_store", "feature_store", "coverage_report"), "extraction_bundle_shape")
    if bundle.get("schema_version") != VERSION:
        raise ValueError("extraction_schema_version")
    digest = bundle.get("sample_sha256")
    if digest is not None and (not isinstance(digest, str) or not HASH.fullmatch(digest)):
        raise ValueError("extraction_document_identity")
    if bundle.get("extraction_profile") not in {"fast-static", "deep-static"}:
        raise ValueError("extraction_profile")
    if not isinstance(bundle.get("status"), str) or bundle["status"] not in statuses:
        raise ValueError("extraction_status")
    safety = bundle.get("safety", {})
    mapping(safety, (), "extraction_safety_shape")
    if any(safety.get(key) is not False for key in (
            "active_content_executed", "rendering_performed", "external_uri_followed",
            "original_bytes_changed")):
        raise ValueError("extraction_safety_unverified")
    for key, version, fields in (("evidence_store", "pdf-evidence-store-v1",('records','edges','capability_checks','conflicts')),
                         ("feature_store", "pdf-feature-store-v1",('records',)),
                         ("coverage_report", "pdf-coverage-report-v1",('groups','backends','limitations',
                             'observation_status_counts','whole_document_complete','worker','provenance'))):
        store = bundle.get(key, {})
        mapping(store, ("schema_version", "sample_sha256",*fields), "extraction_store_shape",closed=True)
        if store.get("schema_version") != version or store.get("sample_sha256") != digest:
            raise ValueError("extraction_store_identity")
    evidence = bundle["evidence_store"]
    mapping(evidence, ("records", "edges", "capability_checks", "conflicts"), "extraction_evidence_shape")
    if any(not isinstance(evidence[key], list) for key in ("records", "edges", "capability_checks", "conflicts")):
        raise ValueError("extraction_evidence_shape")
    if any(not isinstance(item,dict) for key in ('capability_checks','conflicts') for item in evidence[key]):
        raise ValueError('extraction_evidence_shape')
    nodes, edge_ids = {}, set()
    for item in evidence["records"]:
        mapping(item, ("evidence_id", "kind", "backend", "observation_status", "object_number", "generation",
                       "revision", "byte_offset_start", "byte_offset_end", "filter_chain", "is_synthetic_repaired", "details"),
                "extraction_observation_shape",closed=True)
        identifier = item.get("evidence_id")
        if not isinstance(identifier, str) or not identifier or identifier in nodes:
            raise ValueError("extraction_evidence_identity")
        if not isinstance(item.get("observation_status"), str) or item["observation_status"] not in statuses:
            raise ValueError("extraction_observation_status")
        for field in ("object_number", "generation", "byte_offset_start", "byte_offset_end", "revision"):
            value = item.get(field)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("extraction_locator")
        start, end = item.get("byte_offset_start"), item.get("byte_offset_end")
        if start is not None and end is not None and end < start:
            raise ValueError("extraction_locator")
        if not isinstance(item.get("is_synthetic_repaired"), bool):
            raise ValueError("extraction_repair_provenance")
        chain = item["filter_chain"]
        if chain is not None and (not isinstance(chain, list) or any(not isinstance(name, str) for name in chain)):
            raise ValueError("extraction_filter_provenance")
        if not isinstance(item["details"], dict) or not all(isinstance(item[key], str) for key in ("kind", "backend")):
            raise ValueError("extraction_observation_shape")
        nodes[identifier] = item
    for edge in evidence["edges"]:
        mapping(edge, ("id", "source", "target"), "extraction_edge_shape")
        if any(not isinstance(edge[key], str) for key in ("id", "source", "target")):
            raise ValueError("extraction_edge_shape")
        if edge.get("source") not in nodes or edge.get("target") not in nodes:
            raise ValueError("extraction_dangling_edge")
        if not edge["id"] or edge["id"] in edge_ids or edge["id"] in nodes:
            raise ValueError("extraction_edge_identity")
        edge_ids.add(edge["id"])
    names = set()
    mapping(bundle["feature_store"], ("records",), "extraction_feature_store_shape")
    if not isinstance(bundle["feature_store"]["records"], list):
        raise ValueError("extraction_feature_store_shape")
    for record in bundle["feature_store"]["records"]:
        mapping(record, ("feature_name", "feature_group", "value", "observation_status", "evidence_refs",
                         "scope", "scope_complete", "coverage_ratio", "limitations"), "extraction_feature_shape",closed=True)
        name, group = record["feature_name"], record["feature_group"]
        if not isinstance(name, str) or not name or name in names or not isinstance(group, str) or group not in GROUPS:
            raise ValueError("extraction_feature_identity")
        names.add(name)
        status, value = record["observation_status"], record["value"]
        if not isinstance(status, str) or status not in statuses:
            raise ValueError("extraction_observation_status")
        if type(value) not in (int, float, bool, type(None)) or (type(value) is float and not math.isfinite(value)):
            raise ValueError("extraction_feature_value")
        if status in UNAVAILABLE and value is not None:
            raise ValueError("unavailable_feature_has_value")
        if status in {"observed", "absent_within_scope"} and value is None:
            raise ValueError("verified_feature_missing_value")
        refs = record["evidence_refs"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in nodes for ref in refs):
            raise ValueError("extraction_feature_reference")
        if value is not None and not refs:
            raise ValueError("extraction_unattributed_value")
        if status == "absent_within_scope" and (value != 0 or record["scope_complete"] is not True):
            raise ValueError("absence_requires_complete_scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise ValueError("extraction_feature_scope")
        if type(record["scope_complete"]) is not bool:
            raise ValueError("extraction_scope_completion")
        strings(record['limitations'],'extraction_feature_limitations')
        ratio = record["coverage_ratio"]
        if ratio is not None and (type(ratio) not in (int, float) or not 0 <= ratio <= 1
                                  or type(ratio) is float and not math.isfinite(ratio)):
            raise ValueError("extraction_coverage_ratio")
    coverage = bundle["coverage_report"]
    mapping(coverage, ("groups", "backends", "limitations", "observation_status_counts", "whole_document_complete", "worker", "provenance"),
            "extraction_coverage_shape")
    mapping(coverage["groups"], (), "extraction_coverage_shape")
    if set(coverage["groups"]) != set(GROUPS):
        raise ValueError("extraction_coverage_groups")
    for group, entry in coverage["groups"].items():
        mapping(entry, ("observation_status", "feature_count", "scope", "limitations"), "extraction_coverage_shape",closed=True)
        if not isinstance(entry["observation_status"], str) or entry["observation_status"] not in statuses:
            raise ValueError("extraction_coverage_status")
        expected = sum(item["feature_group"] == group for item in bundle["feature_store"]["records"])
        if type(entry["feature_count"]) is not int or entry["feature_count"] != expected:
            raise ValueError("extraction_coverage_count")
        if not isinstance(entry['scope'],str) or not entry['scope']:
            raise ValueError('extraction_coverage_scope')
        strings(entry['limitations'],'extraction_coverage_limitations')
    mapping(coverage['backends'],(),'extraction_backend_shape')
    optional=('version','scope','graph_observation_status','graph_limitations','lexical_observation_status','model')
    for name,entry in coverage['backends'].items():
        if not isinstance(name,str) or not name: raise ValueError('extraction_backend_identity')
        mapping(entry,('observation_status','limitations'),'extraction_backend_shape',closed=True,optional=optional)
        if not isinstance(entry['observation_status'],str) or entry['observation_status'] not in statuses:
            raise ValueError('extraction_backend_status')
        strings(entry['limitations'],'extraction_backend_limitations')
        if 'scope' in entry and (not isinstance(entry['scope'],str) or not entry['scope']):
            raise ValueError('extraction_backend_scope')
        if 'version' in entry and not isinstance(entry['version'],(dict,str,type(None))):
            raise ValueError('extraction_backend_version')
        if 'model' in entry and not isinstance(entry['model'],dict): raise ValueError('extraction_backend_model')
        for key in ('graph_observation_status','lexical_observation_status'):
            if key in entry and (not isinstance(entry[key],str) or entry[key] not in statuses):
                raise ValueError('extraction_backend_status')
        if 'graph_limitations' in entry: strings(entry['graph_limitations'],'extraction_backend_limitations')
    strings(coverage['limitations'],'extraction_coverage_limitations')
    for key in ('worker','provenance'): mapping(coverage[key],(),'extraction_coverage_shape')
    if coverage['whole_document_complete'] is not False: raise ValueError('extraction_whole_document_completion')
    counts=coverage['observation_status_counts']
    mapping(counts,(),'extraction_status_counts')
    expected=Counter(record['observation_status'] for record in bundle['feature_store']['records'])
    if (any(not isinstance(key,str) or key not in statuses or type(value) is not int or value<0 for key,value in counts.items())
            or any(counts.get(key,0)!=expected.get(key,0) for key in statuses)):
        raise ValueError('extraction_status_counts')
    # Python's encoder otherwise silently coerces numeric dict keys to strings.
    pending=[bundle];seen=set()
    while pending:
        item=pending.pop()
        if isinstance(item,(dict,list,tuple)) and id(item) not in seen:
            seen.add(id(item))
            if isinstance(item,dict):
                if any(not isinstance(key,str) for key in item): raise ValueError('extraction_json_value')
                pending.extend(item.values())
            else: pending.extend(item)
    try: json.dumps(bundle, allow_nan=False)
    except (TypeError,ValueError,RecursionError) as error:
        raise ValueError('extraction_json_value') from error
    return bundle
