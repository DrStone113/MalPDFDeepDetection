"""JSON Schema 2020-12 documents for the three public extraction stores."""

import json

from malpdf.extraction.contracts import GROUPS, ObservationStatus, ExtractionStatus

_STATUS = {"enum": [str(value) for value in ObservationStatus]}
_HASH = {"type": ["string", "null"], "pattern": "^[a-f0-9]{64}$", "minLength": 64, "maxLength": 64}
_STRINGS = {"type": "array", "items": {"type": "string"}}
_INTEGER = {"type": ["integer", "null"], "minimum": 0}


def _object(properties,*,required=None,additional=False):
    return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else list(required), "additionalProperties": additional}


def _store(version, properties, *, required=None):
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            **_object({"schema_version": {"const": version}, "sample_sha256": _HASH, **properties}, required=required)}


def schemas():
    """Return independent JSON-safe schemas, also exportable without PDF access."""
    observation = _object({
        "evidence_id": {"type": "string", "minLength": 1}, "kind": {"type": "string"},
        "backend": {"type": "string"}, "observation_status": _STATUS,
        **{key: _INTEGER for key in ("object_number", "generation", "revision", "byte_offset_start", "byte_offset_end")},
        "filter_chain": {"type": ["array", "null"], "items": {"type": "string"}}, "is_synthetic_repaired": {"type": "boolean"},
        "details": {"type": "object"},
    })
    record = _object({
        "feature_name": {"type": "string", "minLength": 1}, "feature_group": {"enum": list(GROUPS)},
        "value": {"type": ["number", "boolean", "null"]}, "observation_status": _STATUS,
        "evidence_refs": _STRINGS, "scope": {"type": "string", "minLength": 1},
        "scope_complete": {"type": "boolean"},
        "coverage_ratio": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
        "limitations": _STRINGS,
    })
    record["allOf"] = [
        {"if": {"properties": {"observation_status": {"enum": ["decode_error", "unsupported", "encrypted", "timeout", "resource_limit", "not_run"]}}},
         "then": {"properties": {"value": {"type": "null"}}}},
        {"if": {"properties": {"observation_status": {"const": "absent_within_scope"}}},
         "then": {"properties": {"value": {"enum": [0, False]}, "scope_complete": {"const": True}}}},
        {"if": {"properties": {"observation_status": {"enum": ["observed", "absent_within_scope"]}}},
         "then": {"properties": {"value": {"type": ["number", "boolean"]}, "evidence_refs": {"minItems": 1}}}},
        {"if": {"required":["value"],"properties":{"value":{"not":{"type":"null"}}}},
         "then":{"properties":{"evidence_refs":{"minItems":1}}}},
    ]
    group = _object({"observation_status": _STATUS, "feature_count": {"type": "integer", "minimum": 0},
                     "scope": {"type": "string","minLength":1}, "limitations": _STRINGS})
    backend=_object({'observation_status':_STATUS,'limitations':_STRINGS,
        'scope':{'type':'string','minLength':1},'version':{'type':['object','string','null']},
        'model':{'type':'object'},'graph_observation_status':_STATUS,'graph_limitations':_STRINGS,
        'lexical_observation_status':_STATUS},required=('observation_status','limitations'))
    edge=_object({key:{'type':'string','minLength':1} for key in ('id','source','target')},additional=True)
    # JSON materialization breaks template aliases within and across documents.
    return json.loads(json.dumps({
        "evidence_store.schema.json": _store("pdf-evidence-store-v1", {
            "records": {"type": "array", "items": observation},
            "edges": {"type": "array", "items": edge},
            "capability_checks": {"type": "array", "items": {"type": "object"}},
            "conflicts": {"type": "array", "items": {"type": "object"}},
        }),
        "feature_record.schema.json": _store("pdf-feature-store-v1", {
            "records": {"type": "array", "items": record}}),
        "coverage_report.schema.json": _store("pdf-coverage-report-v1", {
            "groups": _object({name: group for name in GROUPS}),
            "backends": {"type": "object",'propertyNames':{'type':'string','minLength':1}, "additionalProperties": backend},
            "limitations": _STRINGS, "observation_status_counts": {"type": "object",'propertyNames':_STATUS, "additionalProperties": {"type": "integer", "minimum": 0}},
            "whole_document_complete": {"const": False}, "worker": {"type": "object"}, "provenance": {"type": "object"},
            "extraction_status": {"type": "string", "enum": [str(val) for val in ExtractionStatus]},
            "evasion_or_quota_flags": {"type": "object", "additionalProperties": {"type": ["boolean", "integer"]}},
        }, required=("schema_version", "sample_sha256", "groups", "backends", "limitations", "observation_status_counts", "whole_document_complete", "worker", "provenance")),
    }))
