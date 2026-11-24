from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any

DEFAULT_SIGNATURE_RULES_PATH = Path(__file__).resolve().parents[3] / "configs" / "pdf_signature_rules.json"
_RULE_FIELDS = ("id", "name", "severity", "target", "description_vi")
_MAX_SCAN_TEXT = 64 * 1024


@lru_cache(maxsize=8)
def _load_rules(path: Path) -> tuple[tuple[dict[str, str], re.Pattern | None], ...]:
    with path.open("rb") as stream:
        config = stream.read(128 * 1024 + 1)
    if len(config) > 128 * 1024:
        raise ValueError("pdf_signature_config_too_large")
    rules = json.loads(config)
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError("invalid_pdf_signature_rules")
    compiled = []
    ids = set()
    for item in rules:
        if not isinstance(item, dict) or any(
            not isinstance(item.get(key), str) or not item[key] for key in _RULE_FIELDS
        ):
            raise ValueError("invalid_pdf_signature_rule")
        target, severity = item["target"], item["severity"]
        if target not in {"script", "uri", "anomaly", "raw"} or severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid_pdf_signature_rule")
        matcher = item.get("anomaly_tag" if target == "anomaly" else "pattern")
        if item["id"] in ids or not isinstance(matcher, str) or not 0 < len(matcher) <= 512:
            raise ValueError("invalid_pdf_signature_rule")
        ids.add(item["id"])
        rule = {key: item[key] for key in _RULE_FIELDS}
        rule["anomaly_tag" if target == "anomaly" else "pattern"] = matcher
        pattern = (
            None
            if target == "anomaly"
            else re.compile(matcher.encode("utf-8") if target == "raw" else matcher, re.IGNORECASE)
        )
        compiled.append((rule, pattern))
    return tuple(compiled)


def _anomaly_tags(ingest_data: dict[str, Any]) -> set[str]:
    js = ingest_data.get("js_semantics", {})
    indicators = set(js.get("dangerous_indicators", ()))
    tags = indicators | set(ingest_data.get("anomaly_tags", ())) | set(ingest_data.get("non_js_triggers", ()))
    tags.update(ingest_data.get("xfa_analysis", {}).get("anomalies", ()))
    for anomaly in ingest_data.get("codec_anomalies", ()):
        tags.update(anomaly.get("reason_codes", ()))
    polyglot = ingest_data.get("polyglot_analysis", {})
    tags.update(polyglot.get("anomalies", ()))
    if polyglot.get("has_polyglot_payload"):
        tags.add("polyglot_active_payload")
    if len(set(js.get("deobfuscation_techniques", ()))) >= 2 and indicators.intersection(
        {
            "eval_exec",
            "function_constructor_exec",
            "prototype_constructor_exec",
            "app_doc_payload",
            "js_flow_suspicious_uri",
        }
    ):
        tags.add("js_multilayer_dropper")
    return tags


def _bounded_values(values) -> tuple[str, ...]:
    texts = []
    remaining = _MAX_SCAN_TEXT
    for value in values:
        if not remaining or len(texts) >= 256:
            break
        if value:
            text = value[:remaining]
            texts.append(text)
            remaining -= len(text)
    return tuple(texts)


def match_pdf_signatures(
    raw_bytes: bytes, ingest_data: dict[str, Any], rules_path: Path | None = None
) -> list[dict[str, Any]]:
    """Match trusted local rules against bounded static evidence."""
    rules = _load_rules(DEFAULT_SIGNATURE_RULES_PATH if rules_path is None else Path(rules_path))
    tags = _anomaly_tags(ingest_data)
    sources = {}
    matches = []
    for rule, pattern in rules:
        target = rule["target"]
        if pattern is None:
            matched = rule["anomaly_tag"] in tags
        else:
            if target not in sources:
                if target == "raw":
                    half = _MAX_SCAN_TEXT // 2
                    sources[target] = (
                        (raw_bytes,) if len(raw_bytes) <= _MAX_SCAN_TEXT else (raw_bytes[:half], raw_bytes[-half:])
                    )
                elif target == "script":
                    sources[target] = _bounded_values(
                        script.get("code") for script in ingest_data.get("extracted_scripts", ())
                    )
                else:
                    sources[target] = _bounded_values(uri.get("uri") for uri in ingest_data.get("extracted_uris", ()))
            matched = any(pattern.search(value) for value in sources[target])
        if matched:
            matches.append(rule.copy())
    return matches
