"""Torch-free policy-neural log-odds fusion, quota separation, and benign structural consistency."""

from __future__ import annotations

import math
import re
from typing import Any

import numpy as np

CODEC_QUOTA_REASON_CODES: frozenset[str] = frozenset(
    {
        "decoded_byte_or_expansion_limit",
        "stream_filter_count_limit",
    }
)

HIGH_SEVERITY_POLICY_WEIGHTS: dict[str, float] = {
    "/Launch": 2.45,
    "gotor_unc_ntlm_risk": 2.40,
    "polyglot_payload": 2.35,
    "xfa_xml_dtd_unsupported": 2.35,
    "xfa_formcalc_network_call": 2.30,
    "javascript_malicious_indicators": 2.40,
    "javascript_flow_suspicious_uri": 2.35,
    "offline_threat_intel": 2.80,
    "hex_escaped_trigger_evasion": 2.25,
    "phishing_uri": 2.25,
    "uri_ml_or_gate": 2.25,
    "uri_ml_gated_fusion": 1.65,
    "parser_differential": 2.15,
    "codec_anomaly": 2.20,
    "/FileAttachment": 1.85,
    "/GoToR": 1.80,
    "/3D": 1.85,
    "/U3D": 1.85,
    "/PRC": 1.85,
}

_SUBSET_FONT_PREFIX = re.compile(r"^[A-Z]{6}\+[A-Za-z0-9_.-]+")


def is_quota_only_codec_reasons(reasons: list[str] | tuple[str, ...] | set[str]) -> bool:
    reason_set = {str(code) for code in reasons if code}
    return bool(reason_set) and reason_set.issubset(CODEC_QUOTA_REASON_CODES)


def calibrated_probability(logit: float, temperature: float) -> float:
    return math.exp(-float(np.logaddexp(0.0, -logit / temperature)))


def compute_benign_structural_consistency(ingest_data: dict[str, Any]) -> dict[str, Any]:
    records = ingest_data.get("raw_records") or []
    pages_count = int(ingest_data.get("pages_count") or 0)
    polyglot = ingest_data.get("polyglot_analysis") or {}
    diff = ingest_data.get("differential_analysis") or {}
    js = ingest_data.get("js_semantics") or {}
    codec_anomalies = ingest_data.get("codec_anomalies") or []
    codec_limits = ingest_data.get("codec_inspection_limits") or []

    has_catalog = any(r.get("kind") == "catalog" for r in records)
    has_pages_tree = any(r.get("kind") == "pages" for r in records) and pages_count >= 1
    no_active_scripts = not js.get("has_scripts") and not ingest_data.get("extracted_scripts")
    no_polyglot_or_diff = not polyglot.get("has_polyglot_payload") and not diff.get("has_differential_evasion")
    no_malformed_codecs = not codec_anomalies

    subset_hits = 0
    for rec in records:
        preview = str(rec.get("content_preview") or "")
        if "/BaseFont /" in preview:
            parts = preview.split("/BaseFont /", 1)[1][:48].split()
            if parts and _SUBSET_FONT_PREFIX.match(parts[0]):
                subset_hits += 1

    cues: list[str] = []
    if has_catalog and has_pages_tree:
        cues.append("valid_catalog_and_page_tree")
    if no_active_scripts:
        cues.append("zero_embedded_scripts")
    if no_polyglot_or_diff:
        cues.append("parser_and_envelope_consistent")
    if no_malformed_codecs:
        cues.append("no_malformed_media_headers")
    if subset_hits > 0:
        cues.append("standard_subset_font_naming")

    score = round(min(1.0, len(cues) / 5.0), 4)
    return {
        "consistency_score": score,
        "cues": cues,
        "quota_limited_resources": len(codec_limits),
    }


def fuse_neural_and_static_evidence(
    *,
    raw_logit: float,
    raw_prob: float,
    threshold: float,
    temperature: float,
    hard_reasons: set[str],
) -> dict[str, Any]:
    """Combine calibrated neural log-odds with deduplicated Tier-1 static policy weights."""
    ordered_reasons = sorted(r for r in hard_reasons if r)
    if not ordered_reasons:
        return {
            "applied": False,
            "fused_logit": raw_logit,
            "fused_prob": raw_prob,
            "policy_override": False,
            "score_source": "neural_calibrated",
            "reasons": [],
        }

    if raw_prob >= threshold:
        return {
            "applied": False,
            "fused_logit": raw_logit,
            "fused_prob": raw_prob,
            "policy_override": False,
            "score_source": "neural_and_static_aligned",
            "reasons": ordered_reasons,
        }

    temp = temperature if math.isfinite(temperature) and 1e-6 <= temperature <= 1e6 else 1.0
    p_clamped = min(max(raw_prob if math.isfinite(raw_prob) else 0.5, 1e-12), 1.0 - 1e-12)
    z_neural = max(math.log(p_clamped) - math.log1p(-p_clamped), -1.80)
    total_weight = sum(HIGH_SEVERITY_POLICY_WEIGHTS.get(reason, 2.20) for reason in ordered_reasons)
    z_anchor = 2.08 + 0.35 * total_weight
    z_combined = min(max(z_anchor, z_neural + total_weight), 6.90)
    p_candidate = 1.0 / (1.0 + math.exp(-z_combined))

    thr_safe = min(max(threshold if math.isfinite(threshold) else 0.5, 0.0), math.nextafter(1.0, 0.0))
    ceil_prob = max(0.999, thr_safe)
    fused_prob = min(max(p_candidate, thr_safe), ceil_prob)
    if fused_prob <= 0.0:
        fused_prob = math.nextafter(0.0, 1.0)
    log_odds = math.log(fused_prob) - math.log1p(-fused_prob)
    fused_logit = max(-1e300, min(1e300, log_odds * temp))

    return {
        "applied": True,
        "fused_logit": fused_logit,
        "fused_prob": fused_prob,
        "policy_override": True,
        "score_source": "policy_fusion",
        "reasons": ordered_reasons,
    }
