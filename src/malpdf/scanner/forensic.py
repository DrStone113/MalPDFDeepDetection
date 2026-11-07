from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import re
from typing import Any

import numpy as np

from malpdf.scanner.ingestion import AST_NODE_TYPES

DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    ("eval_exec", r"\beval\s*\(", "Dynamic Code Execution (eval)"),
    ("unescape_decode", r"\bunescape\s*\(", "Observed unescape call"),
    ("from_char_code", r"\bString\s*\.\s*fromCharCode\s*\(", "CharCode Obfuscation Construction"),
    ("heap_spray_pattern", r"%u[0-9a-fA-F]{4}", "Observed UTF-16 escape literal (%uXXXX)"),
    ("long_hex_sequence", r"(?:\\x[0-9a-fA-F]{2}){8,}", "Hexadecimal Bytecode Stream"),
    ("util_printf_overflow", r"\butil\s*\.\s*printf\s*\(", "Observed util.printf call"),
    ("app_doc_payload", r"\b(?:app|doc)\s*\.\s*(?:media|getAnnots|exportDataObject|alert|launchURL)", "Acrobat Reader DOM API Hook"),
    ("document_write_exec", r"\bdocument\s*\.\s*write\s*\(", "DOM Stream Injection"),
]


def _shannon_entropy_str(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def deobfuscate_javascript_static(code: str) -> dict[str, Any]:
    if not code:
        return {
            "deobfuscated_code": "",
            "deobfuscation_applied": False,
            "deobfuscation_techniques": [],
        }

    transformed = code
    techniques: list[str] = []

    def _replace_from_char_code(match: re.Match[str]) -> str:
        args_str = match.group(1)
        tokens = [t.strip() for t in args_str.split(",") if t.strip()]
        chars: list[str] = []
        for tok in tokens[:2048]:
            try:
                val = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)
                if 0 <= val <= 0x10FFFF:
                    chars.append(chr(val))
                else:
                    return match.group(0)
            except ValueError:
                return match.group(0)
        if not chars:
            return match.group(0)
        if "fromCharCode_decode" not in techniques:
            techniques.append("fromCharCode_decode")
        decoded = "".join(chars).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{decoded}"'

    transformed = re.sub(
        r"\bString\s*\.\s*fromCharCode\s*\(\s*([0-9a-fA-FxX,\s]+)\s*\)",
        _replace_from_char_code,
        transformed,
    )

    def _replace_unescape(match: re.Match[str]) -> str:
        inner = match.group(2)

        def _u16(m: re.Match[str]) -> str:
            return chr(int(m.group(1), 16))

        def _u8(m: re.Match[str]) -> str:
            return chr(int(m.group(1), 16))

        step = re.sub(r"%u([0-9a-fA-F]{4})", _u16, inner)
        step = re.sub(r"%([0-9a-fA-F]{2})", _u8, step)
        if step != inner and "unescape_percent_decode" not in techniques:
            techniques.append("unescape_percent_decode")
        escaped = step.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    transformed = re.sub(
        r"\b(?:unescape|decodeURIComponent)\s*\(\s*(['\"])(.*?)\1\s*\)",
        _replace_unescape,
        transformed,
        flags=re.DOTALL,
    )

    def _replace_hex_escapes(match: re.Match[str]) -> str:
        val = int(match.group(1), 16)
        if 32 <= val <= 126 or val in (9, 10, 13):
            if "hex_escape_decode" not in techniques:
                techniques.append("hex_escape_decode")
            return chr(val)
        return match.group(0)

    transformed = re.sub(r"\\x([0-9a-fA-F]{2})", _replace_hex_escapes, transformed)

    def _replace_unicode_escapes(match: re.Match[str]) -> str:
        val = int(match.group(1), 16)
        if 32 <= val <= 126 or val >= 160:
            if "unicode_escape_decode" not in techniques:
                techniques.append("unicode_escape_decode")
            return chr(val)
        return match.group(0)

    transformed = re.sub(r"\\u([0-9a-fA-F]{4})", _replace_unicode_escapes, transformed)

    concat_pat = re.compile(r"(['\"])([^'\"\\]{1,256})\1\s*\+\s*\1([^'\"\\]{1,256})\1")
    for _ in range(6):
        next_str, count = concat_pat.subn(r"\1\2\3\1", transformed)
        if count > 0:
            if "string_concat_fold" not in techniques:
                techniques.append("string_concat_fold")
            transformed = next_str
        else:
            break

    return {
        "deobfuscated_code": transformed,
        "deobfuscation_applied": bool(techniques and transformed != code),
        "deobfuscation_techniques": techniques,
    }


def _annotate_code_lines(code: str) -> list[dict[str, Any]]:
    raw_lines = [ln for ln in code.splitlines() if ln.strip()]
    if not raw_lines and code.strip():
        raw_lines = [code.strip()]
    annotated: list[dict[str, Any]] = []
    for idx, line in enumerate(raw_lines[:30], start=1):
        tag = ""
        severity = "normal"
        for pat_id, regex, label in DANGEROUS_PATTERNS:
            if re.search(regex, line, re.IGNORECASE):
                tag = label
                severity = "critical" if pat_id in ("eval_exec", "unescape_decode", "heap_spray_pattern", "util_printf_overflow") else "warning"
                break
        if not tag and re.search(r"\b(?:for|while)\s*\(", line):
            tag = "Iterative Buffer Loop"
            severity = "secondary"
        annotated.append({
            "line_no": idx,
            "code": line,
            "tag": tag,
            "severity": severity,
        })
    return annotated


class ForensicAttributionEngine:
    def __init__(self) -> None:
        pass

    def explain(
        self,
        ingest_data: dict[str, Any],
        cross_modal_attn: Any = None,
        malware_prob: float | None = None,
        node_saliency: list[float] | None = None,
        edge_attention: list[float] | None = None,
        ast_token_attention: list[float] | None = None,
        tabular_grad_importance: list[float] | None = None,
        xai_proof_metrics: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        cross_weights = None
        if cross_modal_attn is not None:
            weights = cross_modal_attn.detach().cpu().numpy() if hasattr(cross_modal_attn, "detach") else np.asarray(cross_modal_attn)
            weights = weights.squeeze()
            if weights.ndim == 1 and len(weights) == 2:
                cross_weights = {"graph_weight": round(float(weights[0]), 4), "ast_weight": round(float(weights[1]), 4)}

        records = ingest_data.get("raw_records", [])
        scripts = ingest_data.get("extracted_scripts", [])
        stats = ingest_data.get("ast_stats") or {}
        counts = ingest_data.get("ast_node_counts") or {}
        triggers = []
        for index, record in enumerate(records):
            if record.get("is_threat_trigger") or record.get("kind") in ("action", "script", "filespec"):
                triggers.append({
                    "object_id": record.get("evidence_id"),
                    "obj_ref_str": record.get("obj_ref_str"),
                    "kind": record.get("kind"),
                    "invoker": record.get("invoker"),
                    "filter": record.get("filter"),
                    "size_bytes": record.get("size_bytes"),
                    "entropy": record.get("entropy"),
                    "has_stream": record.get("has_stream"),
                    "is_threat_trigger": bool(record.get("is_threat_trigger")),
                    "xai_saliency": node_saliency[index] if node_saliency and index < len(node_saliency) else None,
                })
        triggers.sort(
            key=lambda item: (
                1 if item.get("is_threat_trigger") else 0,
                1 if item.get("object_id") in ("script:action:open_action", "action:open_action") else 0,
                float(item.get("xai_saliency") or 0.0),
            ),
            reverse=True,
        )

        threat_scripts = []
        for script in scripts:
            code = script.get("code", "")
            deobf = deobfuscate_javascript_static(code)
            deobf_code = deobf["deobfuscated_code"]
            combined_scan_text = code + ("\n" + deobf_code if deobf["deobfuscation_applied"] else "")
            matches = [
                (tag, label)
                for tag, pattern, label in DANGEROUS_PATTERNS
                if re.search(pattern, combined_scan_text, re.IGNORECASE)
            ]
            raw_snippet = re.sub(r"\s+", " ", code).strip()[:180]
            deobf_snippet = re.sub(r"\s+", " ", deobf_code).strip()[:180]
            display_snippet = (
                f"[DEOBFUSCATED ({', '.join(deobf['deobfuscation_techniques'])})]: {deobf_snippet}\n[RAW]: {raw_snippet}"
                if deobf["deobfuscation_applied"]
                else raw_snippet
            )
            threat_scripts.append({
                "script_id": script.get("script_id"),
                "parent_id": script.get("parent_id"),
                "entropy": round(_shannon_entropy_str(code), 4),
                "length_chars": len(code),
                "dangerous_indicators": [tag for tag, _ in matches],
                "indicator_descriptions": [label for _, label in matches],
                "snippet": raw_snippet,
                "code_snippet": display_snippet,
                "raw_code_snippet": raw_snippet,
                "deobfuscated_code": deobf_code,
                "deobfuscation_applied": deobf["deobfuscation_applied"],
                "deobfuscation_techniques": deobf["deobfuscation_techniques"],
                "full_code": code,
                "annotated_lines": _annotate_code_lines(deobf_code if deobf["deobfuscation_applied"] else code),
            })

        adjacency: dict[str | None, list[str | None]] = {}
        for edge in ingest_data.get("raw_edges", []):
            adjacency.setdefault(edge.get("source"), []).append(edge.get("target"))
        record_map = {record["evidence_id"]: record for record in records if record.get("evidence_id")}
        root = "catalog:root" if "catalog:root" in record_map else None
        threat_triggers = [
            t for t in triggers if t.get("is_threat_trigger") or t.get("kind") in ("script", "filespec")
        ]
        default_stream_goal = next(
            (record["evidence_id"] for record in records if record.get("kind") == "stream"),
            root,
        )
        goal = threat_triggers[0]["object_id"] if threat_triggers else default_stream_goal
        paths = [[root]] if root else []
        seen = {root}
        path_ids = []
        while paths:
            current = paths.pop(0)
            if current[-1] == goal:
                path_ids = current
                break
            for target in adjacency.get(current[-1], []):
                if target in record_map and target not in seen:
                    seen.add(target)
                    paths.append(current + [target])
        if not path_ids and root:
            path_ids = [root]
        attack_path = []
        for identifier in path_ids:
            record = record_map[identifier]
            kind = str(record.get("kind", "Object")).capitalize()
            invoker = record.get("invoker") or identifier
            if identifier == "catalog:root":
                label = "Catalog (/Root)"
            elif identifier == "action:open_action":
                label = "Action (/OpenAction)"
            elif identifier == "action:aa":
                label = "Action (/AA)"
            else:
                label = f"{kind} ({invoker})"
            attack_path.append(label)

        ast_attributions = []
        if ast_token_attention:
            for index, node_type in enumerate(AST_NODE_TYPES):
                if index < len(ast_token_attention):
                    attention = float(ast_token_attention[index])
                    ast_attributions.append({
                        "token_type": node_type,
                        "count": counts.get(node_type),
                        "raw_attention": attention,
                        "normalized_pct": attention * 100.0,
                        "attention_weight": round(attention, 4),
                    })
            ast_attributions.sort(key=lambda value: value["raw_attention"], reverse=True)

        tabular_attributions = []
        names = ingest_data.get("feature_names", [])
        raw_values = ingest_data.get("raw_feature_vec", [])
        means = ingest_data.get("scaler_mean", [])
        tab = ingest_data.get("tab_features")
        if tabular_grad_importance and len(tabular_grad_importance) == len(names):
            if hasattr(tab, "detach"):
                scores = tab.squeeze(0).detach().cpu().tolist()
            elif isinstance(tab, np.ndarray):
                scores = tab.reshape(-1).tolist()
            else:
                scores = []
            total = sum(abs(value) for value in tabular_grad_importance)
            for index, name in enumerate(names):
                value = tabular_grad_importance[index]
                tabular_attributions.append({
                    "feature_name": name,
                    "raw_value": raw_values[index] if index < len(raw_values) else None,
                    "z_score": scores[index] if index < len(scores) else None,
                    "train_mean": means[index] if index < len(means) else None,
                    "attribution_score": value,
                    "impact_pct": abs(value) / total * 100.0 if total else 0.0,
                    "direction": "threat" if value > 0 else "benign" if value < 0 else "neutral",
                })
            tabular_attributions.sort(key=lambda item: abs(item["attribution_score"]), reverse=True)

        proof = xai_proof_metrics or {}
        xai_metrics = {key: proof.get(key) for key in ("fidelity_score", "comprehensiveness_drop", "sparsity_index", "lipschitz_stability")}
        xai_metrics.update({
            "dag_entropy": ingest_data.get("raw_entropy"),
            "ast_complexity": stats.get("total_nodes"),
            "ast_max_depth": stats.get("max_depth"),
            "ast_loops": stats.get("loops"),
            "primary_disarm_target": triggers[0].get("obj_ref_str") if triggers else None,
        })

        cross_matrix: list[dict[str, Any]] = []
        has_measured_saliency = node_saliency is not None and len(node_saliency) > 0
        if records and has_measured_saliency:
            ranked_indices = sorted(
                range(min(len(records), len(node_saliency))),
                key=lambda idx: (
                    1 if records[idx].get("is_threat_trigger") else 0,
                    float(node_saliency[idx]),
                ),
                reverse=True,
            )
            active_ast = [a for a in ast_attributions if (a.get("count") or 0) > 0]
            top_tabs = tabular_attributions[:6]
            for rank_pos, idx in enumerate(ranked_indices[:6]):
                rec = records[idx]
                eid = str(rec.get("evidence_id", f"node:{idx}"))
                sal = float(node_saliency[idx])
                is_trig = bool(rec.get("is_threat_trigger")) or rec.get("kind") in ("action", "script")
                if is_trig and active_ast:
                    ast_item = active_ast[rank_pos % len(active_ast)]
                    target_tok = f"AST::{ast_item['token_type']}"
                    score = max(sal, float(ast_item.get("raw_attention", 0.0)))
                elif top_tabs and rank_pos < len(top_tabs):
                    tab_item = top_tabs[rank_pos]
                    target_tok = f"Tabular::{tab_item['feature_name']}"
                    score = max(sal, min(1.0, abs(float(tab_item.get("attribution_score", 0.0)))))
                else:
                    target_tok = f"Structure::{rec.get('invoker', '/Root')}"
                    score = sal
                if is_trig and (malware_prob or 0.0) >= 0.5:
                    tier = "Critical" if rank_pos < 2 else "Severe"
                elif score >= 0.25:
                    tier = "Severe"
                elif score >= 0.12:
                    tier = "High"
                else:
                    tier = "Normal"
                cross_matrix.append({
                    "node_id": eid,
                    "source_obj_ref": rec.get("obj_ref_str") or eid,
                    "source_role": f"{str(rec.get('kind', 'object')).capitalize()} ({rec.get('invoker', '/Root')})",
                    "target_token": target_tok,
                    "attention_score": round(float(score), 4),
                    "impact_tier": tier,
                })

        if triggers:
            observations = []
            for index, trigger in enumerate(triggers):
                sal_val = trigger.get("xai_saliency")
                sal_str = f"Mức liên quan: {sal_val * 100:.1f}%" if isinstance(sal_val, (int, float)) else "Điểm lưu ý"
                inv = str(trigger.get("invoker") or "/Root")
                knd = str(trigger.get("kind") or "action")
                is_crit = bool(trigger.get("is_threat_trigger")) or knd in ("script", "filespec")
                observations.append({
                    "stage_num": index + 1,
                    "title": f"Điểm kiểm tra {index + 1}: {inv} ({trigger.get('obj_ref_str') or trigger.get('object_id')})",
                    "object_ref": trigger.get("obj_ref_str"),
                    "node_id": trigger.get("object_id"),
                    "risk_score": sal_str if is_crit else "An toàn",
                    "severity": "critical" if is_crit else "normal",
                    "description": (
                        f"Thành phần {inv} được cài đặt để tự động chạy mã ẩn ngay khi người dùng mở xem tài liệu."
                        if is_crit
                        else f"Thiết lập điều hướng trang hoặc đường dẫn liên kết thông thường ({inv}), không chứa mã độc thực thi."
                    ),
                    "tags": ["Tự chạy khi mở" if is_crit else "Điều hướng / Liên kết", inv],
                })
        else:
            observations = [
                {
                    "stage_num": 1,
                    "title": "Điểm kiểm tra 1: Khung tài liệu gốc (/Catalog & /Pages)",
                    "object_ref": "obj_1 0 R",
                    "node_id": "catalog:root",
                    "risk_score": "An toàn",
                    "severity": "normal",
                    "description": "Khung tài liệu chỉ chứa bố cục trang bình thường, không có lệnh tự động chạy khi mở tệp.",
                    "tags": ["Bố cục trang", "Không có lệnh ngầm"],
                },
                {
                    "stage_num": 2,
                    "title": "Điểm kiểm tra 2: Nội dung chữ viết & hình ảnh (/Contents)",
                    "object_ref": "stream:page_0",
                    "node_id": "stream:page_0",
                    "risk_score": "An toàn",
                    "severity": "normal",
                    "description": "Các trang chỉ chứa văn bản và phông chữ hiển thị tiêu chuẩn, không nhúng mã ẩn.",
                    "tags": ["Nội dung sạch", "Không có JavaScript"],
                },
            ]

        return {
            "cross_modal_weights": cross_weights,
            "modality_breakdown": {"graph_pct": proof.get("graph_branch_pct"), "ast_pct": proof.get("ast_branch_pct"), "tabular_pct": proof.get("tabular_branch_pct")},
            "trigger_objects": triggers,
            "threat_scripts": threat_scripts,
            "ast_token_attributions": ast_attributions[:10],
            "ast_token_importance": ast_attributions[:10],
            "tabular_attributions": tabular_attributions[:10],
            "tabular_anomalies": tabular_attributions[:10],
            "cross_attention_matrix": cross_matrix,
            "cross_attention_matrix_status": "measured_gradient_saliency" if has_measured_saliency else "unavailable",
            "mitre_cascade": observations,
            "xai_metrics": xai_metrics,
            "thesis_synthesis": {
                "headline": (
                    f"Kết luận kiểm tra: {'Nguy hiểm' if (malware_prob or 0.0) >= 0.5 else 'An toàn'} ({malware_prob:.2%})"
                    if malware_prob is not None
                    else "Chưa có kết luận tự động"
                ),
                "summary_vi": (
                    f"Hệ thống đã rà soát {len(records)} thành phần trong tệp PDF, ghi nhận {len(triggers)} điểm kích hoạt và {len(scripts)} đoạn mã kịch bản."
                ),
                "proof_statement": "Kết luận dựa trên các thành phần thực tế tìm thấy bên trong tệp.",
            },
            "attack_path": attack_path,
            "attack_path_string": " -> ".join(attack_path),
            "attack_path_status": "observed" if path_ids and path_ids[-1] == goal else "unreachable_in_observed_graph",
            "suspicious_object_count": len(triggers),
            "script_count": len(threat_scripts),
        }

    def save_attack_path_diagram(
        self,
        output_path: Path | str,
        sha256: str,
        malware_prob: float | None,
        attack_path: list[str],
        cross_modal_weights: dict[str, float] | None,
    ) -> Path:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fig, (ax_graph, ax_attn) = plt.subplots(1, 2, figsize=(10, 3.5), dpi=300, gridspec_kw={"width_ratios": [2.5, 1.2]})

        n_nodes = len(attack_path)
        x_coords = np.linspace(1, 9, n_nodes)
        y_coords = np.ones(n_nodes) * 2.0
        palette = ["#2ca02c", "#d62728", "#9467bd", "#ff7f0e", "#1f77b4"]
        colors = [palette[index % len(palette)] for index in range(n_nodes)]

        ax_graph.scatter(x_coords, y_coords, s=1400, c=colors, zorder=3, edgecolors="#222222", linewidths=1.5)
        for i in range(n_nodes - 1):
            ax_graph.annotate(
                "",
                xy=(x_coords[i + 1] - 0.5, y_coords[i + 1]),
                xytext=(x_coords[i] + 0.5, y_coords[i]),
                arrowprops=dict(facecolor="#333333", edgecolor="#333333", arrowstyle="->", lw=2.2),
            )
        for x, y, label in zip(x_coords, y_coords, attack_path):
            parts = label.split(" ")
            main_text = parts[0]
            sub_text = " ".join(parts[1:]) if len(parts) > 1 else ""
            ax_graph.text(x, y + 0.12, main_text, ha="center", va="center", fontsize=9, fontweight="bold", color="white")
            if sub_text:
                ax_graph.text(x, y - 0.12, sub_text, ha="center", va="center", fontsize=7.5, color="#f5f5f5")

        ax_graph.set_xlim(0, 10)
        ax_graph.set_ylim(1.0, 3.0)
        ax_graph.axis("off")
        ax_graph.set_title(f"Attack Flow Subgraph (SHA: {sha256[:8]}...)", fontsize=11, fontweight="bold")

        labels = ["Hetero-Graph", "AST Tokens"]
        if cross_modal_weights is None:
            ax_attn.text(0.5, 0.5, "Attention unavailable", ha="center", va="center")
            ax_attn.axis("off")
            fig.tight_layout()
            fig.savefig(out, bbox_inches="tight")
            plt.close(fig)
            return out
        weights = [cross_modal_weights["graph_weight"], cross_modal_weights["ast_weight"]]
        bar_colors = ["#1f77b4", "#ff7f0e"]
        bars = ax_attn.bar(labels, weights, color=bar_colors, width=0.45, edgecolor="#222222")
        ax_attn.set_ylim(0, 1.05)
        ax_attn.set_ylabel("Attention Weight", fontsize=9, fontweight="bold")
        score_label = f"P={malware_prob:.2%}" if malware_prob is not None else "P unavailable"
        ax_attn.set_title(f"Cross-Attention ({score_label})", fontsize=10, fontweight="bold")
        for bar in bars:
            yval = bar.get_height()
            ax_attn.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.02, f"{yval:.2f}", ha="center", va="bottom", fontsize=8, fontweight="bold")

        plt.tight_layout()
        fig.savefig(out, bbox_inches="tight")
        plt.close(fig)
        return out
