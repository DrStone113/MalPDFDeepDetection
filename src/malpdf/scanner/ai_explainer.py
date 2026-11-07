from __future__ import annotations

import re
from typing import Any


CLIENT_LLM_SYSTEM_PROMPT = (
    "Bạn là Trợ lý Phân tích An toàn Tài liệu của hệ thống phòng thủ MalPDF DeepDetection. "
    "Nhiệm vụ của bạn là đọc phiếu kết quả kiểm tra tệp PDF do hệ thống cung cấp và giải thích dễ hiểu bằng tiếng Việt cho người dùng: "
    "tình trạng an toàn của tệp, ý nghĩa các thành phần bên trong, và hướng dẫn làm sạch tệp (CDR) để đọc văn bản an toàn. "
    "Nếu người dùng chào hỏi hoặc hỏi bạn là mô hình gì, hãy giới thiệu ngắn gọn thân thiện và tóm tắt luôn kết quả kiểm tra tệp hiện tại."
)
DEFAULT_WEBLLM_MODEL = "Qwen2.5-1.5B-Instruct-q4f16_1-MLC"
FALLBACK_WEBLLM_MODEL = "Llama-3.2-1B-Instruct-q4f16_1-MLC"


class AIThreatExplainer:
    def __init__(self) -> None:
        pass

    def build_compact_llm_context(
        self,
        scan_result: dict[str, Any],
        cdr_audit: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        verdict = scan_result.get("verdict", "UNAVAILABLE")
        prob = scan_result.get("malware_probability")
        prob_pct = round(prob * 100, 2) if isinstance(prob, (int, float)) else None
        pages = scan_result.get("pages_count", 1)
        size_kb = round(scan_result.get("file_size_bytes", 0) / 1024.0, 2)
        pdf_version = scan_result.get("pdf_version", "1.7")
        file_name = scan_result.get("file_name", "document.pdf")
        is_ood = bool(scan_result.get("is_ood"))
        ood_score = scan_result.get("ood_score")
        dossier = scan_result.get("forensic_dossier", {}) or {}
        taxonomy = scan_result.get("threat_taxonomy") or dossier.get("threat_taxonomy") or {}
        threat_label = taxonomy.get("threat_label") or (
            "HEUR:Trojan.PDF.Generic" if verdict == "MALICIOUS" else "Clean.PDF.Verified"
        )
        threat_title_vi = taxonomy.get("threat_title_vi") or (
            "Tệp PDF có dấu hiệu chứa mã độc" if verdict == "MALICIOUS" else "Tài liệu PDF an toàn"
        )
        all_triggers = dossier.get("trigger_objects", []) or dossier.get("suspicious_triggers", []) or []
        active_triggers = [t for t in all_triggers if t.get("is_threat_trigger") or t.get("kind") in ("script", "filespec")]
        triggers = active_triggers if (active_triggers or verdict == "BENIGN") else all_triggers
        scripts = dossier.get("threat_scripts", []) or dossier.get("script_findings", []) or []
        attack_path_str = dossier.get("attack_path_string") or " -> ".join(
            dossier.get("attack_path") or ["Catalog (/Root)"]
        )

        trigger_items = [
            f"{t.get('invoker', '/Unknown')} ({t.get('obj_ref_str') or t.get('object_id')})"
            for t in triggers[:5]
        ]
        script_summaries: list[dict[str, Any]] = []
        detail_parts: list[str] = []
        for s in scripts[:3]:
            inds = (s.get("dangerous_indicators") or [])[:5]
            raw_snippet = str(s.get("deobfuscated_code") or s.get("raw_code_snippet") or s.get("snippet") or "")
            clean_snippet = re.sub(r"\s+", " ", raw_snippet).strip()[:120]
            sid = str(s.get("script_id") or "script")
            script_summaries.append(
                {
                    "script_id": sid,
                    "indicators": inds,
                    "deobfuscated": bool(s.get("deobfuscation_applied", False)),
                    "snippet_preview": clean_snippet,
                }
            )
            if inds:
                detail_parts.append(f"Found suspicious {', '.join(inds)} inside {sid}")

        if trigger_items:
            detail_parts.append(f"Triggers: {', '.join(trigger_items)}")
        if not detail_parts:
            detail_parts.append(
                "No embedded JavaScript or automatic execution triggers detected."
                if verdict == "BENIGN"
                else f"Detected {threat_label} via attack path {attack_path_str}"
            )

        status_str = "Malicious" if verdict == "MALICIOUS" else ("Benign" if verdict == "BENIGN" else "Unavailable")
        threat_type_str = (
            "Embedded Javascript / AutoAction"
            if scripts
            else (threat_label if verdict == "MALICIOUS" else "None")
        )

        cdr_summary: dict[str, Any] | None = None
        if isinstance(cdr_audit, dict) and cdr_audit.get("is_sanitized"):
            post_ver = cdr_audit.get("post_scan_verification") or {}
            p_after = post_ver.get("prob_after")
            cdr_summary = {
                "is_sanitized": True,
                "removed_triggers": (cdr_audit.get("removed_triggers") or [])[:6],
                "prob_after_pct": round(p_after * 100, 2) if isinstance(p_after, (int, float)) else None,
                "pages_preserved": f"{cdr_audit.get('sanitized_pages', pages)}/{cdr_audit.get('original_pages', pages)}",
            }

        return {
            "status": status_str,
            "verdict": verdict,
            "malware_probability_pct": prob_pct,
            "threat_type": threat_type_str,
            "threat_label": threat_label,
            "threat_title_vi": threat_title_vi,
            "details": "; ".join(detail_parts)[:360],
            "file_name": file_name,
            "pages_count": pages,
            "file_size_kb": size_kb,
            "pdf_version": pdf_version,
            "is_ood": is_ood,
            "ood_score": round(ood_score, 4) if isinstance(ood_score, (int, float)) else None,
            "attack_path": attack_path_str[:180],
            "triggers": trigger_items,
            "scripts": script_summaries,
            "mitre_attack": [
                f"{m.get('id')}: {m.get('name')}"
                for m in (taxonomy.get("mitre_attack") or [])[:4]
                if isinstance(m, dict)
            ],
            "cdr_sanitization": cdr_summary,
        }

    def explain_threat(
        self,
        scan_result: dict[str, Any],
        cdr_audit: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        verdict = scan_result.get("verdict", "UNAVAILABLE")
        prob = scan_result.get("malware_probability")
        prob_pct = round(prob * 100, 2) if isinstance(prob, (int, float)) else None
        confidence = scan_result.get("confidence", "UNAVAILABLE")
        ood_score = scan_result.get("ood_score")
        ood_threshold = scan_result.get("ood_threshold", -0.85)
        is_ood = scan_result.get("is_ood")
        pages = scan_result.get("pages_count", 1)
        size_kb = round(scan_result.get("file_size_bytes", 0) / 1024.0, 2)
        pdf_version = scan_result.get("pdf_version", "1.7")
        raw_entropy = scan_result.get("raw_entropy", 0.0)
        file_name = scan_result.get("file_name", "document.pdf")
        dossier = scan_result.get("forensic_dossier", {}) or {}
        taxonomy = scan_result.get("threat_taxonomy") or dossier.get("threat_taxonomy") or {}
        threat_label = taxonomy.get("threat_label") or ("HEUR:Trojan.PDF.Generic" if verdict == "MALICIOUS" else "Clean.PDF.Verified")
        threat_title_vi = taxonomy.get("threat_title_vi") or (
            "Tệp PDF có dấu hiệu chứa mã độc" if verdict == "MALICIOUS" else "Tài liệu PDF an toàn"
        )
        threat_cats = taxonomy.get("threat_categories") or []
        behavior_tags = taxonomy.get("behavior_tags") or []
        mitre_list = taxonomy.get("mitre_attack") or []
        detected_cnt = taxonomy.get("detected_count", 0)
        total_analyzers = taxonomy.get("total_analyzers", 8)
        all_triggers = dossier.get("trigger_objects", []) or dossier.get("suspicious_triggers", []) or []
        active_triggers = [t for t in all_triggers if t.get("is_threat_trigger") or t.get("kind") in ("script", "filespec")]
        triggers = active_triggers if (active_triggers or verdict == "BENIGN") else all_triggers
        scripts = dossier.get("threat_scripts", []) or dossier.get("script_findings", []) or []
        attack_path_str = dossier.get("attack_path_string") or " -> ".join(dossier.get("attack_path") or ["Catalog (/Root)"])

        indicators: list[str] = []
        deobf_techniques: list[str] = []
        for s in scripts:
            indicators.extend(s.get("dangerous_indicators", []))
            for tech in s.get("deobfuscation_techniques", []):
                if tech not in deobf_techniques:
                    deobf_techniques.append(tech)
        unique_indicators = list(dict.fromkeys(indicators))
        trigger_names = [
            f"{t.get('invoker', '/Unknown')} ({t.get('obj_ref_str') or t.get('object_id')})"
            for t in triggers
        ]
        trigger_summary = ", ".join(trigger_names[:4]) if trigger_names else "không có lệnh tự động chạy"

        cdr_status_text = (
            f"Bạn có thể bấm 'Làm sạch tệp' ngay trên web để gỡ bỏ {len(triggers)} thành phần tự chạy ({trigger_summary}) mà vẫn giữ nguyên vẹn toàn bộ chữ viết và hình ảnh của {pages} trang tài liệu."
            if triggers
            else "Tệp không có lệnh tự chạy nguy hiểm. Nếu muốn cẩn thận hơn khi nhận tệp từ người lạ, bạn vẫn có thể bấm 'Làm sạch tệp' trước khi xem."
        )
        if isinstance(cdr_audit, dict) and cdr_audit.get("is_sanitized"):
            removed = cdr_audit.get("removed_triggers", [])
            post_ver = cdr_audit.get("post_scan_verification") or {}
            p_before = post_ver.get("prob_before")
            p_after = post_ver.get("prob_after")
            if isinstance(p_before, (int, float)) and isinstance(p_after, (int, float)):
                cdr_status_text = (
                    f"Tệp đã được làm sạch an toàn: đã gỡ bỏ {len(removed)} lệnh kích hoạt ngầm, mức rủi ro giảm từ {p_before * 100:.2f}% xuống còn {p_after * 100:.2f}%, giữ nguyên đủ {cdr_audit.get('sanitized_pages', pages)}/{cdr_audit.get('original_pages', pages)} trang."
                )

        compact_ctx = self.build_compact_llm_context(scan_result, cdr_audit=cdr_audit)

        if prob_pct is None or verdict == "UNAVAILABLE":
            blockers = ", ".join(scan_result.get("prediction_blockers", [])[:4]) or "unverified_training_contract"
            return {
                "explanation_method": "deterministic_evidence_summary",
                "danger_level": "UNAVAILABLE",
                "danger_score": None,
                "headline": "Chưa đủ thông tin để đánh giá tự động bằng AI",
                "executive_summary": (
                    f"Tệp '{file_name}' ({size_kb} KB, {pages} trang) đã được đọc cấu trúc cơ bản, "
                    f"nhưng chưa thể chấm điểm rủi ro tự động ({blockers}). "
                    f"Các thành phần ghi nhận trực tiếp trong tệp: {trigger_summary}."
                ),
                "danger_analysis": [
                    {
                        "title": "Trạng thái kiểm tra",
                        "severity": "warning",
                        "detail": f"Chưa tính được điểm rủi ro tự động do thiếu thông số đầu vào ({blockers}).",
                    },
                    {
                        "title": "Thành phần tìm thấy",
                        "severity": "warning" if triggers or scripts else "safe",
                        "detail": f"Tìm thấy {len(triggers)} điểm kích hoạt ({trigger_summary}) và {len(scripts)} đoạn mã kịch bản.",
                    },
                    {
                        "title": "Cách xử lý an toàn",
                        "severity": "info",
                        "detail": "Bạn nên dùng chức năng 'Làm sạch tệp' để gỡ bỏ toàn bộ lệnh chạy ngầm trước khi mở xem.",
                    },
                ],
                "technical_breakdown": [
                    f"Điểm kích hoạt ghi nhận được: {trigger_summary}.",
                    f"Số đoạn mã kịch bản bên trong: {len(scripts)}.",
                    f"Lý do chưa chấm điểm tự động: {blockers}.",
                ],
                "remediation": (
                    "Không nên mở trực tiếp tệp gốc khi chưa rõ nguồn gốc. Hãy chuyển sang mục 'Làm sạch tệp' "
                    "để loại bỏ các lệnh chạy ngầm rồi tải bản sạch về đọc."
                ),
                "llm_compact_context": compact_ctx,
                "llm_system_prompt": CLIENT_LLM_SYSTEM_PROMPT,
                "preferred_webllm_model": DEFAULT_WEBLLM_MODEL,
                "fallback_webllm_model": FALLBACK_WEBLLM_MODEL,
            }

        if verdict == "MALICIOUS":
            danger_level = "CRITICAL" if prob_pct >= 85 else "HIGH"
            deobf_note = (
                " Đoạn mã này đã bị cố tình viết rối chữ để che giấu nội dung thật."
                if deobf_techniques
                else ""
            )
            mitre_str = ", ".join(f"{m['name']} ({m['id']})" for m in mitre_list[:3]) if mitre_list else "Thực thi mã ngầm"
            cats_str = ", ".join(threat_cats) if threat_cats else "trojan"
            breakdown = [
                f"Loại mối đe dọa: {threat_title_vi} (mã nhận diện: {threat_label}).",
                f"Kết quả rà soát: {detected_cnt}/{total_analyzers} hạng mục kiểm tra phát hiện dấu hiệu nguy hiểm.",
                f"Hành vi ghi nhận: {mitre_str}.",
                f"Vị trí gắn lệnh tự chạy trong tệp: {trigger_summary}.",
                f"Đoạn mã ẩn bên trong: phát hiện {len(scripts)} đoạn mã JavaScript.{deobf_note}",
                f"Trình tự kích hoạt khi mở tệp: {attack_path_str}.",
            ]
            return {
                "explanation_method": "deterministic_evidence_summary",
                "danger_level": danger_level,
                "danger_score": prob_pct,
                "headline": f"{threat_title_vi} — Mức độ rủi ro {prob_pct}%",
                "executive_summary": (
                    f"Tệp '{file_name}' ({pages} trang, {size_kb} KB) có dấu hiệu nguy hiểm rất rõ ràng ({prob_pct}% rủi ro). "
                    f"Bên cạnh nội dung văn bản thông thường, tệp này bị cài sẵn {len(triggers)} lệnh tự động kích hoạt và {len(scripts)} đoạn mã ẩn. "
                    f"Nếu bạn mở tệp trực tiếp, đoạn mã ngầm sẽ tự động chạy ngay lập tức mà không hỏi ý kiến. "
                    f"Hãy bấm 'Làm sạch tệp' để gỡ bỏ phần mã độc trước khi đọc."
                ),
                "danger_analysis": [
                    {
                        "title": "Tệp này là loại gì?",
                        "severity": "critical",
                        "detail": (
                            f"{threat_title_vi} ({threat_label}, nhóm: {cats_str}). "
                            f"Có {detected_cnt}/{total_analyzers} hạng mục kiểm tra phát hiện bất thường."
                        ),
                    },
                    {
                        "title": "Điều gì xảy ra nếu mở tệp?",
                        "severity": "high",
                        "detail": (
                            f"Khi vừa mở tài liệu, lệnh tự động ({trigger_summary}) sẽ âm thầm kích hoạt {len(scripts)} đoạn mã JavaScript ẩn bên trong."
                        ),
                    },
                    {
                        "title": "Cách đọc nội dung an toàn",
                        "severity": "info",
                        "detail": cdr_status_text,
                    },
                ],
                "technical_breakdown": breakdown,
                "remediation": (
                    f"Không mở trực tiếp tệp gốc trên máy tính. Hãy bấm nút 'Làm sạch tệp' để hệ thống tự động gỡ bỏ "
                    f"{len(triggers)} lệnh chạy ngầm nhưng vẫn giữ nguyên chữ và hình ảnh, sau đó tải bản PDF an toàn về xem."
                ),
                "llm_compact_context": compact_ctx,
                "llm_system_prompt": CLIENT_LLM_SYSTEM_PROMPT,
                "preferred_webllm_model": DEFAULT_WEBLLM_MODEL,
                "fallback_webllm_model": FALLBACK_WEBLLM_MODEL,
            }

        return {
            "explanation_method": "deterministic_evidence_summary",
            "danger_level": "SAFE",
            "danger_score": prob_pct,
            "headline": f"Tài liệu an toàn — Không phát hiện mã độc (rủi ro thấp {prob_pct}%)",
            "executive_summary": (
                f"Tệp '{file_name}' ({pages} trang, {size_kb} KB) đã vượt qua cả {total_analyzers} hạng mục kiểm tra an toàn. "
                f"Hệ thống không tìm thấy mã độc, lệnh tự động chạy hay đoạn mã ẩn đáng ngờ nào bên trong tài liệu này. "
                f"Bạn có thể yên tâm mở đọc bình thường."
            ),
            "danger_analysis": [
                {
                    "title": "Kết quả kiểm tra",
                    "severity": "safe",
                    "detail": f"Tài liệu sạch ({threat_label}), mức rủi ro rất thấp ({prob_pct}%), không có cảnh báo nào từ {total_analyzers} hạng mục.",
                },
                {
                    "title": "Thành phần bên trong",
                    "severity": "safe",
                    "detail": f"Không có lệnh tự động chạy khi mở tệp và không có mã kịch bản ẩn trong {pages} trang tài liệu.",
                },
                {
                    "title": "Hướng dẫn sử dụng",
                    "severity": "info",
                    "detail": cdr_status_text,
                },
            ],
            "technical_breakdown": [
                f"Thông tin tệp: {pages} trang, dung lượng {size_kb} KB, phiên bản PDF {pdf_version}.",
                f"Đánh giá an toàn: {threat_title_vi} ({detected_cnt}/{total_analyzers} hạng mục cảnh báo).",
                "Lệnh tự động kích hoạt & mã ẩn: Không phát hiện.",
            ],
            "remediation": "Tài liệu an toàn, bạn có thể mở xem bình thường. Nếu tệp nhận từ nguồn lạ, bạn vẫn có thể bấm 'Làm sạch tệp' để loại bỏ toàn bộ thành phần tương tác phụ.",
            "llm_compact_context": compact_ctx,
            "llm_system_prompt": CLIENT_LLM_SYSTEM_PROMPT,
            "preferred_webllm_model": DEFAULT_WEBLLM_MODEL,
            "fallback_webllm_model": FALLBACK_WEBLLM_MODEL,
        }

    def answer_question(
        self,
        scan_result: dict[str, Any],
        question: str,
        cdr_audit: dict[str, Any] | None = None,
    ) -> str:
        explanation = self.explain_threat(scan_result, cdr_audit=cdr_audit)
        query = question.lower().strip()
        verdict = scan_result.get("verdict", "UNAVAILABLE")
        verdict_vi = "NGUY HIỂM" if verdict == "MALICIOUS" else ("AN TOÀN" if verdict == "BENIGN" else "CHƯA XÁC ĐỊNH")
        prob = scan_result.get("malware_probability")
        prob_str = f"{prob * 100:.2f}%" if isinstance(prob, (int, float)) else "Chưa rõ"
        file_name = scan_result.get("file_name", "document.pdf")
        pages = scan_result.get("pages_count", 1)
        size_kb = round(scan_result.get("file_size_bytes", 0) / 1024.0, 2)
        pdf_version = scan_result.get("pdf_version", "1.7")
        raw_entropy = scan_result.get("raw_entropy", 0.0)
        ood_score = scan_result.get("ood_score")
        ood_threshold = scan_result.get("ood_threshold", -0.85)
        is_ood = scan_result.get("is_ood")

        dossier = scan_result.get("forensic_dossier", {}) or {}
        taxonomy = scan_result.get("threat_taxonomy") or dossier.get("threat_taxonomy") or {}
        all_triggers = dossier.get("trigger_objects", []) or dossier.get("suspicious_triggers", []) or []
        active_triggers = [t for t in all_triggers if t.get("is_threat_trigger") or t.get("kind") in ("script", "filespec")]
        triggers = active_triggers if (active_triggers or verdict == "BENIGN") else all_triggers
        scripts = dossier.get("threat_scripts", []) or dossier.get("script_findings", []) or []
        attack_path = dossier.get("attack_path_string") or " -> ".join(dossier.get("attack_path") or ["Catalog (/Root)"])
        modality = dossier.get("modality_breakdown") or {}
        xai_metrics = dossier.get("xai_metrics") or {}
        tab_anomalies = dossier.get("tabular_attributions") or dossier.get("tabular_anomalies") or []
        cross_matrix = dossier.get("cross_attention_matrix") or []
        graph_nodes = scan_result.get("graph_nodes") or (dossier.get("interactive_graph") or {}).get("nodes") or []

        t_label = taxonomy.get("threat_label") or ("HEUR:Trojan.PDF.Generic" if verdict == "MALICIOUS" else "Clean.PDF.Verified")
        t_title = taxonomy.get("threat_title_vi") or ("Tệp có dấu hiệu mã độc" if verdict == "MALICIOUS" else "Tài liệu an toàn")
        sections: list[str] = [
            f"Kết quả kiểm tra `{file_name}`: **{verdict_vi} ({verdict})** — Mức độ rủi ro: **{prob_str}**"
        ]

        obj_match = re.search(r"\b(?:obj_?)?(\d+)\s+0\s+r\b|\bobj[_\s]+(\d+)\b", query)
        matched_specific_section = False

        is_greeting_or_identity = bool(
            re.search(r"\b(hello|hi|hey|alo|qwen|llama|webllm)\b", query)
            or any(
                w in query
                for w in (
                    "xin chào",
                    "xin chao",
                    "chào bạn",
                    "chao ban",
                    "bạn là ai",
                    "ban la ai",
                    "bạn là model gì",
                    "ban la model gi",
                    "model gi",
                    "model gì",
                    "mô hình gì",
                    "mo hinh gi",
                )
            )
        )
        if is_greeting_or_identity:
            matched_specific_section = True
            sections.append(
                "Xin chào bạn! Mình là **Trợ lý Phân tích An toàn Tài liệu** của hệ thống **MalPDF DeepDetection**:\n"
                "- **Trợ lý ngôn ngữ trên trình duyệt (Client-side AI):** Vận hành trên **WebLLM (WebGPU)** với mô hình **`Qwen2.5-1.5B-Instruct`** (hoặc **`Llama-3.2-1B-Instruct`**) kết hợp bộ giải thích chuẩn xác của **MalPDF DeepDetection**.\n"
                "- **Động cơ phát hiện lõi (Core Scanner):** **PDF-TransGraph v2 (23D HGT + AST Transformer + 38D Tabular)** và **PDFMultiLabelThreatNet v2 (8 nhãn hành vi)** chạy trên **ONNX Runtime**.\n"
                f"- **Tóm tắt tệp đang mở (`{file_name}`):** {explanation['executive_summary']}"
            )

        if any(w in query for w in ("loại", "chủng", "họ", "trojan", "exploit", "dropper", "phishing", "virustotal", "vt", "mitre", "att&ck", "phân loại", "family", "category", "tag", "nhãn")):
            matched_specific_section = True
            cats = ", ".join(f"`{c}`" for c in (taxonomy.get("threat_categories") or [])) or "`không có`"
            tags = ", ".join(f"`{b}`" for b in (taxonomy.get("behavior_tags") or [])) or "`pdf`"
            mitre_rows = [
                f"  - **{m['name']}** (mã kỹ thuật `{m['id']}`): ghi nhận tại `{m['evidence']}`"
                for m in (taxonomy.get("mitre_attack") or [])
            ]
            det_rows = [
                f"  - **{a['analyzer']}**: {a['evidence']}"
                for a in (taxonomy.get("analyzer_detections") or [])
                if a.get("detected")
            ]
            sections.append(
                "Phân loại chi tiết mối đe dọa:\n"
                f"- **Tên gọi dễ hiểu:** {t_title}\n"
                f"- **Mã phân loại kỹ thuật:** `{t_label}` (nhóm: {cats})\n"
                f"- **Đặc điểm phát hiện trong tệp:** {tags}\n"
                f"- **Giải thích:** {taxonomy.get('summary_vi', '')}\n"
                f"- **Số hạng mục phát hiện bất thường:** `{taxonomy.get('detected_count', 0)}/{taxonomy.get('total_analyzers', 8)}`\n"
                + ("\n".join(det_rows) + "\n" if det_rows else "")
                + ("- **Hành vi tương ứng (MITRE ATT&CK):**\n" + "\n".join(mitre_rows) if mitre_rows else "- **Hành vi tấn công:** Không phát hiện.")
            )

        if obj_match or any(w in query for w in ("đối tượng", "object", "node", "nút", "offset", "hex", "catalog", "openaction", "/aa", "/xfa", "đồ thị", "cấu trúc", "dag", "adobe", "reader")):
            matched_specific_section = True
            target_num = (obj_match.group(1) or obj_match.group(2)) if obj_match else None
            node_lines: list[str] = []
            for n in graph_nodes:
                oref = str(n.get("obj_ref") or "")
                inv = str(n.get("invoker") or "")
                nid = str(n.get("id") or "")
                if target_num and f"obj_{target_num} " not in oref and f":{target_num}" not in nid:
                    continue
                node_lines.append(
                    f"- Thành phần `{nid}` (`{oref or 'trực tiếp'}` | vị trí `{inv}` | kích thước `{n.get('size_bytes', 0)} byte`)"
                )
            if not node_lines and graph_nodes:
                for n in graph_nodes[:5]:
                    node_lines.append(
                        f"- Thành phần `{n.get('id')}` (`{n.get('obj_ref') or 'trực tiếp'}` | vị trí `{n.get('invoker')}`)"
                    )
            open_effect = (
                f"Nếu mở trực tiếp bằng phần mềm đọc PDF (như Adobe Reader), tệp sẽ đi theo đường dẫn `{attack_path}` để tự động kích hoạt lệnh ngầm mà bạn không biết."
                if verdict == "MALICIOUS"
                else "Khi mở bằng phần mềm đọc PDF, tệp chỉ hiển thị các trang văn bản bình thường, không tự chạy lệnh ngầm nào."
            )
            sections.append(
                "Cấu trúc bên trong & điều gì xảy ra khi mở tệp:\n"
                f"- {open_effect}\n"
                f"- **Tổng số thành phần trong tệp:** `{len(graph_nodes)}` thành phần (trong đó có `{len(triggers)}` điểm đáng chú ý).\n"
                + ("\n".join(node_lines[:6]) if node_lines else "")
            )

        if any(w in query for w in ("js", "javascript", "script", "ast", "eval", "unescape", "fromcharcode", "obfuscat", "giải mã", "payload", "mã độc", "kịch bản", "token")):
            matched_specific_section = True
            if scripts:
                s_lines: list[str] = []
                for idx_s, s in enumerate(scripts, 1):
                    inds = ", ".join(s.get("dangerous_indicators", [])) or "không rõ"
                    deobf_flag = s.get("deobfuscation_applied", False)
                    deobf_info = (
                        f"Nội dung sau khi làm rõ mã rối: `{s.get('deobfuscated_code', '')[:140]}`"
                        if deobf_flag
                        else f"Đoạn mã trích xuất: `{s.get('raw_code_snippet') or s.get('snippet', '')}`"
                    )
                    s_lines.append(
                        f"- **Đoạn mã JavaScript #{idx_s} (`{s.get('script_id')}`):** dài `{s.get('length_chars')} ký tự`, dấu hiệu đáng ngờ: `{inds}`.\n  - {deobf_info}"
                    )
                sections.append(
                    "Các đoạn mã JavaScript ẩn tìm thấy trong tệp:\n"
                    + "\n".join(s_lines)
                )
            else:
                sections.append(
                    "Kiểm tra mã JavaScript ẩn:\n"
                    "- Không tìm thấy bất kỳ đoạn mã JavaScript chạy ngầm nào trong tệp PDF này."
                )

        if any(w in query for w in ("mô hình", "model", "transgraph", "gnn", "hgt", "rwse", "tabular", "z-score", "entropy", "đặc trưng", "feature", "tại sao", "vì sao", "nguyên nhân", "nguy hiểm", "antivirus", "diệt virus")):
            matched_specific_section = True
            g_pct = modality.get("graph_pct")
            a_pct = modality.get("ast_pct")
            t_pct = modality.get("tabular_pct")
            mod_line = (
                f"- **Cơ sở kết luận của AI:** Dựa `{g_pct:.1f}%` vào cấu trúc liên kết của tệp, `{a_pct:.1f}%` vào nội dung mã ẩn và `{t_pct:.1f}%` vào các thông số thống kê.\n"
                if all(isinstance(v, (int, float)) for v in (g_pct, a_pct, t_pct))
                else ""
            )
            why_line = (
                "- **Vì sao cần chú ý?** Nhiều tệp PDF độc hại cố tình làm rối chữ trong đoạn mã để tránh bị phát hiện theo chữ ký cố định, nhưng vẫn phải gắn lệnh tự chạy vào khung tài liệu — đó là điểm hệ thống này kiểm tra trực tiếp.\n"
                if verdict == "MALICIOUS"
                else "- **Vì sao tệp an toàn?** Cả bố cục trang lẫn các thành phần bên trong đều là nội dung hiển thị tiêu chuẩn, không có dấu hiệu giấu mã.\n"
            )
            tab_lines = [
                f"- Thông số `{item.get('feature_name')}` có giá trị `{item.get('raw_value'):.2f}` (khác biệt so với mức thông thường `{item.get('train_mean'):.2f}`)"
                for item in tab_anomalies[:3]
                if isinstance(item.get("raw_value"), (int, float))
            ]
            sections.append(
                "Giải thích nguyên nhân đánh giá:\n"
                + why_line
                + mod_line
                + f"- **Thông tin tệp:** PDF phiên bản `{pdf_version}` | `{pages}` trang | dung lượng `{size_kb} KB`\n"
                + ("\n".join(tab_lines) if tab_lines else "")
            )

        if any(w in query for w in ("xai", "fidelity", "comprehensiveness", "sparsity", "lipschitz", "ood", "energy", "ablation", "toán học", "chứng minh", "độ tin cậy")):
            matched_specific_section = True
            fid = xai_metrics.get("fidelity_score")
            comp = xai_metrics.get("comprehensiveness_drop")
            spar = xai_metrics.get("sparsity_index")
            lip = xai_metrics.get("lipschitz_stability")
            ood_line = (
                f"- **Độ quen thuộc cấu trúc (OOD):** điểm đo `{ood_score:.4f}` so với ngưỡng `{ood_threshold:.2f}` -> **{'Cấu trúc lạ cần lưu ý (OOD)' if is_ood else 'Cấu trúc quen thuộc bình thường'}**\n"
                if isinstance(ood_score, (int, float))
                else "- **Độ quen thuộc cấu trúc (OOD):** Chưa có số đo.\n"
            )
            proof_line = (
                f"- **Độ sát thực tế của giải thích (Fidelity):** `{fid:.4f}`\n"
                f"- **Mức giảm rủi ro khi bỏ phần nghi ngờ (Comprehensiveness):** `{comp:.4f}`\n"
                f"- **Độ tập trung bằng chứng (Sparsity):** `{spar:.1f}%`\n"
                f"- **Độ ổn định (Lipschitz):** `±{lip:.4f}`\n"
                if all(isinstance(v, (int, float)) for v in (fid, comp, spar, lip))
                else "- **Chỉ số chi tiết:** Chưa đo trên phiên hiện tại.\n"
            )
            cm_lines = [
                f"  - `{row.get('source_role')}` (`{row.get('source_obj_ref')}`) -> `{row.get('target_token')}` (mức liên quan `{row.get('attention_score'):.4f}`)"
                for row in cross_matrix[:3]
            ]
            sections.append(
                "Các chỉ số kiểm chứng độ tin cậy (XAI & OOD):\n"
                + ood_line
                + proof_line
                + ("- **Các thành phần ảnh hưởng nhiều nhất đến kết luận:**\n" + "\n".join(cm_lines) if cm_lines else "")
            )

        if any(w in query for w in ("cdr", "tẩy độc", "khử độc", "làm sạch", "an toàn", "mở", "xử lý", "khắc phục", "disarm")):
            matched_specific_section = True
            if isinstance(cdr_audit, dict) and cdr_audit.get("is_sanitized"):
                removed = cdr_audit.get("removed_triggers", [])
                post_ver = cdr_audit.get("post_scan_verification") or {}
                p_before = post_ver.get("prob_before")
                p_after = post_ver.get("prob_after")
                v_after = post_ver.get("verdict_after", "BENIGN")
                orig_sz = cdr_audit.get("original_size_bytes", 1)
                clean_sz = cdr_audit.get("sanitized_size_bytes", 0)
                retain_pct = (clean_sz / max(orig_sz, 1)) * 100.0
                prob_cmp = (
                    f"giảm mạnh từ **{p_before * 100:.2f}%** xuống chỉ còn **{p_after * 100:.2f}%** (**{v_after}**)"
                    if isinstance(p_before, (int, float)) and isinstance(p_after, (int, float))
                    else f"**{v_after}**"
                )
                sections.append(
                    "Kết quả làm sạch tệp PDF (CDR):\n"
                    f"- **Trạng thái:** Đã gỡ bỏ phần nguy hiểm thành công trong `{cdr_audit.get('disarm_latency_ms', 0)} ms`.\n"
                    f"- **Thành phần nguy hiểm đã gỡ bỏ ({len(removed)}):** `{', '.join(removed) if removed else 'Không có'}`\n"
                    f"- **Kiểm tra lại sau khi làm sạch:** Mức độ rủi ro {prob_cmp}.\n"
                    f"- **Nội dung đọc giữ nguyên:** Bảo toàn đủ `{cdr_audit.get('sanitized_pages')}/{cdr_audit.get('original_pages')} trang` (`{retain_pct:.1f}%` dung lượng), chữ viết và bố cục giữ nguyên vẹn."
                )
            else:
                sections.append(
                    "Cách làm sạch tệp an toàn (CDR):\n"
                    f"- {explanation['remediation']}\n"
                    "- **Cách hoạt động rất đơn giản:** Hệ thống chỉ cắt bỏ đúng các lệnh tự chạy và mã ẩn (`/OpenAction`, `/AA`, `/JavaScript`, `/Launch`), hoàn toàn không đụng vào chữ viết, phông chữ hay hình ảnh của tài liệu."
                )

        if not matched_specific_section:
            sections.append(
                f"Tóm tắt dễ hiểu:\n{explanation['executive_summary']}\n\n"
                "Các điểm chính ghi nhận được:\n"
                + "\n".join(f"- {item}" for item in explanation["technical_breakdown"])
                + f"\n\nLời khuyên cho bạn:\n- {explanation['remediation']}"
            )

        return "\n\n".join(sections)
