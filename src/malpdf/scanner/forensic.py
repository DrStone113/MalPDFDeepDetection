from __future__ import annotations

import base64
import binascii
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any
import unicodedata
from urllib.parse import unquote, urlsplit

import esprima
import numpy as np

from malpdf.scanner.js_intent import analyze_pdf_javascript_intent, classify_obfuscation_techniques
from malpdf.static.js_semantics import SemanticBudget, SemanticLimits, analyze_js_tree
from malpdf.static.js_semantics import children as js_children

TRIGGER_FEATURES_V3 = {
    "lexical_JS",
    "lexical_JavaScript",
    "lexical_OpenAction",
    "lexical_AA",
    "lexical_Launch",
    "lexical_EmbeddedFile",
    "lexical_XFA",
    "js_per_obj",
}
_NON_THREAT_AUDIT_MARKERS = frozenset({"action_inspection_limit", "codec_inspection_limit"})
_BENIGN_CATALOG_ACTION_ROLES = frozenset({"destination", "benign_navigation", "empty_aa"})
_CATALOG_ACTION_TOKENS = {"action:open_action": "OpenAction", "action:aa": "AA"}
_CLEAN_CALIBRATION_FLOOR = 0.004


def observed_ast_distribution(ingest_data: dict[str, Any]) -> list[float]:
    from malpdf.scanner.ingestion import AST_NODE_TYPES

    if not ingest_data.get("extracted_scripts"):
        return []
    counts = ingest_data.get("ast_node_counts") or {}
    values = [counts.get(name, 0) for name in AST_NODE_TYPES]
    total = sum(values)
    return [value / total for value in values] if total else []


DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    ("eval_exec", r"\beval\s*\(", "Gọi thực thi mã động (eval)"),
    ("unescape_decode", r"\bunescape\s*\(", "Gọi giải mã chuỗi %u (unescape)"),
    ("from_char_code", r"\bString\s*\.\s*fromCharCode\s*\(", "Ghép chuỗi từ mã ký tự (String.fromCharCode)"),
    ("heap_spray_pattern", r"%u[0-9a-fA-F]{4}", "Chuỗi ký tự thoát UTF-16 (%uXXXX)"),
    ("long_hex_sequence", r"(?:\\x[0-9a-fA-F]{2}){8,}", "Chuỗi byte thập lục phân dài (\\xNN)"),
    ("util_printf_overflow", r"\butil\s*\.\s*printf\s*\(", "Gọi hàm util.printf()"),
    (
        "app_doc_payload",
        r"\b(?:app|doc)\s*\.\s*(?:media|getAnnots|exportDataObject|importDataObject|launchURL|submitForm|addScript|syncAnnotScan)\b",
        "Gọi API trình đọc PDF (app/doc)",
    ),
    ("document_write_exec", r"\bdocument\s*\.\s*write\s*\(", "Ghi nội dung qua document.write()"),
    ("function_constructor_exec", r"\b(?:new\s+)?(?-i:Function)\s*\(", "Tạo hàm từ chuỗi mã JavaScript"),
    ("base64_atob_call", r"\batob\s*\(", "Giải mã chuỗi Base64"),
    ("prototype_constructor_exec", r"\.constructor\s*\(", "Gọi hàm qua thuộc tính constructor"),
    ("metadata_payload_staging", r"\bthis\s*\.\s*info\b", "Tham chiếu siêu dữ liệu của tài liệu"),
    ("dynamic_bracket_exec", r"\b(?:this|window|globalThis)\s*\[", "Truy cập thuộc tính động của đối tượng toàn cục"),
]


def _describe_trigger_cascade(inv: str, knd: str, action_role: str | None, is_crit: bool) -> str:
    if action_role == "verified_benign_js":
        return "Hành động JavaScript đã được kiểm chứng theo mục đích sử dụng trong tài liệu."
    if action_role == "destination":
        return "Khóa /OpenAction thiết lập trang đích điều hướng khi mở tài liệu."
    if action_role == "benign_navigation":
        return "Hành động điều hướng trình xem an toàn (chuyển trang/đích hiển thị)."
    if action_role == "empty_aa":
        return "Khóa /AA rỗng không chứa hành động thực thi."
    if action_role == "remote_goto":
        return "Hành động /GoToR tham chiếu tài liệu bên ngoài."
    if action_role == "file_attachment":
        return "Chú thích /FileAttachment trỏ đến tệp đính kèm qua /FS."
    if "/OpenAction" in inv:
        return "Khóa /OpenAction kích hoạt hành động tự động ngay khi mở tài liệu."
    if "/AA" in inv:
        return "Khóa /AA định nghĩa hành động tự chạy theo sự kiện đóng, mở hoặc chuyển trang."
    if "/Names/JavaScript" in inv:
        return "Danh mục /Names/JavaScript lưu trữ đoạn mã JavaScript bên trong tệp."
    if "/XFA" in inv:
        return "Biểu mẫu /AcroForm/XFA chứa định nghĩa biểu mẫu XML động."
    if knd == "filespec" or "/EmbeddedFiles" in inv:
        return "Đính kèm tệp bên ngoài (/EmbeddedFiles) bên trong cấu trúc PDF."
    if knd == "script" or "/JS" in inv or "/JavaScript" in inv:
        return "Đoạn mã JavaScript trích xuất từ đối tượng cấu trúc PDF."
    if is_crit:
        return f"Đối tượng kích hoạt hoặc thực thi ghi nhận tại {inv}."
    return f"Đối tượng cấu trúc tại {inv}."


def _shannon_entropy_str(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_EXPLOIT_APIS = re.compile(
    r"\b(?:util\s*\.\s*printf|Collab\s*\.\s*(?:collectEmailInfo|getIcon)|media\s*\.\s*newPlayer"
    r"|spell\s*\.\s*customDictionaryOpen|exportDataObject|importDataObject|ActiveXObject|WScript|Shell)\s*\(",
    re.IGNORECASE,
)
_UNSAFE_JS_SYNTAX = re.compile(
    r"\\x[0-9a-fA-F]{2}|\\u00[0-7][0-9a-fA-F]|\b(?:with|setTimeout|setInterval)\s*\("
    r"|\b(?:eval|Function|__proto__|constructor)\b|\barguments\s*\["
)
_MAX_JS_BYTES = 256 * 1024
_MAX_FLOW_STRING = 2048
_FLOW_LIMITS = SemanticLimits(max_nodes=4000, max_steps=8000)
_JS_CALL_NAME = re.compile(r"[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*")


@dataclass(frozen=True)
class _JSReference:
    names: tuple[str, ...]


_JSValue = str | tuple[str, ...] | _JSReference | None


def _merge_js_values(left: _JSValue, right: _JSValue) -> _JSValue:
    if left == right:
        return left
    if isinstance(left, _JSReference) and isinstance(right, _JSReference):
        names = tuple(sorted(set(left.names) | set(right.names)))
        return _JSReference(names) if len(names) <= 4 else None
    return None


def _js_member_reference(owner: _JSValue, prop: _JSValue) -> _JSReference | None:
    if not isinstance(owner, _JSReference) or not isinstance(prop, str) or not _JS_CALL_NAME.fullmatch(prop):
        return None
    names = []
    for prefix in owner.names:
        name = f"{prefix}.{prop}"
        if prefix in {"this", "window", "globalThis"} and prop in {"eval", "Function", "atob", "unescape"}:
            name = prop
        elif name == "this.submitForm":
            name = "doc.submitForm"
        if len(name) <= _MAX_FLOW_STRING:
            names.append(name)
    return _JSReference(tuple(names)) if names else None


def _js_join(values: tuple[str, ...], separator: str) -> str | None:
    if len(separator) > 4 or not separator.isascii():
        return None
    if sum(map(len, values)) + max(0, len(values) - 1) * len(separator) > _MAX_JS_BYTES:
        return None
    return separator.join(values)


def _resolve_js_ast_flow(tree: dict) -> tuple[set[str], set[str]]:
    strings: set[str] = set()
    calls: set[str] = set()
    remaining = _FLOW_LIMITS.max_nodes

    def visit(node: dict | None, bindings: dict[str, _JSValue], depth: int = 0) -> _JSValue:
        nonlocal remaining
        if node is None or remaining <= 0 or depth > 80:
            return None
        remaining -= 1

        def read(child: dict | None) -> _JSValue:
            return visit(child, bindings, depth + 1)

        kind = node["type"]
        if kind == "Literal":
            value = node.get("value")
        elif kind == "Identifier":
            name = node["name"]
            value = bindings[name] if name in bindings else _JSReference((name,))
        elif kind == "ThisExpression":
            value = _JSReference(("this",))
        elif kind == "MemberExpression":
            owner = read(node["object"])
            prop = read(node["property"]) if node["computed"] else node["property"].get("name")
            return _js_member_reference(owner, prop)
        elif kind in {"VariableDeclarator", "AssignmentExpression"}:
            target = node["id" if kind == "VariableDeclarator" else "left"]
            value = read(node.get("init" if kind == "VariableDeclarator" else "right"))
            if target["type"] != "Identifier":
                read(target)
                return None
            name = target["name"]
            operator = node.get("operator", "=")
            if operator != "=":
                previous = bindings.get(name)
                value = (
                    previous + value
                    if operator == "+=" and isinstance(previous, str) and isinstance(value, str)
                    else None
                )
            bindings[name] = value if not isinstance(value, str) or len(value) <= _MAX_FLOW_STRING else None
        elif kind == "BinaryExpression":
            left, right = read(node["left"]), read(node["right"])
            value = (
                left + right if node["operator"] == "+" and isinstance(left, str) and isinstance(right, str) else None
            )
        elif kind == "ArrayExpression":
            elements = tuple(read(item) for item in node["elements"][:257])
            return elements if len(elements) <= 256 and all(isinstance(item, str) for item in elements) else None
        elif kind in {"CallExpression", "NewExpression"}:
            callee = node["callee"]
            if callee["type"] == "MemberExpression":
                owner = read(callee["object"])
                prop = read(callee["property"]) if callee["computed"] else callee["property"].get("name")
                reference = _js_member_reference(owner, prop)
            else:
                owner, prop = None, None
                reference = read(callee)
            args = [read(arg) for arg in node["arguments"]]
            if isinstance(reference, _JSReference) and len(calls) < 256:
                calls.update(reference.names)
            value = None
            if kind == "CallExpression":
                if prop == "reverse" and isinstance(owner, tuple) and not args:
                    return owner[::-1]
                if prop == "join" and isinstance(owner, tuple) and len(args) == 1 and isinstance(args[0], str):
                    value = _js_join(owner, args[0])
                elif prop == "split" and args == [""] and isinstance(owner, str):
                    return tuple(owner) if len(owner) <= 256 and all(ord(char) <= 0xFFFF for char in owner) else None
        elif kind in {"IfStatement", "ConditionalExpression"}:
            read(node["test"])
            branches = [bindings.copy(), bindings.copy()]
            branch_values = [
                visit(node.get(key), branch, depth + 1) for key, branch in zip(("consequent", "alternate"), branches)
            ]
            for name in branches[0].keys() | branches[1].keys():
                left, right = (branch.get(name) for branch in branches)
                bindings[name] = _merge_js_values(left, right)
            return _merge_js_values(*branch_values)
        elif kind in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            function = node.get("id")
            if kind == "FunctionDeclaration" and function:
                bindings[function["name"]] = None
            local = dict.fromkeys(bindings)
            local.update((param["name"], None) for param in node["params"] if param["type"] == "Identifier")
            visit(node["body"], local, depth + 1)
            return None
        else:
            for _, child in js_children(node):
                if remaining <= 0:
                    break
                read(child)
            return None
        if isinstance(value, str):
            if len(value) > _MAX_FLOW_STRING:
                return None
            if len(strings) < 256:
                strings.add(value)
            return value
        return value if isinstance(value, _JSReference) else None

    visit(tree, {})
    return strings, calls


def _inspect_js_flow(code: str, budget: SemanticBudget | None = None) -> tuple[set[str], set[str], bool]:
    try:
        tree = esprima.parseScript(code, {"tolerant": True}).toDict()
    except (esprima.Error, RecursionError, ValueError):
        return set(), set(), True
    strings, calls = _resolve_js_ast_flow(tree)
    if budget is not None:
        digest = hashlib.sha256(code.encode("utf-8", errors="surrogatepass")).hexdigest()
        analysis = analyze_js_tree(tree, digest, budget=budget)
        calls.update(name for call in analysis["calls"] for name in call["known_api_candidates"])
    return strings, calls, False


def evaluate_javascript_semantics(
    extracted_scripts: list[dict[str, Any]],
    ast_stats: dict[str, float] | None = None,
    ast_node_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    codes = [script.get("code") for script in extracted_scripts]
    intent = analyze_pdf_javascript_intent([code if isinstance(code, str) else "" for code in codes])
    indicators: set[str] = set()
    techniques: set[str] = set()
    evasive_techniques: set[str] = set()
    resolved_calls: set[str] = set()
    resolved_urls: set[str] = set()
    budget = SemanticBudget(_FLOW_LIMITS)
    inspected = {}
    for code, report in zip(codes, intent["per_script_intents"], strict=True):
        if not isinstance(code, str):
            report.update(
                is_verified_benign=False, intent_label_vi="", unverified_reasons=["javascript_body_unavailable"]
            )
            continue
        if not code.strip() or report["intent_codes"] == ["empty_noop"] or len(code) > _MAX_JS_BYTES:
            continue
        if len(code.encode("utf-8", errors="surrogatepass")) > _MAX_JS_BYTES:
            continue
        if code not in inspected:
            deobfuscated = deobfuscate_javascript_static(code)
            folded = deobfuscated["deobfuscation_techniques"]
            techniques.update(folded)
            evasive, _ = classify_obfuscation_techniques(code, folded)
            strings, flow_calls, syntax_error = _inspect_js_flow(code, budget)
            normalized = deobfuscated["deobfuscated_code"]
            if normalized != code:
                folded_strings, folded_calls, _ = _inspect_js_flow(normalized)
                strings.update(folded_strings)
                flow_calls.update(folded_calls)
            resolved_calls.update(flow_calls)
            urls = {match.group() for value in strings for match in EMBEDDED_URI_PATTERN.finditer(value)}
            resolved_urls.update(urls)
            text = "\n".join(
                (code, normalized, "\n".join(sorted(strings)), *(f"{name}(" for name in sorted(flow_calls)))
            )
            found = {tag for tag, pattern, _ in DANGEROUS_PATTERNS if re.search(pattern, text, re.IGNORECASE)}
            found.update(re.sub(r"\s", "", match.group()[:-1]) for match in _EXPLOIT_APIS.finditer(text))
            if syntax_error:
                found.add("javascript_syntax_error")
            if any(is_suspicious_uri(uri)[0] for uri in urls):
                found.add("js_flow_suspicious_uri")
            reasons = set()
            if _UNSAFE_JS_SYNTAX.search(code):
                reasons.add("unsafe_javascript_syntax")
            if found:
                reasons.add("dangerous_javascript_indicator")
            if evasive:
                reasons.add("evasive_obfuscation")
            inspected[code] = found, evasive, reasons
            indicators.update(found)
            evasive_techniques.update(evasive)
        found, evasive, reasons = inspected[code]
        if reasons:
            report.update(
                is_verified_benign=False,
                intent_label_vi="",
                unverified_reasons=sorted(set(report["unverified_reasons"]) | reasons),
                dangerous_indicators=sorted(set(report["dangerous_indicators"]) | found),
                evasive_obfuscation_techniques=sorted(set(report["evasive_obfuscation_techniques"]) | set(evasive)),
            )
    indicators.update(intent["dangerous_indicators"])
    evasive_techniques.update(intent["evasive_obfuscation_techniques"])
    reports = intent["per_script_intents"]
    verified = bool(reports) and all(report["is_verified_benign"] for report in reports)
    return {
        **intent,
        "has_scripts": bool(codes),
        "is_verified_benign_js": verified,
        "intent_summary_vi": intent["intent_summary_vi"] if verified else "",
        "script_intents": sorted(
            {code for report in reports if report["is_verified_benign"] for code in report["intent_codes"]}
        ),
        "unverified_reasons": sorted({reason for report in reports for reason in report["unverified_reasons"]}),
        "malicious_indicator_count": len(indicators),
        "dangerous_indicators": sorted(indicators),
        "deobfuscation_techniques": sorted(techniques),
        "evasive_obfuscation_techniques": sorted(evasive_techniques),
        "benign_api_calls": sorted(
            {call for report in reports if report["is_verified_benign"] for call in report["benign_api_calls"]}
        ),
        "resolved_calls": sorted(resolved_calls),
        "resolved_urls": sorted(resolved_urls),
        "flow_suspicious_urls": [uri for uri in sorted(resolved_urls) if is_suspicious_uri(uri)[0]],
    }


def invalidate_incomplete_javascript_verification(ingest_data: dict[str, Any]) -> None:
    js = ingest_data["js_semantics"]
    non_js = set(ingest_data.get("non_js_triggers", ()))
    raw_tokens = ingest_data.get("raw_tokens", {})
    stream_interior = (ingest_data.get("structural_audit") or {}).get("stream_interior_tokens") or {}
    xfa = ingest_data.get("xfa_analysis", {})
    gaps = non_js.intersection(
        {"javascript_body_unavailable", "action_inspection_limit", "supplemental_inspection_incomplete"}
    )
    if ingest_data.get("evasion_unpack_audit", {}).get("hex_escaped_names_decoded", 0) > 0:
        gaps.add("hex_escaped_pdf_names")
    if xfa.get("present") or xfa.get("anomalies"):
        gaps.add("xfa_javascript_unverified")
    if not ingest_data.get("extracted_scripts") and any(
        raw_tokens.get(token, 0) > stream_interior.get(token, 0) for token in ("JS", "JavaScript")
    ):
        gaps.add("javascript_body_unavailable")
    if gaps:
        js.update(
            is_verified_benign_js=False,
            intent_summary_vi="",
            unverified_reasons=sorted(set(js.get("unverified_reasons", ())) | gaps),
        )


_DANGEROUS_URI_SCHEMES = {"javascript", "vbscript", "data", "file", "smb", "mhtml", "jar"}
EMBEDDED_URI_PATTERN = re.compile(
    r"\b(?:https?://|(?:" + "|".join(sorted(_DANGEROUS_URI_SCHEMES)) + r"):)[^\s\"'<>]*", re.IGNORECASE
)
_URI_PAYLOAD = re.compile(
    r"\.(?:exe|scr|bat|cmd|ps1|vbs|hta|msi|dll|iso|lnk|zip|rar|7z|js|jse|wsf|docm|xlsm|apk|dmg|pkg)(?![a-z0-9])",
    re.IGNORECASE,
)
_URI_CREDENTIAL = re.compile(
    r"(?<![a-z0-9])(?:log-?in|sign-?in|verify-account|docusign-verify|onedrive-secure|sharepoint-auth"
    r"|webmail-auth|password-reset|oauth-token)(?![a-z0-9])"
)
_KNOWN_AUTH_HOSTS = {
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "account.microsoft.com",
    "account.docusign.com",
    "github.com",
    "doi.org",
    "arxiv.org",
    "example.org",
}
_OFFICIAL_URI_DOMAINS = frozenset(
    """
    microsoft.com live.com microsoftonline.com office.com sharepoint.com onedrive.com docusign.com
    google.com adobe.com paypal.com apple.com dropbox.com github.com arxiv.org doi.org nist.gov nasa.gov irs.gov
    example.org example.com edu gov mil edu.vn gov.vn chinhphu.vn orcid.org ieee.org acm.org springer.com
    sciencedirect.com nature.com iso.org w3.org ietf.org python.org wikipedia.org wikimedia.org linkedin.com
""".split()
)
_PHISHING_SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co cutt.ly is.gd rebrand.ly ngrok-free.app trycloudflare.com".split()
)
_USER_CONTENT_OR_REDIRECT_HOSTS = frozenset(
    """
    forms.gle forms.office.com 1drv.ms lnkd.in rb.gy ow.ly shorturl.at canva.site notion.site web.app
    firebaseapp.com workers.dev pages.dev netlify.app vercel.app blob.core.windows.net s3.amazonaws.com
    firebasestorage.googleapis.com storage.googleapis.com github.io
""".split()
)
_USER_CONTENT_URL_PREFIXES = (
    ("docs.google.com", "/forms/"),
    ("sites.google.com", "/view/"),
    ("drive.google.com", "/uc"),
    ("onedrive.live.com", "/redir"),
)
_PHISHING_BRANDS = frozenset(
    "microsoft office365 onedrive sharepoint docusign paypal appleid adobe dropbox google".split()
)
_PHISHING_LURES = (
    "verify your account",
    "sign in to view",
    "download attachment",
    "docusign",
    "onedrive",
    "qr code",
    "shared a document",
    "reset your password",
    "click here to access",
    "review and sign",
    "view document securely",
    "confirm your identity",
    "account suspended",
    "xác minh tài khoản",
    "đăng nhập để xem",
    "đặt lại mật khẩu",
    "khôi phục tài khoản",
    "xác nhận mật khẩu",
    "tài khoản bị khóa",
    "tài khoản sẽ bị khóa",
    "nhấn vào đây để truy cập",
    "quét mã qr",
    "quet ma qr de",
    "scan qr code",
    "xac nhan danh tinh",
    "mở tài liệu bảo mật",
)


def _strip_diacritics(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text.replace("đ", "d").replace("Đ", "D"))
    return " ".join("".join(char for char in decomposed if unicodedata.category(char) != "Mn").lower().split())


_NORMALIZED_PHISHING_LURES = {phrase: _strip_diacritics(phrase) for phrase in _PHISHING_LURES}


def phishing_lure_phrases(text: str) -> set[str]:
    normalized = _strip_diacritics(text[:8192])
    return {phrase for phrase, needle in _NORMALIZED_PHISHING_LURES.items() if needle in normalized}


def _host_matches(host: str, domains: frozenset[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def _is_untrusted_host(host: str) -> bool:
    return _host_matches(host, _USER_CONTENT_OR_REDIRECT_HOSTS) or bool(
        host and host not in _KNOWN_AUTH_HOSTS and not _host_matches(host, _OFFICIAL_URI_DOMAINS)
    )


def _is_user_content_path(host: str, path: str) -> bool:
    path = unquote(path).lower()
    return any(host == domain and path.startswith(prefix) for domain, prefix in _USER_CONTENT_URL_PREFIXES)


def is_risky_remote_target(target: str) -> bool:
    normalized = unquote(target).strip().lower()
    return normalized.startswith(("\\\\", "//", "file:", "smb:")) or any(
        match.end() == len(normalized) for match in _URI_PAYLOAD.finditer(normalized)
    )


def is_untrusted_http_uri(uri: str) -> bool:
    try:
        parts = urlsplit(uri.strip())
        host = unquote(parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and (_is_untrusted_host(host) or _is_user_content_path(host, parts.path))


def is_suspicious_uri(uri: str, *, lure_phrases: set[str] | frozenset[str] = frozenset()) -> tuple[bool, list[str]]:
    normalized = uri.strip().replace("\t", "").replace("\r", "").replace("\n", "")
    scheme, separator, _ = normalized.partition(":")
    if separator and scheme.lower() in _DANGEROUS_URI_SCHEMES:
        return True, ["dangerous_scheme"]
    try:
        parts = urlsplit(normalized)
        host = unquote(parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False, []
    reasons = []
    if parts.scheme in ("http", "https") and "@" in unquote(parts.netloc):
        reasons.append("credential_at_spoofing")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            reasons.append("raw_ip_host")
    else:
        reasons.append("raw_ip_host")
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append("punycode_homograph")
    if _URI_PAYLOAD.search(unquote(parts.path + "?" + parts.query)):
        reasons.append("executable_payload_link")
    if host and host not in _KNOWN_AUTH_HOSTS and _URI_CREDENTIAL.search(host + "/" + unquote(parts.path).lower()):
        reasons.append("credential_phishing_endpoint")
    shared_host = next(
        (domain for domain in _USER_CONTENT_OR_REDIRECT_HOSTS if host == domain or host.endswith(f".{domain}")), ""
    )
    content_path = _is_user_content_path(host, parts.path)
    untrusted = shared_host or content_path or _is_untrusted_host(host)
    brand_host = host.removesuffix(shared_host).rstrip(".") if shared_host else "" if content_path else host
    if untrusted and any(brand in brand_host for brand in _PHISHING_BRANDS):
        reasons.append("brand_impersonation_host")
    if (
        len(lure_phrases) >= 2
        and parts.scheme in {"http", "https"}
        and (untrusted or _host_matches(host, _PHISHING_SHORTENERS))
    ):
        reasons.append("phishing_lure_context")
    return bool(reasons), reasons


def _is_benign_catalog_action(record: dict[str, Any]) -> bool:
    return not record.get("is_threat_trigger") and record.get("action_role") in _BENIGN_CATALOG_ACTION_ROLES


def _catalog_action_tokens_accounted_for(raw_tokens: dict[str, int], reconciled_ids: set[str]) -> bool:
    return all(
        (count := raw_tokens.get(token, 0)) == 0 or (count == 1 and evidence_id in reconciled_ids)
        for evidence_id, token in _CATALOG_ACTION_TOKENS.items()
    )


def _reconcile_semantic_verdict(
    ingest_data: dict[str, Any],
    logit: float,
    probability: float,
    threshold: float,
    temperature: float,
    is_v3: bool,
    counterfactual: Callable[[list[int], list[int], list[float]], float],
) -> tuple[float, float]:
    phishing = ingest_data["phishing_analysis"]["has_phishing_threat"]
    codec = bool(ingest_data["codec_anomalies"])
    non_js = set(ingest_data["non_js_triggers"])
    threat_non_js = non_js - _NON_THREAT_AUDIT_MARKERS
    hardening_reasons = non_js.intersection(
        {
            "/Launch",
            "/GoToR",
            "/FileAttachment",
            "/3D",
            "/U3D",
            "/PRC",
            "gotor_unc_ntlm_risk",
            "xfa_formcalc_network_call",
        }
    )
    if ingest_data.get("polyglot_analysis", {}).get("has_polyglot_payload"):
        hardening_reasons.add("polyglot_payload")
    if ingest_data.get("differential_analysis", {}).get("has_differential_evasion"):
        hardening_reasons.add("parser_differential")
    if phishing:
        hardening_reasons.add("phishing_uri")
    if codec:
        hardening_reasons.add("codec_anomaly")
    records = ingest_data["raw_records"]
    if any(record.get("action_type") == "/Launch" for record in records):
        hardening_reasons.add("/Launch")
    evasion_audit = ingest_data.get("evasion_unpack_audit") or {}
    if evasion_audit.get("hex_escaped_names_decoded") and evasion_audit.get("recovered_hidden_triggers"):
        hardening_reasons.add("hex_escaped_trigger_evasion")
    js = ingest_data["js_semantics"]
    raw_tokens = ingest_data["raw_tokens"]
    invalidate_incomplete_javascript_verification(ingest_data)
    has_non_js_threat = bool(
        threat_non_js
        or any(raw_tokens.get(key) for key in ("Launch", "EmbeddedFile", "XFA", "RichMedia"))
        or any(
            record["kind"] == "filespec"
            or record["evidence_id"] == "script:acroform_xfa"
            or record["action_type"] in {"/Launch", "/SubmitForm", "/ImportData", "/GoToE"}
            or record["stream_decode_failed"]
            or record["decompression_ratio_exceeded"]
            for record in records
        )
    )
    if probability < threshold and not hardening_reasons:
        if (ingest_data["pages_count"] > 10 or len(records) >= 40) and (
            has_non_js_threat
            or not js["is_verified_benign_js"]
            and (js["has_scripts"] or any(record["is_threat_trigger"] for record in records))
        ):
            padding = []
            for index, record in enumerate(records):
                if record["is_threat_trigger"]:
                    continue
                match = _PAGE_EVIDENCE_ID.fullmatch(record["evidence_id"])
                if match and int(match[1]) >= 2:
                    padding.append(index)
            if padding:
                core_logit = counterfactual(padding, [], [])
                core_prob = _calibrated_probability(core_logit, temperature)
                if core_prob >= threshold:
                    ingest_data["anti_padding_subgraph_reconciliation"] = {
                        "applied": True,
                        "diluted_prob": round(probability, 4),
                        "core_subgraph_prob": round(core_prob, 4),
                    }
                    return core_logit, core_prob
    hardening_reasons.update(_static_verdict_reasons(ingest_data))
    if hardening_reasons:
        if probability >= threshold:
            return logit, probability
        enforced = max(threshold, 0.885)
        ingest_data["semantic_verdict_enforcement"] = {
            "raw_prob": round(probability, 4),
            "enforced_prob": round(enforced, 4),
            "reasons": sorted(hardening_reasons),
        }
        return math.log(enforced / (1.0 - enforced)) * temperature, enforced
    if ingest_data.get("encryption_analysis", {}).get("password_locked") and probability >= threshold:
        uninspected_probability = threshold / 2
        ingest_data["semantic_verdict_enforcement"] = {
            "raw_prob": round(probability, 4),
            "enforced_prob": round(uninspected_probability, 4),
            "reasons": ["password_locked_structure_uninspected"],
        }
        return math.log(
            uninspected_probability / (1.0 - uninspected_probability)
        ) * temperature, uninspected_probability
    if has_non_js_threat:
        return logit, probability

    catalog_action_records = [
        (index, record) for index, record in enumerate(records) if record.get("evidence_id") in _CATALOG_ACTION_TOKENS
    ]
    benign_nav_indices = [index for index, record in catalog_action_records if _is_benign_catalog_action(record)]
    reconciled_ids = {records[index]["evidence_id"] for index in benign_nav_indices}
    if js["is_verified_benign_js"]:
        script_parents = {script["parent_id"] for script in ingest_data.get("extracted_scripts", ())}
        node_indices = [
            index
            for index, record in enumerate(records)
            if record["kind"] == "script"
            or record["action_type"] == "/JavaScript"
            or (record["evidence_id"] in script_parents and not _is_benign_catalog_action(record))
        ]
        if probability < threshold:
            for index in node_indices:
                records[index].update(is_threat_trigger=False, action_role="verified_benign_js")
            if probability <= _CLEAN_CALIBRATION_FLOOR:
                return logit, probability
        drop_indices = sorted(set(node_indices) | set(benign_nav_indices))
        if len(drop_indices) >= len(records):
            drop_indices = node_indices
        trigger_columns = TRIGGER_FEATURES_V3 if is_v3 else {"JS", "Javascript", "OpenAction", "AA"}
    else:
        if (
            js["has_scripts"]
            or ingest_data.get("extracted_scripts")
            or ingest_data.get("xfa_analysis", {}).get("present")
            or ingest_data.get("qr_analysis", {}).get("suspicious_uris")
            or ingest_data.get("signature_matches")
            or ingest_data.get("evasion_unpack_audit", {}).get("hex_escaped_names_decoded")
            or any(record.get("is_threat_trigger") for record in records)
            or len(benign_nav_indices) != len(catalog_action_records)
            or not 0 < len(benign_nav_indices) < len(records)
            or not _catalog_action_tokens_accounted_for(raw_tokens, reconciled_ids)
        ):
            return logit, probability
        if probability <= _CLEAN_CALIBRATION_FLOOR:
            ingest_data["navigation_semantic_calibration"] = {
                "applied": True,
                "raw_prob": round(probability, 4),
                "calibrated_prob": round(probability, 4),
                "reconciled_nodes": sorted(reconciled_ids),
                "reason": "benign_catalog_navigation_verified",
            }
            return logit, probability
        drop_indices = benign_nav_indices
        prefix = "lexical_" if is_v3 else ""
        trigger_columns = {prefix + _CATALOG_ACTION_TOKENS[evidence_id] for evidence_id in reconciled_ids}
    if len(drop_indices) >= len(records):
        return logit, probability
    if is_v3:
        names = ingest_data["v3_feature_names"]
        center, scale = ingest_data["v3_scaler_center"], ingest_data["v3_scaler_scale"]
    else:
        names = ingest_data["feature_names"]
        center, scale = ingest_data["scaler_mean"], ingest_data["scaler_scale"]
    column_indices = [index for index, name in enumerate(names) if name in trigger_columns]
    baselines = [-center[index] / scale[index] for index in column_indices]
    cf_logit = counterfactual(drop_indices, column_indices, baselines)
    cf_prob = _calibrated_probability(cf_logit, temperature)
    if cf_prob >= min(threshold, probability):
        return logit, probability
    calibration = {
        "applied": True,
        "raw_prob": round(probability, 4),
        "calibrated_prob": round(cf_prob, 4),
    }
    if js["is_verified_benign_js"]:
        for index in node_indices:
            records[index].update(is_threat_trigger=False, action_role="verified_benign_js")
        ingest_data["ast_semantic_calibration"] = {**calibration, "reason": "verified_benign_js_counterfactual"}
    else:
        ingest_data["navigation_semantic_calibration"] = {
            **calibration,
            "reconciled_nodes": sorted(reconciled_ids),
            "reason": "benign_catalog_navigation_counterfactual",
        }
    return cf_logit, cf_prob


def _static_verdict_reasons(ingest_data: dict[str, Any]) -> set[str]:
    js = ingest_data["js_semantics"]
    reasons = {match["id"] for match in ingest_data.get("signature_matches", ()) if match["severity"] == "critical"}
    if js["malicious_indicator_count"]:
        reasons.add("javascript_malicious_indicators")
    if js.get("flow_suspicious_urls"):
        reasons.add("javascript_flow_suspicious_uri")
    if ingest_data.get("threat_intel", {}).get("hit"):
        reasons.add("offline_threat_intel")
    return reasons


_PAGE_EVIDENCE_ID = re.compile(r"(?:page:|stream:page_|annotation:|action:annot_)(\d+)(?:_\d+)?")


def _calibrated_probability(logit: float, temperature: float) -> float:
    return math.exp(-float(np.logaddexp(0.0, -logit / temperature)))


def classify_prediction_confidence(prob: float, threshold: float, is_ood: bool) -> str:
    if is_ood or not math.isfinite(prob):
        return "LOW"
    if prob >= threshold:
        if prob >= max(0.85, threshold + 0.35):
            return "HIGH"
        return "MEDIUM" if prob >= max(0.50, threshold + 0.15) else "LOW"
    if prob <= min(0.15, threshold * 0.35):
        return "HIGH"
    return "MEDIUM" if prob <= min(0.30, threshold * 0.70) else "LOW"


def semantic_graph_selection(
    node_count: int,
    edge_index: np.ndarray,
    script_nodes: list[int],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    retained_nodes = np.ones(node_count, dtype=bool)
    retained_nodes[script_nodes] = False
    retained_edges = retained_nodes[edge_index].all(axis=0)
    new_indices = np.cumsum(retained_nodes, dtype=np.int64) - 1
    return retained_nodes, retained_edges, new_indices[edge_index[:, retained_edges]]


def reconcile_taxonomy_observations(
    observations: dict[str, str | None],
    ingest_data: dict[str, Any],
    verdict: str,
) -> set[str]:
    suppressed = set()
    triggers = set(ingest_data.get("non_js_triggers", ()))
    threat_triggers_set = triggers - _NON_THREAT_AUDIT_MARKERS
    password_locked = ingest_data.get("encryption_analysis", {}).get("password_locked")
    js_semantics = ingest_data.get("js_semantics", {})
    evasion_audit = ingest_data.get("evasion_unpack_audit", {})
    verified_benign_js = bool(js_semantics.get("is_verified_benign_js")) and not evasion_audit.get(
        "hex_escaped_names_decoded"
    )
    if verdict == "BENIGN" and not threat_triggers_set and not password_locked and verified_benign_js:
        suppressed = {"js_script_exec", "auto_open_trigger", "obfuscated_payload", "buffer_loop_staging"}
        for label in suppressed:
            observations[label] = None
    phishing = ingest_data.get("phishing_analysis", {})
    if phishing.get("has_phishing_threat"):
        urls = phishing.get("suspicious_uris", [])
        reasons = sorted({reason for url in urls for reason in url["reasons"]})
        observations["suspicious_uri_redirect"] = f"Ghi nhận {len(urls)} URL đáng ngờ ({', '.join(reasons)})."
    if "/GoToR" in triggers:
        redirect = "Ghi nhận hành động mở tài liệu từ xa (/GoToR)."
        observations["suspicious_uri_redirect"] = " ".join(
            filter(None, (observations.get("suspicious_uri_redirect"), redirect))
        )
    if "/FileAttachment" in triggers:
        attachment = "Ghi nhận chú thích đính kèm tệp (/FileAttachment)."
        observations["embedded_dropper_or_launch"] = " ".join(
            filter(None, (observations.get("embedded_dropper_or_launch"), attachment))
        )
    codec_reasons = sorted(
        {f"{item['codec']}: {', '.join(item['reason_codes'])}" for item in ingest_data.get("codec_anomalies", [])}
    )
    effective_recovered = list(evasion_audit.get("recovered_hidden_triggers", []))
    records = ingest_data.get("raw_records") or []
    raw_tokens = ingest_data.get("raw_tokens") or {}
    audit = ingest_data.get("structural_audit") or {}
    stream_interior = audit.get("stream_interior_tokens") or {}

    def effective_tok(name: str) -> int:
        return max(0, int(raw_tokens.get(name, 0)) - int(stream_interior.get(name, 0)))

    scripts = ingest_data.get("extracted_scripts") or []
    catalog_actions = [record for record in records if record.get("evidence_id") in _CATALOG_ACTION_TOKENS]
    benign_catalog_ids = {record["evidence_id"] for record in catalog_actions if _is_benign_catalog_action(record)}
    if (
        "OpenAction" in effective_recovered
        and not evasion_audit.get("hex_escaped_names_decoded")
        and raw_tokens.get("OpenAction", 0) <= 1
        and "action:open_action" in benign_catalog_ids
    ):
        effective_recovered.remove("OpenAction")
    if verdict == "BENIGN" and verified_benign_js and not threat_triggers_set:
        effective_recovered = [
            token for token in effective_recovered if token not in {"JS", "JavaScript", "AA", "OpenAction", "AcroForm"}
        ]
    structural = observations.get("structural_parser_evasion")
    details = [structural] if structural else []
    differential = ingest_data.get("differential_analysis", {})
    if differential.get("has_differential_evasion"):
        details.append("Bất thường giữa các bộ phân tích PDF (" + ", ".join(differential["anomalies"]) + ").")
    if codec_reasons:
        details.append("Bất thường khi kiểm tra luồng (" + ", ".join(codec_reasons) + ").")
    xfa_anomalies = ingest_data.get("xfa_analysis", {}).get("anomalies", [])
    if xfa_anomalies:
        details.append("Bất thường khi kiểm tra XFA (" + ", ".join(xfa_anomalies) + ").")
    polyglot = ingest_data.get("polyglot_analysis") or {}
    if polyglot.get("has_polyglot_payload"):
        details.append("Phát hiện định dạng nhúng ngoài phần PDF (" + ", ".join(polyglot["anomalies"]) + ").")
    media = triggers.intersection({"/3D", "/U3D", "/PRC"})
    if media:
        details.append("Ghi nhận cấu trúc 3D (" + ", ".join(sorted(media)) + ").")
    if effective_recovered and verdict == "MALICIOUS":
        details.append("Tên PDF khôi phục (" + ", ".join("/" + name for name in effective_recovered) + ").")
    observations["structural_parser_evasion"] = " ".join(details) or None

    qr = ingest_data.get("qr_analysis", {})
    if (
        verdict != "BENIGN"
        or not records
        or not raw_tokens
        or not ingest_data.get("graph_present", True)
        or password_locked
        or threat_triggers_set
        or (triggers and not verified_benign_js)
        or ingest_data.get("codec_anomalies")
        or phishing.get("has_phishing_threat")
        or qr.get("has_qr_threat")
        or qr.get("suspicious_uris")
        or differential.get("has_differential_evasion")
        or polyglot.get("has_polyglot_payload")
        or xfa_anomalies
        or ingest_data.get("threat_intel", {}).get("hit")
        or ingest_data.get("signature_matches")
        or js_semantics.get("malicious_indicator_count")
        or any(record.get("is_threat_trigger") for record in records)
    ):
        return suppressed

    no_js = (
        not scripts
        and effective_tok("JS") == effective_tok("JavaScript") == 0
        and not any(record.get("kind") == "script" for record in records)
    )
    no_xfa = (
        not ingest_data.get("xfa_analysis", {}).get("present")
        and not effective_tok("XFA")
        and not any(record.get("evidence_id") == "script:acroform_xfa" for record in records)
    )
    no_dropper = effective_tok("Launch") == effective_tok("EmbeddedFile") == 0 and not any(
        record.get("kind") == "filespec" or record.get("action_type") == "/Launch" for record in records
    )
    verified_form_only = verified_benign_js and no_xfa and no_dropper and not effective_recovered
    disproven = {
        "js_script_exec": no_js,
        "obfuscated_payload": no_js,
        "buffer_loop_staging": no_js,
        "auto_open_trigger": not scripts
        and all(_is_benign_catalog_action(record) for record in catalog_actions)
        and effective_tok("OpenAction")
        <= max(int("action:open_action" in benign_catalog_ids), int(audit.get("inspected_benign_openaction_tokens", 0)))
        and effective_tok("AA")
        <= max(int("action:aa" in benign_catalog_ids), int(audit.get("inspected_benign_aa_tokens", 0))),
        "active_form_or_exploit": verified_form_only
        or (
            not scripts
            and no_xfa
            and effective_tok("AcroForm") + effective_tok("Acroform") <= int(audit.get("inspected_acroform_tokens", 0))
        ),
        "embedded_dropper_or_launch": verified_form_only or (not scripts and no_dropper),
        "suspicious_uri_redirect": not phishing.get("suspicious_uris")
        and not any(record.get("action_type") in {"/SubmitForm", "/GoToR"} for record in records)
        and max(len(ingest_data.get("extracted_uris", ())), int(ingest_data.get("inspected_uri_tokens", 0)))
        >= effective_tok("URI"),
        "structural_parser_evasion": not evasion_audit.get("hex_escaped_names_decoded")
        and not effective_recovered
        and not any(
            record.get("stream_decode_failed") or record.get("decompression_ratio_exceeded") for record in records
        )
        and effective_tok("obj") == raw_tokens.get("endobj", 0)
        and effective_tok("stream") == raw_tokens.get("endstream", 0),
    }
    suppressed.update(head for head, disproved in disproven.items() if disproved and observations.get(head) is None)
    return suppressed


_JS_QUOTED = r"""(?:"(?:[^"\\\r\n]|\\[^\r\n])*"|'(?:[^'\\\r\n]|\\[^\r\n])*')"""
_JS_ATOB = re.compile(r"""\batob\s*\(\s*(['"])([A-Za-z0-9+/]*={0,2})\1\s*\)""")
_JS_UNESCAPE = re.compile(rf"\b(?:unescape|decodeURIComponent)\s*\(\s*({_JS_QUOTED})\s*\)")
_JS_JOIN = re.compile(
    rf"\[\s*(?:(?P<items>{_JS_QUOTED}(?:\s*,\s*{_JS_QUOTED}){{0,255}})\s*)?\]"
    rf"\s*\.\s*join\s*\(\s*(?P<separator>{_JS_QUOTED})\s*\)"
)
_JS_REVERSE = re.compile(
    rf"(?P<value>{_JS_QUOTED})\s*\.\s*split\s*\(\s*(['\"])\2\s*\)"
    r"\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(['\"])\3\s*\)"
)
_JS_CONCAT = re.compile(rf"({_JS_QUOTED})\s*\+\s*({_JS_QUOTED})")


def _decode_js_base64(body: str) -> str | None:
    padded = body + "=" * (-len(body) % 4) if "=" not in body else body
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if base64.b64encode(decoded.encode("utf-8")).decode("ascii") != padded:
        return None
    return decoded if all(char.isprintable() or char in "\t\r\n" for char in decoded) else None


def _js_literal_text(literal: str) -> str:
    if "\\" not in literal:
        return literal[1:-1]
    return esprima.parseScript(literal).body[0].expression.value


def deobfuscate_javascript_static(code: str) -> dict[str, Any]:
    transformed = code
    techniques: list[str] = []

    def mark(technique: str) -> None:
        if technique not in techniques:
            techniques.append(technique)

    def quoted(match: re.Match[str], value: str | None, technique: str) -> str:
        if value is None:
            return match.group()
        mark(technique)
        return json.dumps(value, ensure_ascii=False).replace("\u2028", r"\u2028").replace("\u2029", r"\u2029")

    def from_char_code(match: re.Match[str]) -> str:
        tokens = match[1].split(",")
        if len(tokens) > 2048:
            return match.group()
        try:
            chars = "".join(
                chr(int(token, 16 if token.strip().lower().startswith("0x") else 10) % 65536) for token in tokens
            )
        except ValueError:
            return match.group()
        return quoted(match, chars, "fromCharCode_decode")

    def unescape(match: re.Match[str]) -> str:
        try:
            inner = _js_literal_text(match[1])
        except esprima.Error:
            return match.group()
        decoded = re.sub(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})", lambda m: chr(int(m[1] or m[2], 16)), inner)
        return quoted(match, decoded, "unescape_percent_decode") if decoded != inner else match.group()

    def escape(match: re.Match[str]) -> str:
        kind = match[1] or match[3]
        value = int(match[2] or match[4], 16)
        if 32 <= value <= 126 or kind == "u" and value >= 160 or kind == "x" and value in (9, 10, 13):
            mark("hex_escape_decode" if kind == "x" else "unicode_escape_decode")
            return chr(value)
        return match.group()

    def join(match: re.Match[str]) -> str:
        try:
            parts = tuple(_js_literal_text(item.group()) for item in re.finditer(_JS_QUOTED, match["items"] or ""))
            separator = _js_literal_text(match["separator"])
        except esprima.Error:
            return match.group()
        return quoted(match, _js_join(parts, separator), "array_join_fold")

    def reverse(match: re.Match[str]) -> str:
        try:
            value = _js_literal_text(match["value"])
        except esprima.Error:
            return match.group()
        return quoted(match, value[::-1] if all(ord(char) <= 0xFFFF for char in value) else None, "string_reverse_fold")

    def concat(match: re.Match[str]) -> str:
        try:
            value = _js_literal_text(match[1]) + _js_literal_text(match[2])
        except esprima.Error:
            return match.group()
        return quoted(match, value, "string_concat_fold")

    if code and len(code) <= _MAX_JS_BYTES and len(code.encode("utf-8", errors="surrogatepass")) <= _MAX_JS_BYTES:
        for _ in range(3):
            previous = transformed
            transformed = re.sub(r"\bString\s*\.\s*fromCharCode\s*\(([0-9a-fA-FxX,\s]+)\)", from_char_code, transformed)
            transformed = _JS_UNESCAPE.sub(unescape, transformed)
            transformed = re.sub(r"\\(x)([0-9a-fA-F]{2})|\\(u)([0-9a-fA-F]{4})", escape, transformed)
            transformed = _JS_ATOB.sub(lambda m: quoted(m, _decode_js_base64(m[2]), "base64_atob_decode"), transformed)
            transformed = _JS_JOIN.sub(join, transformed)
            transformed = _JS_REVERSE.sub(reverse, transformed)
            transformed = _JS_CONCAT.sub(concat, transformed)
            if len(transformed.encode("utf-8", errors="surrogatepass")) > _MAX_JS_BYTES:
                transformed = previous
                break
            if transformed == previous:
                break

    return {
        "deobfuscated_code": transformed,
        "deobfuscation_applied": transformed != code,
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
                severity = (
                    "critical"
                    if pat_id in ("eval_exec", "unescape_decode", "heap_spray_pattern", "util_printf_overflow")
                    else "warning"
                )
                break
        if not tag and re.search(r"\b(?:for|while)\s*\(", line):
            tag = "Vòng lặp điều khiển"
            severity = "secondary"
        annotated.append(
            {
                "line_no": idx,
                "code": line,
                "tag": tag,
                "severity": severity,
            }
        )
    return annotated


class ForensicAttributionEngine:
    def __init__(self) -> None:
        pass

    def explain(
        self,
        ingest_data: dict[str, Any],
        cross_modal_attn: Any = None,
        malware_prob: float | None = None,
        node_saliency: list[float | None] | None = None,
        edge_attention: list[float] | None = None,
        ast_token_attention: list[float] | None = None,
        tabular_grad_importance: list[float | None] | None = None,
        xai_proof_metrics: dict[str, float] | None = None,
        saliency_method: str = "gradient_input",
    ) -> dict[str, Any]:
        cross_weights = None
        if cross_modal_attn is not None:
            weights = (
                cross_modal_attn.detach().cpu().numpy()
                if hasattr(cross_modal_attn, "detach")
                else np.asarray(cross_modal_attn)
            )
            weights = weights.squeeze()
            if weights.ndim == 1 and len(weights) == 2:
                cross_weights = {"graph_weight": round(float(weights[0]), 4), "ast_weight": round(float(weights[1]), 4)}
            elif weights.ndim == 1 and len(weights) == 3:
                cross_weights = {
                    "tabular_weight": round(float(weights[0]), 4),
                    "graph_weight": round(float(weights[1]), 4),
                    "ast_weight": round(float(weights[2]), 4),
                }

        from malpdf.scanner.ingestion import AST_NODE_TYPES

        records = ingest_data.get("raw_records", [])
        v3_evidence = cross_weights is not None and "tabular_weight" in cross_weights
        scripts = ingest_data.get("extracted_scripts", [])
        js_semantics = ingest_data.get("js_semantics", {})
        script_intents = js_semantics.get("per_script_intents", [])
        stats = ingest_data.get("ast_stats") or {}
        counts = ingest_data.get("ast_node_counts") or {}
        triggers = []
        for index, record in enumerate(records):
            if record.get("is_threat_trigger") or record.get("kind") in ("action", "script", "filespec"):
                triggers.append(
                    {
                        "object_id": record.get("evidence_id"),
                        "obj_ref_str": record.get("obj_ref_str"),
                        "kind": record.get("kind"),
                        "invoker": record.get("invoker"),
                        "filter": record.get("filter"),
                        **record.get("byte_measurements", {"size_bytes": None, "entropy": None}),
                        "action_role": record.get("action_role"),
                        "has_stream": record.get("has_stream"),
                        "is_threat_trigger": bool(record.get("is_threat_trigger")),
                        "xai_saliency": node_saliency[index] if node_saliency and index < len(node_saliency) else None,
                    }
                )
        triggers.sort(
            key=lambda item: (
                1 if item.get("is_threat_trigger") else 0,
                1 if item.get("object_id") in ("script:action:open_action", "action:open_action") else 0,
                float(item.get("xai_saliency") or 0.0),
            ),
            reverse=True,
        )

        threat_scripts = []
        for index, script in enumerate(scripts):
            code = script.get("code", "")
            intent = script_intents[index] if index < len(script_intents) else {}
            verified = bool(intent.get("is_verified_benign"))
            deobf = deobfuscate_javascript_static(code)
            deobf_code = deobf["deobfuscated_code"]
            combined_scan_text = code + ("\n" + deobf_code if deobf["deobfuscation_applied"] else "")
            matches = [
                (tag, label)
                for tag, pattern, label in DANGEROUS_PATTERNS
                if not verified and re.search(pattern, combined_scan_text, re.IGNORECASE)
            ]
            descriptions = dict(matches)
            indicators = list(dict.fromkeys([*descriptions, *intent.get("dangerous_indicators", ())]))
            raw_snippet = re.sub(r"\s+", " ", code).strip()[:180]
            deobf_snippet = re.sub(r"\s+", " ", deobf_code).strip()[:180]
            show_deobfuscated = deobf["deobfuscation_applied"] and not verified
            display_snippet = (
                f"[DEOBFUSCATED ({', '.join(deobf['deobfuscation_techniques'])})]: {deobf_snippet}\n[RAW]: {raw_snippet}"
                if show_deobfuscated
                else raw_snippet
            )
            threat_scripts.append(
                {
                    "script_id": script.get("script_id"),
                    "parent_id": script.get("parent_id"),
                    "entropy": round(_shannon_entropy_str(code), 4),
                    "length_chars": len(code),
                    "is_verified_benign": verified,
                    "intent_codes": intent.get("intent_codes", []),
                    "intent_label_vi": intent.get("intent_label_vi", ""),
                    "dangerous_indicators": indicators,
                    "indicator_descriptions": [descriptions.get(tag, tag) for tag in indicators],
                    "snippet": raw_snippet,
                    "code_snippet": display_snippet,
                    "raw_code_snippet": raw_snippet,
                    "deobfuscated_code": deobf_code,
                    "deobfuscation_applied": show_deobfuscated,
                    "deobfuscation_techniques": deobf["deobfuscation_techniques"],
                    "full_code": code,
                    "annotated_lines": _annotate_code_lines(deobf_code if show_deobfuscated else code),
                }
            )

        adjacency: dict[str | None, list[str | None]] = {}
        for edge in ingest_data.get("raw_edges", []):
            adjacency.setdefault(edge.get("source"), []).append(edge.get("target"))
        record_map = {record["evidence_id"]: record for record in records if record.get("evidence_id")}
        root = "catalog:root" if "catalog:root" in record_map else None
        script_parents = {s.get("parent_id") for s in scripts if s.get("parent_id")}
        threat_triggers = [
            t
            for t in triggers
            if t.get("action_role") != "verified_benign_js"
            and (
                t.get("is_threat_trigger")
                or t.get("kind") in ("script", "filespec")
                or t.get("object_id") in script_parents
            )
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
                    ast_attributions.append(
                        {
                            "token_type": node_type,
                            "count": counts.get(node_type),
                            "raw_attention": attention,
                            "normalized_pct": attention * 100.0,
                            "attention_weight": round(attention, 4),
                        }
                    )
            ast_attributions.sort(key=lambda value: value["raw_attention"], reverse=True)

        tabular_attributions = []
        names = ingest_data.get("feature_names", [])
        raw_values = ingest_data.get("raw_feature_vec", [])
        means = ingest_data.get("scaler_mean", [])
        tab = ingest_data.get("tab_features")
        v3_names = ingest_data.get("v3_feature_names", [])
        use_v3_features = bool(v3_names) and (
            len(tabular_grad_importance or []) == len(v3_names) or (v3_evidence and tabular_grad_importance is None)
        )
        if use_v3_features:
            names = v3_names
            raw_values = ingest_data.get("v3_raw_feature_vec", [])
            means = ingest_data.get("v3_scaler_center", [])
            tab = ingest_data.get("v3_tab_features")
        if tabular_grad_importance and len(tabular_grad_importance) == len(names):
            if hasattr(tab, "detach"):
                scores = tab.squeeze(0).detach().cpu().tolist()
            elif isinstance(tab, np.ndarray):
                scores = tab.reshape(-1).tolist()
            else:
                scores = []
            total = sum(abs(value) for value in tabular_grad_importance if value is not None)
            for index, name in enumerate(names):
                value = tabular_grad_importance[index]
                if value is None:
                    continue
                tabular_attributions.append(
                    {
                        "feature_name": name,
                        "raw_value": raw_values[index] if index < len(raw_values) else None,
                        "z_score": scores[index] if index < len(scores) else None,
                        "train_mean": means[index] if index < len(means) else None,
                        "attribution_score": value,
                        "impact_pct": abs(value) / total * 100.0 if total else 0.0,
                        "direction": "threat" if value > 0 else "benign" if value < 0 else "neutral",
                    }
                )
            tabular_attributions.sort(key=lambda item: abs(item["attribution_score"]), reverse=True)

        proof = xai_proof_metrics or {}
        xai_metrics = {
            key: proof.get(key)
            for key in ("fidelity_score", "comprehensiveness_drop", "sparsity_index", "lipschitz_stability")
        }
        xai_metrics.update(
            {
                "sparsity_scope": "evaluated_inputs" if proof.get("sparsity_index") is not None else None,
                "dag_entropy": ingest_data.get("raw_entropy"),
                "ast_complexity": stats.get("total_nodes"),
                "ast_max_depth": stats.get("max_depth"),
                "ast_loops": stats.get("loops"),
                "primary_disarm_target": triggers[0].get("obj_ref_str") if triggers else None,
            }
        )

        cross_matrix: list[dict[str, Any]] = []
        measured_indices = [index for index, value in enumerate(node_saliency or []) if value is not None]
        has_measured_saliency = bool(measured_indices)
        if records and has_measured_saliency:
            ranked_indices = sorted(
                (index for index in measured_indices if index < len(records)),
                key=lambda idx: (
                    1 if records[idx].get("is_threat_trigger") else 0,
                    float(node_saliency[idx]),
                ),
                reverse=True,
            )
            active_ast = [a for a in ast_attributions if (a.get("count") or 0) > 0] if not v3_evidence else []
            top_tabs = tabular_attributions[:6]
            for rank_pos, idx in enumerate(ranked_indices[:6]):
                rec = records[idx]
                eid = str(rec.get("evidence_id", f"node:{idx}"))
                sal = float(node_saliency[idx])
                is_trig = bool(rec.get("is_threat_trigger"))
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
                cross_matrix.append(
                    {
                        "node_id": eid,
                        "source_obj_ref": rec.get("obj_ref_str") or eid,
                        "source_role": f"{str(rec.get('kind', 'object')).capitalize()} ({rec.get('invoker', '/Root')})",
                        "target_token": target_tok,
                        "attention_score": round(float(score), 4),
                        "impact_tier": tier,
                    }
                )

        if triggers:
            observations = []
            for index, trigger in enumerate(triggers):
                sal_val = trigger.get("xai_saliency")
                sal_str = (
                    f"Mức liên quan: {sal_val * 100:.1f}%"
                    if isinstance(sal_val, (int, float))
                    else "Chưa đo mức ảnh hưởng"
                )
                inv = str(trigger.get("invoker") or "/Root")
                knd = str(trigger.get("kind") or "action")
                action_role = trigger.get("action_role")
                is_crit = action_role != "verified_benign_js" and (
                    bool(trigger.get("is_threat_trigger")) or knd in ("script", "filespec")
                )
                observations.append(
                    {
                        "stage_num": index + 1,
                        "title": f"Điểm kiểm tra {index + 1}: {inv} ({trigger.get('obj_ref_str') or trigger.get('object_id')})",
                        "object_ref": trigger.get("obj_ref_str"),
                        "node_id": trigger.get("object_id"),
                        "risk_score": sal_str if is_crit else "Cấu trúc PDF",
                        "severity": "critical" if is_crit else "normal",
                        "description": _describe_trigger_cascade(inv, knd, action_role, is_crit),
                        "tags": ["Dấu hiệu tĩnh" if is_crit else "Cấu trúc PDF", inv],
                    }
                )
        else:
            observations = []

        return {
            **{
                name: ingest_data[name]
                for name in (
                    "js_semantics",
                    "encryption_analysis",
                    "signature_matches",
                    "threat_intel",
                    "phishing_analysis",
                    "qr_analysis",
                    "differential_analysis",
                    "codec_anomalies",
                    "xfa_analysis",
                    "polyglot_analysis",
                    "non_js_triggers",
                    "evasion_unpack_audit",
                    "ast_semantic_calibration",
                    "navigation_semantic_calibration",
                    "semantic_verdict_enforcement",
                    "anti_padding_subgraph_reconciliation",
                    "graph_byte_source",
                )
                if name in ingest_data
            },
            "cross_modal_weights": cross_weights,
            "modality_breakdown": {
                "graph_pct": proof.get("graph_branch_pct"),
                "ast_pct": proof.get("ast_branch_pct"),
                "tabular_pct": proof.get("tabular_branch_pct"),
            },
            "trigger_objects": triggers,
            "threat_scripts": threat_scripts,
            "ast_token_attributions": ast_attributions[:10],
            "ast_token_importance": ast_attributions[:10],
            "ast_token_attribution_source": ("observed_node_frequency" if v3_evidence else "model_attention")
            if ast_attributions
            else None,
            "tabular_attributions": tabular_attributions if use_v3_features else tabular_attributions[:10],
            "tabular_anomalies": tabular_attributions[:10],
            "cross_attention_matrix": cross_matrix,
            "cross_attention_matrix_status": (
                "measured_occlusion_saliency" if saliency_method == "occlusion" else "measured_gradient_saliency"
            )
            if has_measured_saliency
            else "unavailable",
            "xai_method": saliency_method if has_measured_saliency else None,
            "xai_coverage": {
                "nodes_total": len(records),
                "nodes_measured": len(measured_indices),
                "tabular_features_total": len(names),
                "tabular_features_measured": sum(value is not None for value in (tabular_grad_importance or [])),
            },
            "mitre_cascade": observations,
            "xai_metrics": xai_metrics,
            "thesis_synthesis": {
                "headline": (
                    f"Điểm mô hình: {malware_prob:.2%}" if malware_prob is not None else "Chưa có kết luận tự động"
                ),
                "summary_vi": (
                    f"Đã kiểm tra {len(records)} đối tượng trong tệp, ghi nhận {len(threat_triggers)} thành phần kích hoạt và {len(scripts)} đoạn JavaScript."
                ),
                "proof_statement": "Đối chiếu từ cấu trúc nhị phân và chỉ số trích xuất của chính tệp đang kiểm tra.",
            },
            "attack_path": attack_path,
            "attack_path_kind": "observed_active_object"
            if threat_triggers and path_ids[-1:] == [goal]
            else "document_structure",
            "attack_path_string": " -> ".join(attack_path),
            "attack_path_status": "observed" if path_ids and path_ids[-1] == goal else "unreachable_in_observed_graph",
            "suspicious_object_count": len(threat_triggers),
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

        fig, (ax_graph, ax_attn) = plt.subplots(
            1, 2, figsize=(10, 3.5), dpi=300, gridspec_kw={"width_ratios": [2.5, 1.2]}
        )

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
            ax_graph.text(
                x, y + 0.12, main_text, ha="center", va="center", fontsize=9, fontweight="bold", color="white"
            )
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
        if "tabular_weight" in cross_modal_weights:
            labels.insert(0, "Tabular")
            weights.insert(0, cross_modal_weights["tabular_weight"])
            bar_colors.insert(0, "#2ca02c")
        bars = ax_attn.bar(labels, weights, color=bar_colors, width=0.45, edgecolor="#222222")
        ax_attn.set_ylim(0, 1.05)
        ax_attn.set_ylabel("Attention Weight", fontsize=9, fontweight="bold")
        score_label = f"P={malware_prob:.2%}" if malware_prob is not None else "P unavailable"
        ax_attn.set_title(f"Cross-Attention ({score_label})", fontsize=10, fontweight="bold")
        for bar in bars:
            yval = bar.get_height()
            ax_attn.text(
                bar.get_x() + bar.get_width() / 2.0,
                yval + 0.02,
                f"{yval:.2f}",
                ha="center",
                va="bottom",
                fontsize=8,
                fontweight="bold",
            )

        plt.tight_layout()
        fig.savefig(out, bbox_inches="tight")
        plt.close(fig)
        return out
