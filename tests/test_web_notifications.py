from __future__ import annotations

from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "src/malpdf/web/templates/index.html"
STATIC_DIR = REPO_ROOT / "src/malpdf/web/static"


class DocumentAttributes(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_attributes: dict[str, str | None] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "html":
            self.html_attributes = dict(attrs)


def _inline_core_module() -> str:
    source = (STATIC_DIR / "dashboard-core.js").read_text(encoding="utf-8")
    return re.sub(r"^export\s+", "", source, flags=re.MULTILINE)


def test_browser_template_contains_no_provider_credentials() -> None:
    template_source = TEMPLATE_PATH.read_text(encoding="utf-8")
    assert re.search(r"\bon(?:click|change|keydown|keyup|input|submit|focus|blur)\s*=", template_source) is None
    for path in [TEMPLATE_PATH, *sorted(STATIC_DIR.glob("dashboard*"))]:
        source = path.read_text(encoding="utf-8")
        contains_key_literal = re.search(r"\b(?:sk-(?:proj-)?|hf_)[A-Za-z0-9_-]{20,}", source) is not None
        assert contains_key_literal is False, f"Credential literal found in {path.name}"
        assert "VILAO_API_CONFIG.apiKey" not in source
        assert "fonts.googleapis.com" not in source
        assert "fonts.gstatic.com" not in source
        assert "cdn.jsdelivr.net/npm/marked" not in source


def _browser_attributes(tmp_path: Path, page: str) -> dict[str, str | None]:
    candidates = [
        os.environ.get("MALPDF_TEST_BROWSER"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    browser = next((str(path) for path in candidates if path and Path(path).is_file()), None)
    assert browser is not None, "Chrome/Chromium is required; set MALPDF_TEST_BROWSER to its executable"
    target = tmp_path / "notification.html"
    target.write_text(page, encoding="utf-8")
    result = subprocess.run(
        [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--disable-background-networking",
            "--no-first-run",
            f"--user-data-dir={tmp_path / 'browser-profile'}",
            "--dump-dom",
            "--timeout=10000",
            "--virtual-time-budget=1000",
            target.as_uri(),
        ],
        capture_output=True,
        timeout=30,
        check=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    dom = DocumentAttributes()
    dom.feed(result.stdout.decode("utf-8", errors="replace"))
    return dom.html_attributes


def test_notification_displays_untrusted_subject_as_text_in_real_browser(tmp_path: Path) -> None:
    payload = "<svg onload=\"document.documentElement.setAttribute('data-review-xss','executed')\"></svg>"
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body><div id="toast-container"></div><script>\n'
        + _inline_core_module()
        + "\nconst subject = "
        + json.dumps(payload)
        + ";\nshowToast(subject, 'success', 300000);"
        + "\ndocument.documentElement.setAttribute('data-review-literal-message',"
        + "String(document.getElementById('toast-container').textContent.includes(subject)));"
        + "\n</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    assert "data-review-xss" not in attributes
    assert attributes.get("data-review-literal-message") == "true"


def test_held_email_is_not_labeled_safe_or_offered_as_clean_download(tmp_path: Path) -> None:
    ids = [
        "mail-tab-result-card",
        "mail-tab-res-subject",
        "mail-tab-res-sender",
        "mail-tab-res-attachments",
        "mail-tab-res-threats",
        "mail-tab-action-badge",
    ]
    markup = "".join(f'<div id="{name}"></div>' for name in ids) + '<a id="btn-mail-tab-download-eml"></a>'
    data = {
        "subject": "Needs review",
        "total_attachments": 1,
        "malicious_attachments": 0,
        "unavailable_attachments": 1,
        "action_taken": "HELD_FOR_REVIEW",
        "eml_job_id": "held-email",
    }
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body>'
        + markup
        + "<script>\n"
        + _inline_core_module()
        + "\nrenderEMLInspectionResult("
        + json.dumps(data)
        + ");"
        + "document.documentElement.setAttribute('data-review-badge',document.getElementById('mail-tab-action-badge').innerText);"
        + "document.documentElement.setAttribute('data-review-download-hidden',String(document.getElementById('btn-mail-tab-download-eml').classList.contains('hidden')));"
        + "</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    assert attributes.get("data-review-badge") == "Cần kiểm tra thêm"
    assert attributes.get("data-review-download-hidden") == "true"


def test_scan_guidance_distinguishes_warnings_and_unresolved_results(tmp_path: Path) -> None:
    benign = {
        "verdict": "BENIGN",
        "prediction_available": True,
        "is_ood": False,
        "threat_taxonomy": {"ml_label_predictions": [{"evidence_status": "not_observed"}]},
    }
    observed = {"ml_label_predictions": [{"evidence_status": "observed"}]}
    cases = [
        (benign, "Không tìm thấy dấu hiệu nguy hiểm", "Đã kiểm tra cấu trúc PDF"),
        ({**benign, "is_ood": True}, "Cần lưu ý trước khi mở tệp", "Tạm thời đừng mở bản gốc"),
        ({**benign, "is_ood": None}, "Cần lưu ý trước khi mở tệp", "Tạm thời đừng mở bản gốc"),
        ({**benign, "prediction_available": False}, "Cần lưu ý trước khi mở tệp", "Tạm thời đừng mở bản gốc"),
        ({**benign, "threat_taxonomy": {}}, "Cần lưu ý trước khi mở tệp", "Tạm thời đừng mở bản gốc"),
        (
            {**benign, "threat_taxonomy": {"ml_label_predictions": [{"evidence_status": "model_signal"}]}},
            "Cần lưu ý trước khi mở tệp",
            "Tạm thời đừng mở bản gốc",
        ),
        ({**benign, "threat_taxonomy": observed}, "Có dấu hiệu đáng ngờ", "Tránh mở bản gốc"),
        (
            {"verdict": "UNAVAILABLE", "forensic_dossier": {"threat_taxonomy": observed}},
            "Có dấu hiệu đáng ngờ",
            "Tránh mở bản gốc",
        ),
        ({**benign, "verdict": "MALICIOUS", "is_ood": True}, "Có cảnh báo mã độc", "Đừng mở bản gốc"),
    ]
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body><script>\n'
        + _inline_core_module()
        + "\nconst cases = "
        + json.dumps([data for data, _, _ in cases])
        + ";\n"
        + "document.documentElement.setAttribute('data-review-results',JSON.stringify(cases.map(scanAssessment)));"
        + "</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    results = json.loads(attributes["data-review-results"])
    for result, (_, title, guidance) in zip(results, cases, strict=True):
        assert result["title"] == title
        assert result["guidance"].startswith(guidance)


def test_trusted_types_csp_blocks_raw_innerhtml_and_allows_dom_toast(tmp_path: Path) -> None:
    payload = "<img src=x onerror=1>"
    page = (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"require-trusted-types-for 'script'; trusted-types malpdf-html malpdf-script-url dompurify;\">"
        '</head><body><div id="toast-container"></div><div id="sr-announcer"></div><script>\n'
        + _inline_core_module()
        + "\nlet rawBlocked = false;\n"
        + "try { document.body.innerHTML = "
        + json.dumps(payload)
        + "; } catch (err) { rawBlocked = err instanceof TypeError; }\n"
        + "initTrustedTypes();\n"
        + "showToast("
        + json.dumps(payload)
        + ", 'warning', 300000);\n"
        + "document.documentElement.setAttribute('data-raw-blocked', String(rawBlocked));\n"
        + "document.documentElement.setAttribute('data-toast-literal', "
        + "String(document.getElementById('toast-container').textContent.includes("
        + json.dumps(payload)
        + ")));\n"
        + "</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    assert attributes.get("data-raw-blocked") == "true"
    assert attributes.get("data-toast-literal") == "true"


def test_vietnamese_ime_composition_enter_does_not_submit_chat_form(tmp_path: Path) -> None:
    ai_source = (STATIC_DIR / "dashboard-ai.js").read_text(encoding="utf-8")
    assert "event.isComposing || event.keyCode === 229" in ai_source
    page = """<!doctype html><html><head><meta charset="utf-8"></head><body>
<form id="ai-chat-form"><textarea id="ai-chat-input">Xin chào</textarea><button id="ai-chat-send-btn" type="submit">Gửi</button></form>
<script>
const form = document.getElementById("ai-chat-form");
const input = document.getElementById("ai-chat-input");
let submits = 0;
form.addEventListener("submit", (event) => { event.preventDefault(); submits += 1; });
input.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    if (event.isComposing || event.keyCode === 229) return;
    form.requestSubmit();
  }
});
input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, isComposing: true }));
const afterComposing = submits;
const safariKeyCode = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
Object.defineProperty(safariKeyCode, "keyCode", { get: () => 229 });
input.dispatchEvent(safariKeyCode);
const after229 = submits;
input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", shiftKey: true, bubbles: true, cancelable: true }));
const afterShift = submits;
input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
document.documentElement.setAttribute("data-ime-counts", JSON.stringify([afterComposing, after229, afterShift, submits]));
</script></body></html>"""
    attributes = _browser_attributes(tmp_path, page)
    assert json.loads(attributes["data-ime-counts"]) == [0, 0, 0, 1]


def test_modern_web_workbench_contract_and_highlight_api(tmp_path: Path) -> None:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    theme = (STATIC_DIR / "dashboard-theme.css").read_text(encoding="utf-8")
    script = (STATIC_DIR / "dashboard-app.js").read_text(encoding="utf-8")
    for element_id in ("btn-theme-toggle", "cdr-mode-select", "conformal-state-badge", "cdr-ssim-metric"):
        assert f'id="{element_id}"' in template
    assert 'command="--sort"' in template
    assert "/assets/dashboard-theme.css" in template
    assert "/assets/dashboard-app.js" in template
    for feature in (
        "aria-sort",
        "moveBefore",
        "Intl.Collator",
        "CSS.highlights",
        "TreeWalker",
        "contentvisibilityautostatechange",
    ):
        assert feature in script
    assert "::highlight(malpdf-js-threat)" in theme
    assert ':root:has(> head > meta[name="color-scheme"][content="dark"])' in theme

    page = (
        '<!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><style>'
        + theme
        + """</style></head><body>
<section id="deferred" class="deferred-below-fold"><code id="snippet">Observed marker: alert.</code></section>
<script>
const root = document.documentElement;
window.addEventListener("error", () => { root.dataset.runtimeError = "true"; });
const meta = document.querySelector('meta[name="color-scheme"]');
root.dataset.initialScheme = getComputedStyle(root).colorScheme;
meta.content = "dark";
root.dataset.explicitScheme = getComputedStyle(root).colorScheme;

const snippet = document.getElementById("snippet");
const walker = document.createTreeWalker(snippet, NodeFilter.SHOW_TEXT);
const node = walker.nextNode();
const marker = "alert";
const offset = node.data.indexOf(marker);
const range = new Range();
range.setStart(node, offset);
range.setEnd(node, offset + marker.length);
CSS.highlights.set("malpdf-js-threat", new Highlight(range));
root.dataset.highlightRegistered = String(CSS.highlights.has("malpdf-js-threat"));
const [registered] = CSS.highlights.get("malpdf-js-threat");
root.dataset.highlightNodes = JSON.stringify([registered.startContainer.nodeType, registered.endContainer.nodeType]);
root.dataset.highlightText = registered.toString();

const section = document.getElementById("deferred");
const eventName = "contentvisibilityautostatechange";
section.addEventListener(eventName, (event) => {
  root.dataset.visibilitySkipped = String(event.skipped);
}, { once: true });
section.dispatchEvent(new ContentVisibilityAutoStateChangeEvent(eventName, { skipped: true }));
</script></body></html>"""
    )
    attributes = _browser_attributes(tmp_path, page)
    assert "data-runtime-error" not in attributes
    assert attributes["data-initial-scheme"] == "light dark"
    assert attributes["data-explicit-scheme"] == "dark"
    assert attributes["data-highlight-registered"] == "true"
    assert json.loads(attributes["data-highlight-nodes"]) == [3, 3]
    assert attributes["data-highlight-text"] == "alert"
    assert attributes["data-visibility-skipped"] == "true"
