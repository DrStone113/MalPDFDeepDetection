from __future__ import annotations

from html.parser import HTMLParser
import json
import os
import re
from pathlib import Path
import shutil
import subprocess


class DocumentAttributes(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_attributes: dict[str, str | None] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "html":
            self.html_attributes = dict(attrs)


def test_browser_template_contains_no_provider_credentials() -> None:
    template = Path(__file__).resolve().parents[1] / "src/malpdf/web/templates/index.html"
    source = template.read_text(encoding="utf-8")
    contains_key_literal = re.search(r"\b(?:sk-(?:proj-)?|hf_)[A-Za-z0-9_-]{20,}", source) is not None
    assert contains_key_literal is False, "Provider credential literals must never be served to browsers"
    assert "VILAO_API_CONFIG.apiKey" not in source


def _browser_attributes(tmp_path: Path, page: str) -> dict[str, str | None]:
    candidates = [
        os.environ.get("MALPDF_TEST_BROWSER"), shutil.which("google-chrome"), shutil.which("chromium"),
        shutil.which("chromium-browser"), r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    browser = next((str(path) for path in candidates if path and Path(path).is_file()), None)
    assert browser is not None, "Chrome/Chromium is required; set MALPDF_TEST_BROWSER to its executable"
    target = tmp_path / "notification.html"
    target.write_text(page, encoding="utf-8")
    result = subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--disable-background-networking", "--no-first-run",
         f"--user-data-dir={tmp_path / 'browser-profile'}", "--dump-dom", "--timeout=10000",
         "--virtual-time-budget=1000", target.as_uri()],
        capture_output=True, timeout=30, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    dom = DocumentAttributes()
    dom.feed(result.stdout.decode("utf-8", errors="replace"))
    return dom.html_attributes


def test_notification_displays_untrusted_subject_as_text_in_real_browser(tmp_path: Path) -> None:
    template = Path(__file__).resolve().parents[1] / "src/malpdf/web/templates/index.html"
    source = template.read_text(encoding="utf-8")
    start = source.index("    function showToast(")
    end = source.index("\n    }", start) + len("\n    }")
    escape_start = source.index("    function _escTax(")
    escape_end = source.index("\n    }", escape_start) + len("\n    }")
    payload = '<svg onload="document.documentElement.setAttribute(\'data-review-xss\',\'executed\')"></svg>'
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body><div id="toast-container"></div><script>\n'
        + source[escape_start:escape_end] + "\n" + source[start:end]
        + "\nconst subject = " + json.dumps(payload) + ";\nshowToast(subject, 'success', 300000);"
        + "\ndocument.documentElement.setAttribute('data-review-literal-message',"
        + "String(document.getElementById('toast-container').textContent.includes(subject)));"
        + "\n</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    assert "data-review-xss" not in attributes
    assert attributes.get("data-review-literal-message") == "true"


def test_held_email_is_not_labeled_safe_or_offered_as_clean_download(tmp_path: Path) -> None:
    template = Path(__file__).resolve().parents[1] / "src/malpdf/web/templates/index.html"
    source = template.read_text(encoding="utf-8")
    start = source.index("    function renderEMLInspectionResult(")
    end = source.index("\n    }", start) + len("\n    }")
    ids = ["mail-tab-result-card", "mail-tab-res-subject", "mail-tab-res-sender", "mail-tab-res-attachments",
           "mail-tab-res-threats", "mail-tab-action-badge", "btn-mail-tab-download-eml"]
    markup = "".join(f'<div id="{name}"></div>' for name in ids)
    data = {"subject": "Needs review", "total_attachments": 1, "malicious_attachments": 0,
            "unavailable_attachments": 1, "action_taken": "HELD_FOR_REVIEW", "eml_job_id": "held-email"}
    page = (
        '<!doctype html><html><head><meta charset="utf-8"></head><body>' + markup + "<script>" + source[start:end]
        + "\nrenderEMLInspectionResult(" + json.dumps(data) + ");"
        + "document.documentElement.setAttribute('data-review-badge',document.getElementById('mail-tab-action-badge').innerText);"
        + "document.documentElement.setAttribute('data-review-download-hidden',String(document.getElementById('btn-mail-tab-download-eml').classList.contains('hidden')));"
        + "</script></body></html>"
    )
    attributes = _browser_attributes(tmp_path, page)
    assert attributes.get("data-review-badge") == "Cần kiểm tra thêm"
    assert attributes.get("data-review-download-hidden") == "true"
