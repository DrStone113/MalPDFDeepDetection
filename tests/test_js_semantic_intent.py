from __future__ import annotations

import io

import pikepdf
import pytest

from malpdf.scanner.ai_explainer import AIThreatExplainer
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.js_intent import analyze_pdf_javascript_intent
from test_four_pillar_improvements import _with_scripts

_FORM_HELPERS = """
function normalizedQuantity(value) {
    return Math.max(0, Number(value));
}

function roundCurrency(value) {
    return Math.round(Number(value) * 100) / 100;
}
"""
_FORM_CALCULATION = r"""
var subtotal = 0;
for (var i = 0; i < 5; i++) {
    var quantity = normalizedQuantity(this.getField("Quantity_" + i).value);
    var unitPrice = Number(this.getField("Price_" + i).value);
    var lineAmount = Number(quantity) * unitPrice;
    subtotal += Number(lineAmount);
}

var discountRate = Number(this.getField("DiscountRate").value);
var taxRate = Number(this.getField("TaxRate").value);
var discount = roundCurrency(subtotal * discountRate / 100);
var taxableAmount = subtotal - Number(discount);
var tax = roundCurrency(taxableAmount * taxRate / 100);
this.getField("Subtotal").value = roundCurrency(subtotal);
this.getField("Discount").value = discount;
this.getField("Tax").value = tax;
event.value = roundCurrency(taxableAmount + Number(tax));
AFNumber_Format(2, 0, 0, 0, "$", true);

var invoiceCode = this.getField("InvoiceCode").valueAsString.trim();
var invoicePattern = new RegExp("^[A-Z]{3}-[0-9]{5}$");
var dateText = this.getField("InvoiceDate").valueAsString.trim();
var datePattern = new RegExp("^[0-9]{2}/[0-9]{2}/[0-9]{4}$");
if (datePattern.test(dateText)) {
    var invoiceDate = util.scand("dd/mm/yyyy", dateText);
    this.getField("PreparedDate").value = util.printd("dd mmm yyyy", invoiceDate);
}

if (!invoicePattern.test(invoiceCode) || !datePattern.test(dateText)) {
    var message = "Vui lòng kiểm tra mã hóa đơn và ngày lập. " +
        "Thu\u1ebf được tính sau khi trừ chiết khấu. " +
        "Mã hóa đơn gồm ba chữ cái và năm chữ số.";
    app.alert({cMsg: message, cTitle: "Kiểm tra hóa đơn", nIcon: 1, nType: 0});
}
"""
_FORM_INTENTS = {"form_calculation", "form_formatting_and_validation", "benign_helper_library"}

_UNVERIFIED_JS = [
    pytest.param(
        'var method = "a" + "l" + "e" + "rt"; app[method]("Test notice");',
        id="short-fragment-computed-call",
    ),
    pytest.param(r'app.alert("\x65");', id="hex-escape"),
    pytest.param(r'app.alert("\u0065");', id="ascii-unicode-escape"),
    pytest.param("var text = 'A'; for (var i = 0; i < 5; i++) { text = text + text; }", id="string-doubling"),
    pytest.param("var values = new Array(2048);", id="oversized-array"),
    pytest.param(
        "var value = 12; for (var i = 0; i < 4; i++) { value = (value << 1) ^ i; }",
        id="shift-xor-decoder",
    ),
    pytest.param('function checkFormat() { util.printf("%s", "Test notice"); }', id="restricted-format-api"),
    pytest.param("function checkEmail() { Collab.collectEmailInfo(); }", id="collab-email"),
    pytest.param("function checkAttachment() { this.exportDataObject(); }", id="attachment-export"),
    pytest.param(
        'function checkSubmit() { this.submitForm("https://forms.example.invalid/"); }',
        id="external-form-submit",
    ),
    pytest.param('app.execMenuItem("UnsupportedMenuItem");', id="arbitrary-menu-item"),
    pytest.param("var x = ;", id="syntax-error"),
]


@pytest.fixture(scope="module", params=[False, True], ids=["pytorch", "onnx"])
def use_onnx(request: pytest.FixtureRequest) -> bool:
    return request.param


@pytest.fixture(scope="module")
def scanner(use_onnx: bool):
    if use_onnx:
        from production.onnx_engine import ONNXMalPDFScannerEngine

        return ONNXMalPDFScannerEngine()
    return MalPDFScannerEngine(device="cpu")


def _enterprise_form_pdf() -> bytes:
    with pikepdf.open(io.BytesIO(_with_scripts("names", _FORM_HELPERS))) as pdf:
        field_names = [
            "Subtotal",
            "DiscountRate",
            "TaxRate",
            "Discount",
            "Tax",
            "InvoiceCode",
            "InvoiceDate",
            "PreparedDate",
        ]
        field_names.extend(f"{column}_{i}" for i in range(5) for column in ("Quantity", "Price"))
        fields = [
            pdf.make_indirect(pikepdf.Dictionary(FT=pikepdf.Name.Tx, T=pikepdf.String(name))) for name in field_names
        ]
        total = pdf.make_indirect(
            pikepdf.Dictionary(
                FT=pikepdf.Name.Tx,
                T=pikepdf.String("Total"),
                AA=pikepdf.Dictionary(
                    C=pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(_FORM_CALCULATION)),
                ),
            )
        )
        pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([*fields, total]), CO=pikepdf.Array([total]))
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def _with_page_count(raw: bytes, pages_count: int) -> bytes:
    with pikepdf.open(io.BytesIO(raw)) as pdf:
        del pdf.pages[pages_count:]
        pdf.pages.extend([pdf.pages[0]] * (pages_count - len(pdf.pages)))
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def test_enterprise_form_intent_depends_on_document_helpers():
    report = analyze_pdf_javascript_intent([_FORM_CALCULATION])
    assert not report["is_verified_benign_js"]

    report = analyze_pdf_javascript_intent([_FORM_CALCULATION, _FORM_HELPERS])
    assert report["is_verified_benign_js"] is True
    assert _FORM_INTENTS <= set(report["script_intents"])
    assert not report["evasive_obfuscation_techniques"]


def test_enterprise_multifield_acroform_is_certified_benign(scanner):
    assert len(_FORM_CALCULATION.encode("utf-8")) > 1536
    result = scanner.scan_bytes(_enterprise_form_pdf(), explain=True)
    dossier = result.forensic_dossier
    semantics = dossier["js_semantics"]
    assert dossier["xai_metrics"]["ast_complexity"] > 200
    assert result.verdict == "BENIGN"
    assert result.is_ood is False
    assert semantics["is_verified_benign_js"] is True, semantics["unverified_reasons"]
    assert _FORM_INTENTS <= set(semantics["script_intents"])
    assert len(semantics["per_script_intents"]) == 2
    summary = semantics["intent_summary_vi"]
    assert summary
    taxonomy = result.threat_taxonomy
    assert taxonomy["detected_count"] == 0
    assert taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert dossier["conformal_analysis"]["conformal_state"] == "CERTIFIED_BENIGN"
    assert result.graph_nodes and all(not node["is_threat_trigger"] for node in result.graph_nodes)
    assert result.graph_edges and all(not edge["is_threat_edge"] for edge in result.graph_edges)
    explanation = AIThreatExplainer().explain_threat(result.to_dict())
    assert summary in explanation["executive_summary"]
    assert "thành phần cần lưu ý" not in explanation["executive_summary"]
    head_statuses = {head["id"]: head["evidence_status"] for head in taxonomy["ml_label_predictions"]}
    assert len(head_statuses) == 8
    assert set(head_statuses.values()) == {"not_observed"}, head_statuses


@pytest.mark.parametrize("pages_count", [1, 15], ids=["single-page", "multi-page"])
@pytest.mark.parametrize(
    ("code", "intent"),
    [
        pytest.param(
            "var params = this.getPrintParams(); "
            "params.interactive = params.constants.interactionLevel.full; this.print(params);",
            "print_helper",
            id="print-helper",
        ),
        pytest.param(
            'var groups = this.getOCGs(); if (groups.length > 0) { groups[0].state = true; } app.execMenuItem("FitPage");',
            "document_navigation_ui",
            id="viewer-ocg-navigation",
        ),
        pytest.param("", "empty_noop", id="empty-js"),
        pytest.param("// Adobe Designer", "empty_noop", id="comment-only-js"),
    ],
)
def test_viewer_and_noop_scripts_are_certified_benign(scanner, code, intent, pages_count):
    raw = _with_page_count(_with_scripts("open", code), pages_count)
    result = scanner.scan_bytes(raw, explain=True)
    dossier = result.forensic_dossier
    semantics = dossier["js_semantics"]
    assert result.pages_count == pages_count
    assert semantics["is_verified_benign_js"] is True, semantics["unverified_reasons"]
    assert intent in semantics["script_intents"]
    assert not dossier.get("anti_padding_subgraph_reconciliation", {}).get("applied")
    assert result.verdict == "BENIGN"
    assert result.threat_taxonomy["detected_count"] == 0
    assert dossier["conformal_analysis"]["conformal_state"] == "CERTIFIED_BENIGN"


@pytest.mark.parametrize("code", _UNVERIFIED_JS)
def test_js_intent_rejects_unverified_code(code):
    report = analyze_pdf_javascript_intent([code])
    assert report["is_verified_benign_js"] is False
    assert report["unverified_reasons"]


@pytest.mark.parametrize("code", _UNVERIFIED_JS)
def test_unverified_js_is_malicious(scanner, code):
    result = scanner.scan_bytes(_with_scripts("open", code), explain=True)
    assert result.forensic_dossier["js_semantics"]["is_verified_benign_js"] is False
    assert result.verdict == "MALICIOUS"


def test_hex_escaped_trigger_names_prevent_benign_js_verification(scanner):
    with pikepdf.open(io.BytesIO(_with_scripts("open", 'app.alert("Test notice");'))) as pdf:
        action = pdf.Root.OpenAction
        pdf.Root.XXOpenAction = action
        del pdf.Root.OpenAction
        action.TestJS = action.JS
        del action.JS
        action.S = pikepdf.Name("/XXJavaScript")
        output = io.BytesIO()
        pdf.save(output, object_stream_mode=pikepdf.ObjectStreamMode.disable)
    raw = output.getvalue()
    for placeholder, escaped in (
        (b"/XXOpenAction", b"/#4fpenAction"),
        (b"/XXJavaScript", b"/#4aavaScript"),
        (b"/TestJS", b"/#4a#53"),
    ):
        assert len(placeholder) == len(escaped) and raw.count(placeholder) == 1
        raw = raw.replace(placeholder, escaped, 1)

    result = scanner.scan_bytes(raw, explain=True)
    dossier = result.forensic_dossier
    assert dossier["evasion_unpack_audit"]["hex_escaped_names_decoded"] >= 3
    assert dossier["js_semantics"]["is_verified_benign_js"] is False
    assert result.verdict == "MALICIOUS"
