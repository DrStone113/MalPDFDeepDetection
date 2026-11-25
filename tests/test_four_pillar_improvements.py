from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct

import numpy as np
import pikepdf
from pypdf import PdfReader
from pypdf.generic import ByteStringObject
import pytest

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner import ingestion
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.ingestion import InstantPDFIngestion


@pytest.fixture(scope="module")
def pytorch_engine():
    return MalPDFScannerEngine(device="cpu")


@pytest.fixture(scope="module")
def onnx_engine():
    from production.onnx_engine import ONNXMalPDFScannerEngine

    return ONNXMalPDFScannerEngine()


@pytest.fixture(scope="module", params=["pytorch", "onnx"])
def scanner(request):
    return request.getfixturevalue(f"{request.param}_engine")


def _with_links(*urls: str) -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        pdf.pages[0].obj.Annots = pikepdf.Array(
            [
                pikepdf.Dictionary(
                    Type=pikepdf.Name.Annot,
                    Subtype=pikepdf.Name.Link,
                    Rect=pikepdf.Array([1, 1, 20, 20]),
                    A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(url)),
                )
                for url in urls
            ]
        )
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def _with_scripts(location: str, code: str, *, packed: bool = False) -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        action = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(code)))
        if location in ("names", "combined"):
            pdf.Root.Names = pikepdf.Dictionary(
                JavaScript=pikepdf.Dictionary(Names=pikepdf.Array([pikepdf.String("check"), action]))
            )
        if location in ("open", "combined"):
            pdf.Root.OpenAction = action
        if location == "combined":
            pdf.Root.AA = pikepdf.Dictionary(WS=action)
        if location == "form":
            field = pdf.make_indirect(
                pikepdf.Dictionary(
                    FT=pikepdf.Name.Tx,
                    T=pikepdf.String("Amount"),
                    AA=pikepdf.Dictionary(F=action),
                )
            )
            pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([field]))
        output = io.BytesIO()
        pdf.save(
            output, object_stream_mode=pikepdf.ObjectStreamMode.generate if packed else pikepdf.ObjectStreamMode.disable
        )
        return output.getvalue()


@pytest.mark.parametrize("style", ["objstm", "hex"])
def test_pillar1_hidden_pdf_triggers_detected(scanner, style):
    raw = _with_scripts("combined", 'eval("1 + 1");', packed=style == "objstm")
    if style == "hex":
        raw = (
            raw.replace(b"/OpenAction", b"/#4fpenAction")
            .replace(b"/JavaScript", b"/#4aavaScript")
            .replace(b"/JS", b"/#4a#53")
        )
    result = scanner.scan_bytes(raw, explain=True)
    audit = result.forensic_dossier["evasion_unpack_audit"]
    expected = {"JS", "JavaScript", "OpenAction", "AA"} if style == "objstm" else {"JS", "JavaScript", "OpenAction"}
    assert expected <= set(audit["recovered_hidden_triggers"])
    if style == "objstm":
        assert audit["objstm_streams_unpacked"] > 0
        assert 0 < audit["objstm_decoded_bytes"] <= 4 * 1024**2
    else:
        assert audit["hex_escaped_names_decoded"] >= 3
    assert result.verdict == "MALICIOUS"
    assert result.malware_probability > 0.85
    assert result.forensic_dossier["js_semantics"]["malicious_indicator_count"] > 0


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("names", 'app.alert("Safe test");'),
        ("open", 'app.alert("Safe notice");'),
        ("form", 'AFNumber_Format(2, 0, 0, 0, "$", true);'),
        ("form", 'event.value = this.getField("Subtotal").value;'),
    ],
)
def test_pillar2_verified_benign_javascript(scanner, location, code):
    result = scanner.scan_bytes(_with_scripts(location, code), explain=True)
    assert result.forensic_dossier["js_semantics"]["is_verified_benign_js"]
    assert result.verdict == "BENIGN"
    if location in ("names", "open"):
        assert result.forensic_dossier["ast_semantic_calibration"]["applied"]
    assert result.malware_probability < scanner.decision_threshold
    assert result.threat_taxonomy["threat_label"] == "Clean.PDF.Verified"
    assert result.threat_taxonomy["severity"] == "SAFE"
    assert result.threat_taxonomy["detected_count"] == 0


def test_pillar2_dynamic_javascript_is_not_rescued(scanner):
    result = scanner.scan_bytes(_with_scripts("combined", 'eval("1 + 1");'), explain=True)
    assert not result.forensic_dossier["js_semantics"]["is_verified_benign_js"]
    assert result.verdict == "MALICIOUS"


def test_phishing_is_stripped_and_benign_link_is_preserved():
    safe_url = "https://example.org/doc/0"
    raw = _with_links(safe_url, "https://reader.example@192.0.2.2/verify-account")
    ingested = InstantPDFIngestion().ingest(raw)
    assert ingested["phishing_analysis"]["has_phishing_threat"]
    assert any(node["action_role"] == "suspicious_uri" for node in ingested["raw_records"])
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized
    assert any(path.endswith("/URI") for path in audit.actions_stripped)
    assert len(cleaned) > 0.8 * len(raw)
    assert audit.original_pages == audit.sanitized_pages
    assert audit.content_streams_preserved and audit.resources_preserved
    original, sanitized = [PdfReader(io.BytesIO(data)) for data in (raw, cleaned)]
    assert [p.extract_text() for p in original.pages] == [p.extract_text() for p in sanitized.pages]
    actions = [annotation.get_object().get("/A", {}) for annotation in sanitized.pages[0]["/Annots"]]
    assert [str(action["/URI"]) for action in actions if "/URI" in action] == [safe_url]
    assert not InstantPDFIngestion().ingest(cleaned)["phishing_analysis"]["has_phishing_threat"]


def test_pillar3_phishing_verdict_and_rescan(scanner):
    raw = _with_links("https://reader.example@192.0.2.2/verify-account")
    result = scanner.scan_bytes(raw, explain=True)
    assert result.verdict == "MALICIOUS"
    assert result.malware_probability >= 0.885
    assert result.forensic_dossier["phishing_analysis"]["has_phishing_threat"]
    assert any(
        head["id"] == "suspicious_uri_redirect" and head["detected"]
        for head in result.threat_taxonomy["ml_label_predictions"]
    )
    cleaned, _ = PDFDisarmer().sanitize_bytes(raw)
    assert scanner.scan_bytes(cleaned).verdict == "BENIGN"
    assert scanner.scan_bytes(_with_links("https://example.org/doc/0")).verdict == "BENIGN"


def _with_codec_stream(segment_type: int) -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        stream = pdf.make_stream(struct.pack(">IBBBI", 1, segment_type, 0, 0, 0))
        stream.Filter = pikepdf.Name.JBIG2Decode
        pdf.Root.CodecCheck = stream
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


def test_pillar4_jbig2_framing_anomaly_is_detected(scanner):
    result = scanner.scan_bytes(_with_codec_stream(63), explain=True)
    expected = "jbig2_unknown_segment_type"
    assert any(expected in item["reason_codes"] for item in result.forensic_dossier["codec_anomalies"])
    assert any(node["is_threat_trigger"] and node["filter"] == "/JBIG2Decode" for node in result.graph_nodes)
    assert result.verdict == "MALICIOUS"
    assert any(
        head["id"] == "structural_parser_evasion" and head["detected"]
        for head in result.threat_taxonomy["ml_label_predictions"]
    )
    ingested = InstantPDFIngestion().ingest(_with_codec_stream(51))
    assert ingested["codec_anomalies"] == []


def test_onnx_and_pytorch_pillar_probability_parity(pytorch_engine, onnx_engine):
    for raw in (
        _with_scripts("combined", 'eval("1 + 1");', packed=True),
        _with_scripts("open", 'app.alert("Safe notice");'),
        _with_scripts("form", 'AFNumber_Format(2, 0, 0, 0, "$", true);'),
        _with_links("https://reader.example@192.0.2.2/verify-account"),
        _with_codec_stream(63),
    ):
        pt, ort = [engine.scan_bytes(raw) for engine in (pytorch_engine, onnx_engine)]
        assert pt.verdict == ort.verdict
        assert abs(pt.malware_probability - ort.malware_probability) <= 1e-5


@pytest.mark.parametrize(
    "code",
    [
        "AFNumber_Keystroke(2, 0, 0, 0, '$', true);",
        "AFDate_KeystrokeEx('mm/dd/yyyy');",
        "AFRange_Validate(true, 0, true, 100);",
        "AFSimple_Calculate('SUM', new Array('Quantity', 'Price'));",
        "var qty = this.getField('Quantity').value; var price = 2; event.value = Math.round(qty * price);",
        "if (event.value < 0) { app.alert('Invalid'); event.rc = false; }",
        "var values = [1, 2]; event.value = values[0];",
        "function diagnostic() { return 1; } diagnostic();",
    ],
)
def test_diverse_enterprise_acroform_js_matrix(scanner, code):
    result = scanner.scan_bytes(_with_scripts("form", code), explain=True)
    semantics = result.forensic_dossier["js_semantics"]
    assert semantics["is_verified_benign_js"] is True, semantics["unverified_reasons"]
    assert result.verdict == "BENIGN"
    assert result.threat_taxonomy["detected_count"] == 0


@pytest.mark.parametrize(
    "code",
    [
        pytest.param("var unused = new Function('return 1');", id="function-constructor"),
        pytest.param("var name = 'eval'; this[name]('1 + 1');", id="computed-global-call"),
        pytest.param("var text = 'A'; for (var i = 0; i < 5; i++) { text += text; }", id="string-doubling"),
        pytest.param("function diagnostic() { Collab.getIcon('diagnostic'); }", id="collab-icon"),
    ],
)
def test_non_allowlisted_javascript_is_not_rescued(scanner, code):
    result = scanner.scan_bytes(_with_scripts("combined", code), explain=True)
    assert not result.forensic_dossier["js_semantics"]["is_verified_benign_js"]
    assert result.verdict == "MALICIOUS"


@pytest.mark.parametrize("password", ["", "private-test-copy"])
def test_encrypted_pdf_preserves_input_identity(scanner, password, monkeypatch):
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        output = io.BytesIO()
        pdf.save(output, encryption=pikepdf.Encryption(owner="fixture-owner", user=password, R=4))
    raw = output.getvalue()

    def unavailable_aes(stream, **options):
        if b"/Encrypt" in stream.getvalue():
            raise ingestion.pypdf.errors.DependencyError("AES backend unavailable for regression control")
        return PdfReader(stream, **options)

    monkeypatch.setattr(ingestion, "PdfReader", unavailable_aes)
    ingested = scanner.ingestion.ingest(raw)
    assert ingested["sha256"] == hashlib.sha256(raw).hexdigest()
    assert ingested["size_bytes"] == len(raw)
    assert ingested["raw_tokens"]["Encrypt"] > 0
    assert ingested["graph_present"] is (not password)
    assert ingested["graph_byte_source"] == (None if password else "unlocked_pdf_copy")
    assert scanner.scan_bytes(raw).verdict == "BENIGN"


def _with_lure_link(url: str, *, lure: str = "") -> bytes:
    with pikepdf.open(io.BytesIO(_with_links(url))) as pdf:
        if lure:
            page = pdf.pages[0]
            page.obj.Resources["/Font"] = page.obj.Resources.get("/Font") or pikepdf.Dictionary()
            page.obj.Resources.Font.TestLure = pikepdf.Dictionary(
                Type=pikepdf.Name.Font,
                Subtype=pikepdf.Name.Type1,
                BaseFont=pikepdf.Name.Helvetica,
            )
            page.contents_add(b"BT /TestLure 10 Tf 40 720 Td (" + lure.encode("ascii") + b") Tj ET")
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


@pytest.mark.parametrize(
    ("url", "lure", "reason"),
    [
        ("https://docusign-review.example/document", "", "brand_impersonation_host"),
        (
            "https://bit.ly/reserved-regression-control",
            "Verify your account. Sign in to view.",
            "phishing_lure_context",
        ),
        ("https://example.org/download/fixture.zip", "", "executable_payload_link"),
        ("https://example.org/download/fixture.docm", "", "executable_payload_link"),
    ],
)
def test_diverse_phishing_uri_matrix(scanner, url, lure, reason):
    raw = _with_lure_link(url, lure=lure)
    result = scanner.scan_bytes(raw, explain=True)
    assert result.verdict == "MALICIOUS"
    assert any(reason in item["reasons"] for item in result.forensic_dossier["phishing_analysis"]["suspicious_uris"])
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and audit.content_streams_preserved and audit.resources_preserved
    assert len(cleaned) > 0.8 * len(raw) and audit.original_pages == audit.sanitized_pages
    before, after = ([page.extract_text() for page in PdfReader(io.BytesIO(data)).pages] for data in (raw, cleaned))
    assert any(after) and before == after
    assert scanner.scan_bytes(cleaned, explain=False).verdict == "BENIGN"


def test_hex_uri_byte_string_is_recorded_and_disarmed(scanner):
    raw = _with_links("https://example.org/archive.docm")
    literal = b"(https://example.org/archive.docm)"
    target = b"https://example.org/archive.docm\x00"
    encoded = b"<" + target.hex().encode() + b">"
    assert literal in raw
    raw = raw.replace(literal, encoded, 1)
    annotation = PdfReader(io.BytesIO(raw)).pages[0]["/Annots"][0].get_object()
    assert isinstance(annotation["/A"]["/URI"], ByteStringObject)
    result = scanner.scan_bytes(raw, explain=True)
    assert result.verdict == "MALICIOUS"
    assert any(
        node["id"] == "action:annot_0_0" and node["action_role"] == "suspicious_uri" for node in result.graph_nodes
    )
    cleaned, audit = PDFDisarmer().sanitize_bytes(raw)
    assert audit.is_sanitized and audit.content_streams_preserved and audit.resources_preserved
    assert len(cleaned) > 0.8 * len(raw) and audit.original_pages == audit.sanitized_pages
    before, after = ([page.extract_text() for page in PdfReader(io.BytesIO(data)).pages] for data in (raw, cleaned))
    assert any(after) and before == after
    assert scanner.scan_bytes(cleaned).verdict == "BENIGN"


_REPO = Path(__file__).resolve().parents[1]
_RUN = "run_20261123T095927Z_16abd6134688"


@pytest.fixture(scope="module")
def phase2_variants(tmp_path_factory):
    folder = tmp_path_factory.mktemp("phase2")
    benign, threat = load_real_benign_bytes(), load_real_threat_bytes()
    assert hashlib.sha256(benign).hexdigest() == "ef43e7f9e1c138d5d5279fe3c16e54c7d0a63c1a056f5008550872e31b4b0fa7"
    assert hashlib.sha256(threat).hexdigest() == "b260f9e53f0b8dabdc9ac81e93119e9b66766db88f8ece507596c7039cff9eca"
    benign_path, threat_path = folder / "benign.pdf", folder / "threat.pdf"
    benign_path.write_bytes(benign)
    threat_path.write_bytes(threat)
    recipe = _REPO / "scripts/lab/run_byte_level_stress_v3.py"
    source = ast.parse(recipe.read_text(encoding="utf-8"))
    archived_worker = next(
        ast.literal_eval(node.value)
        for node in source.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "REMOTE_WORKER_SOURCE" for t in node.targets)
    )
    generators = [
        node
        for node in ast.parse(archived_worker).body
        if isinstance(node, ast.FunctionDef) and node.name in {"append_inc", "build_variants"}
    ]
    recipe_namespace = {"pikepdf": pikepdf, "shutil": shutil, "re": re}
    exec(compile(ast.Module(body=generators, type_ignores=[]), str(recipe), "exec"), recipe_namespace)
    return {
        name: (group, path.read_bytes())
        for name, group, path in recipe_namespace["build_variants"](folder, benign_path, threat_path)
    }


def test_all_20_phase_2_byte_stress_variants_live_pytorch_and_onnx(phase2_variants, pytorch_engine, onnx_engine):
    assert [group for group, _ in phase2_variants.values()].count("benign") == 12
    assert [group for group, _ in phase2_variants.values()].count("threat") == 8
    for name, (group, raw) in phase2_variants.items():
        pt, ort = [engine.scan_bytes(raw, explain=False) for engine in (pytorch_engine, onnx_engine)]
        expected = "BENIGN" if group == "benign" else "MALICIOUS"
        assert pt.verdict == ort.verdict == expected, (name, pt.malware_probability, ort.malware_probability)
        assert abs(pt.malware_probability - ort.malware_probability) <= 1e-4, name


def test_catalog_evidence_survives_padded_page_cap(scanner, phase2_variants, monkeypatch):
    _, raw = phase2_variants["threat_padded_50_pages"]
    ingested = scanner.ingestion.ingest(raw)
    assert ingested["pages_count"] == 52
    assert len(ingested["raw_records"]) <= 200
    observed = {record["evidence_id"] for record in ingested["raw_records"]}
    assert {"action:open_action", "action:aa", "script:names_js"} <= observed
    assert len(ingested["extracted_scripts"]) >= 3
    assert scanner.scan_bytes(raw, explain=False).verdict == "MALICIOUS"
    monkeypatch.setattr(scanner, "decision_threshold", 0.95)
    result = scanner.scan_bytes(raw)
    assert result.verdict == "MALICIOUS"
    adjustment = result.forensic_dossier["anti_padding_subgraph_reconciliation"]
    assert adjustment["applied"]
    assert adjustment["diluted_prob"] < scanner.decision_threshold < adjustment["core_subgraph_prob"]


@pytest.mark.parametrize("seed", range(42, 47))
def test_five_seed_stability_on_phase2_stress_variants(seed, phase2_variants, tmp_path, monkeypatch):
    study = _REPO / "reports/experiments/transgraph_v3" / _RUN
    lock = json.loads((study / f"seed_evaluations/seed{seed}/model_lock.json").read_text(encoding="utf-8"))
    summary = json.loads((study / "multiseed_byte_stress_summary.json").read_text(encoding="utf-8"))
    threshold = next(item["calibration"]["threshold"] for item in summary["per_seed"] if item["seed"] == seed)
    directory = _REPO / lock["artifact_directory"]
    weights = directory / "v3_tab_graph_ssl_inv.npz"
    config = directory / "v3_tab_graph_ssl_inv_config.json"
    scaler = directory / "robust_transform.npz"
    for key, file in (("weights", weights), ("model_config", config), ("scaler", scaler)):
        assert hashlib.sha256(file.read_bytes()).hexdigest() == lock["input_sha256"][key]
    contract = json.loads(ingestion.DEFAULT_V3_CONTRACT_PATH.read_text(encoding="utf-8"))
    indices = contract["feature_indices_73"]
    with np.load(scaler, allow_pickle=False) as scale:
        assert np.all(scale["available"][indices])
        contract.update(center=scale["center"][indices].tolist(), scale=scale["scale"][indices].tolist())
    contract.update(
        seed=seed,
        source_run=_RUN,
        temperature=lock["temperature"],
        decision_threshold=threshold,
        weights_npz_sha256=lock["input_sha256"]["weights"],
        model_config=json.loads(config.read_text(encoding="utf-8")),
    )
    contract_file = tmp_path / "seed_contract.json"
    contract_file.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(ingestion, "DEFAULT_V3_CONTRACT_PATH", contract_file)
    scanner = MalPDFScannerEngine(model_path=weights, device="cpu")
    for name in (
        "threat_objstm_packed",
        "threat_padded_50_pages",
        "benign_safe_js_alert",
        "benign_objstm_packed",
        "benign_repaired_xref_padding",
    ):
        group, raw = phase2_variants[name]
        result = scanner.scan_bytes(raw, explain=False)
        assert result.verdict == ("BENIGN" if group == "benign" else "MALICIOUS"), (
            seed,
            name,
            result.malware_probability,
        )
