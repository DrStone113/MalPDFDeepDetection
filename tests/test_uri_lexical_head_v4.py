from __future__ import annotations

import io
import ipaddress
import json
from pathlib import Path
import shutil
import tempfile

from fastapi.testclient import TestClient
import numpy as np
import pikepdf
from production.onnx_engine import ONNXMalPDFScannerEngine
import production.web_service as prod_web
import pymupdf as fitz
import pytest
import torch

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.models.uri_lexical_head_v4 import PDFURILexicalHeadV4, load_uri_head_v4_npz
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.uri_head import URILexicalHeadScorer, validate_uri_lexical_contract
from malpdf.scanner.uri_lexical import (
    URI_LEXICAL_FEATURE_NAMES,
    URI_LEXICAL_SCHEMA_VERSION,
    URI_LOG1P_INDICES,
    _is_ip_host,
    _parse_ip_address,
    extract_plain_text_urls,
    extract_url_lexical_features,
    is_allowlisted_uri,
    is_bare_dual_use_hosted_uri,
    is_scorable_http_uri,
    is_xml_xmp_namespace_uri,
    normalize_uri_for_lexical_features,
    registrable_domain,
)
from malpdf.web.app import app as dev_app

REPO_ROOT = Path(__file__).resolve().parents[1]
OR_GATE_URI = (
    "https://login-verify-microsoft-security-update-2026.top/signin/oauth/confirm.php?session=982371&token=abc"
)
ALT_OR_GATE_URI = "https://xq92-m4k1p.top/k81/d/index.php?e=1"
GATED_FUSION_URI = "http://www.ns4.site"
DUAL_USE_BENIGN_WORKERS = "https://fixture.workers.dev/review"
DUAL_USE_BENIGN_FORMS = "https://docs.google.com/forms/d/fixture/viewform"
DUAL_USE_DGA_WORKERS = "https://holy-union-137c.51g0jm50281.workers.dev/"
DUAL_USE_LURE_FORMS = "https://docs.google.com/forms/d/e/1FAIpQLSf98234_verify_wallet_login_confirm_8421/viewform"
BENIGN_DEEP_URI = "https://www.southbankmosaics.com/docs/reference/manual-v2/section-4.pdf"
BENIGN_ORDINARY_LINK = "https://example.org/docs"


@pytest.fixture(scope="module")
def engines() -> tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine]:
    return MalPDFScannerEngine(device="cpu"), ONNXMalPDFScannerEngine()


def _mutate_benign_pdf(edit) -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        edit(pdf)
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()


def _append_page_stream(pdf: pikepdf.Pdf, page_obj: pikepdf.Dictionary, raw_ops: bytes) -> None:
    extra = pdf.make_indirect(pdf.make_stream(raw_ops))
    contents = page_obj.get("/Contents")
    if isinstance(contents, pikepdf.Array):
        contents.append(extra)
    elif contents is not None:
        page_obj.Contents = pikepdf.Array([contents, extra])
    else:
        page_obj.Contents = extra


def _uri_head_prediction(result) -> dict:
    preds = result.threat_taxonomy["ml_label_predictions"]
    return next(item for item in preds if item["id"] == "suspicious_uri_redirect")


def _assert_cdr_integrity(raw_bytes: bytes, cleaned_bytes: bytes, audit) -> None:
    assert audit.is_sanitized is True
    assert not audit.quarantine_recommended
    assert len(cleaned_bytes) > 0.8 * len(raw_bytes)
    with (
        fitz.open(stream=raw_bytes, filetype="pdf") as before,
        fitz.open(stream=cleaned_bytes, filetype="pdf") as after,
    ):
        assert len(before) == len(after) == audit.original_pages == audit.sanitized_pages
        orig_text = "\n".join(page.get_text("text") for page in before).strip()
        clean_text = "\n".join(page.get_text("text") for page in after).strip()
        assert len(orig_text) > 0
        assert clean_text == orig_text


def test_uri_lexical_schema_normalization_and_tld_fallbacks() -> None:
    assert URI_LEXICAL_SCHEMA_VERSION == "uri_lexical_v4.2"
    assert len(URI_LEXICAL_FEATURE_NAMES) == 36
    assert len(URI_LOG1P_INDICES) == 17

    scorer = URILexicalHeadScorer(prefer_onnx=False)
    assert scorer.model_loaded is True

    # Scheme neutrality (http:// == https://)
    for tail in (
        "login-verify-microsoft-security-update-2026.top/signin/oauth/confirm.php?session=982371&token=abc",
        "www.southbankmosaics.com/docs/reference/manual-v2/section-4.pdf",
        "www.ns4.site",
    ):
        http_url, https_url = f"http://{tail}", f"https://{tail}"
        v_http = extract_url_lexical_features(
            http_url,
            tld_legit_probs=scorer.tld_legit_probs,
            char_probs=scorer.char_probs,
            default_tld_prob=scorer.default_tld_prob,
            default_char_prob=scorer.default_char_prob,
        )
        v_https = extract_url_lexical_features(
            https_url,
            tld_legit_probs=scorer.tld_legit_probs,
            char_probs=scorer.char_probs,
            default_tld_prob=scorer.default_tld_prob,
            default_char_prob=scorer.default_char_prob,
        )
        assert v_http.shape == (36,)
        assert np.array_equal(v_http, v_https)
        p_http, p_https = scorer.score_urls([http_url, https_url])
        assert abs(float(p_http) - float(p_https)) < 1e-12

    # www. neutrality (www.adobe.com/acrobat == adobe.com/acrobat)
    v_www = extract_url_lexical_features(
        "https://www.adobe.com/acrobat",
        tld_legit_probs=scorer.tld_legit_probs,
        char_probs=scorer.char_probs,
        default_tld_prob=scorer.default_tld_prob,
        default_char_prob=scorer.default_char_prob,
    )
    v_bare = extract_url_lexical_features(
        "https://adobe.com/acrobat",
        tld_legit_probs=scorer.tld_legit_probs,
        char_probs=scorer.char_probs,
        default_tld_prob=scorer.default_tld_prob,
        default_char_prob=scorer.default_char_prob,
    )
    assert np.array_equal(v_www, v_bare)

    # Multi-label PSL root protection: www.co.uk must NOT strip www.
    _, _, uk_host, uk_path, _, uk_body = normalize_uri_for_lexical_features("https://www.co.uk/docs")
    assert uk_host == "www.co.uk"
    assert uk_path == "/docs"
    assert uk_body == "www.co.uk/docs"

    # Bare trailing "/" normalization vs query & userinfo/port preservation
    assert normalize_uri_for_lexical_features("https://iana.org")[5] == "iana.org"
    assert normalize_uri_for_lexical_features("https://iana.org/")[5] == "iana.org"
    assert normalize_uri_for_lexical_features("https://www.iana.org/")[5] == "iana.org"
    assert normalize_uri_for_lexical_features("https://iana.org/?a=1")[5] == "iana.org/?a=1"
    _, _, h_up, _, _, b_up = normalize_uri_for_lexical_features("https://user:pass@www.example.com:8080/a?x=1")
    assert h_up == "example.com"
    assert b_up == "user:pass@example.com:8080/a?x=1"

    # Unseen high-risk vs unseen neutral TLD fallback
    v_hr = extract_url_lexical_features(
        "https://example.zip/download",
        tld_legit_probs={},
        char_probs={},
        default_tld_prob=0.50,
    )
    v_neu = extract_url_lexical_features(
        "https://example.invalidtld99/download",
        tld_legit_probs={},
        char_probs={},
        default_tld_prob=0.50,
    )
    idx_tld_prob = URI_LEXICAL_FEATURE_NAMES.index("tld_legitimate_prob")
    assert float(v_hr[idx_tld_prob]) == pytest.approx(0.05)
    assert float(v_neu[idx_tld_prob]) == pytest.approx(0.50)

    # Path challenge controls remain below t_high
    benign_controls = [
        "https://www.adobe.com/acrobat",
        "https://learn.microsoft.com/dotnet/desktop/winforms/",
        "https://github.com/example/project/blob/main/README.md",
        "https://docs.google.com/document/d/fixture/edit",
        "https://docs.example.com/view/98123",
        "https://portal.example.net/docs/overview",
        "https://en.wikipedia.org/wiki/Portable_Document_Format",
        "https://www.iana.org/",
    ]
    assert all(float(p) < scorer.t_high for p in scorer.score_urls(benign_controls))


def test_xml_xmp_and_strict_subdomain_allowlist() -> None:
    for xml_uri in (
        "http://ns.adobe.com/xap/1.0/",
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "http://purl.org/dc/elements/1.1/",
        "http://creativecommons.org/ns#",
        "uuid:8f12ab34-5678-4321-abcd-1234567890ef",
        "xmp:did:1234",
    ):
        assert is_xml_xmp_namespace_uri(xml_uri) is True
    assert is_xml_xmp_namespace_uri("https://evil.example/ns") is False

    for allowed in (
        "https://doi.org/10.1000/xyz",
        "https://sub.nist.gov/publications/detail",
        "https://uni.edu.vn/en/",
    ):
        assert is_allowlisted_uri(allowed) is True

    for untrusted in (
        DUAL_USE_BENIGN_FORMS,
        "https://sites.google.com/view/test-portal",
        "https://bit.ly/3xAbCd",
        "https://evil.github.io/login",
        "https://evil.com?ref=doi.org",
    ):
        assert is_allowlisted_uri(untrusted) is False


def test_dual_use_hosted_routing_tier_contract() -> None:
    assert is_bare_dual_use_hosted_uri(DUAL_USE_BENIGN_WORKERS) is True
    assert is_bare_dual_use_hosted_uri(DUAL_USE_BENIGN_FORMS) is True
    assert is_bare_dual_use_hosted_uri(DUAL_USE_DGA_WORKERS) is False
    assert is_bare_dual_use_hosted_uri(DUAL_USE_LURE_FORMS) is False
    assert is_bare_dual_use_hosted_uri("https://metamusklogiz.godaddysites.com/") is False
    assert is_bare_dual_use_hosted_uri("https://bit.ly/3xAbCd") is False

    scorer = URILexicalHeadScorer(prefer_onnx=False)
    bare_res = scorer.score_pdf_uris([{"raw_uri": DUAL_USE_BENIGN_WORKERS, "source": "annot_uri"}])
    assert bare_res["tier"] == "gated_fusion"

    forms_res = scorer.score_pdf_uris([{"raw_uri": DUAL_USE_BENIGN_FORMS, "source": "annot_uri"}])
    assert forms_res["tier"] == "gated_fusion"

    # Mixed document: benign dual-use link must never mask genuine or_gate phishing URL
    mixed_res = scorer.score_pdf_uris(
        [
            {"raw_uri": DUAL_USE_BENIGN_WORKERS, "source": "annot_uri"},
            {"raw_uri": OR_GATE_URI, "source": "annot_uri"},
        ]
    )
    assert mixed_res["tier"] == "or_gate"
    assert mixed_res["top_url"] == OR_GATE_URI

    dga_res = scorer.score_pdf_uris([{"raw_uri": DUAL_USE_DGA_WORKERS, "source": "annot_uri"}])
    assert dga_res["tier"] == "or_gate"
    lure_res = scorer.score_pdf_uris([{"raw_uri": DUAL_USE_LURE_FORMS, "source": "annot_uri"}])
    assert lure_res["tier"] == "or_gate"


def test_multivector_real_pdf_uri_extraction_and_xmp_filtering(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    pt_engine, _ = engines

    def add_vectors(pdf: pikepdf.Pdf) -> None:
        page0 = pdf.pages[0].obj
        page0.Annots = pikepdf.Array(
            [
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Link,
                        Rect=pikepdf.Array([10, 10, 50, 50]),
                        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=OR_GATE_URI),
                    )
                ),
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Widget,
                        Rect=pikepdf.Array([10, 60, 50, 90]),
                        A=pikepdf.Dictionary(
                            S=pikepdf.Name.SubmitForm,
                            F=pikepdf.Dictionary(FS=pikepdf.Name.URL, F=GATED_FUSION_URI),
                        ),
                    )
                ),
            ]
        )
        pdf.Root.OpenAction = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.URI, URI=ALT_OR_GATE_URI))
        _append_page_stream(pdf, page0, b"\nBT (Visit http://www.rasa.services) Tj ET\n")
        meta = pdf.make_stream(
            b'<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
            b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/"/></rdf:RDF></x:xmpmeta>'
        )
        meta["/Type"] = pikepdf.Name.Metadata
        meta["/Subtype"] = pikepdf.Name.XML
        pdf.Root.Metadata = pdf.make_indirect(meta)

    raw = _mutate_benign_pdf(add_vectors)
    ingest_data = pt_engine.ingestion.ingest(raw)
    extracted = ingest_data.get("extracted_uris") or []
    extracted_uris_text = {str(item.get("raw_uri") or item.get("uri") or "") for item in extracted}
    assert "http://ns.adobe.com/xap/1.0/" not in extracted_uris_text

    scored = pt_engine.uri_head.score_pdf_uris(
        [*extracted, {"raw_uri": "http://ns.adobe.com/xap/1.0/", "source": "flate_text_stream"}]
    )
    vec_counts = scored["vector_counts"]
    assert vec_counts.get("annot_uri", 0) >= 1
    assert vec_counts.get("action_uri", 0) >= 1
    assert vec_counts.get("action_submitform", 0) >= 1
    assert vec_counts.get("flate_text_stream", 0) >= 1
    assert scored["filtered_xml_xmp_count"] >= 1


def test_two_tier_fusion_or_gate_gated_fusion_and_password_fail_closed(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    def with_single_annot(uri: str, *, submit_form: bool = False):
        def edit(pdf: pikepdf.Pdf) -> None:
            page0 = pdf.pages[0].obj
            action = (
                pikepdf.Dictionary(S=pikepdf.Name.SubmitForm, F=pikepdf.Dictionary(FS=pikepdf.Name.URL, F=uri))
                if submit_form
                else pikepdf.Dictionary(S=pikepdf.Name.URI, URI=uri)
            )
            page0.Annots = pikepdf.Array(
                [
                    pdf.make_indirect(
                        pikepdf.Dictionary(
                            Type=pikepdf.Name.Annot,
                            Subtype=pikepdf.Name.Widget if submit_form else pikepdf.Name.Link,
                            Rect=pikepdf.Array([10, 10, 50, 50]),
                            A=action,
                        )
                    )
                ]
            )

        return _mutate_benign_pdf(edit)

    or_raw = with_single_annot(OR_GATE_URI)
    alt_or_raw = with_single_annot(ALT_OR_GATE_URI)
    uncorr_raw = with_single_annot(GATED_FUSION_URI)
    corr_raw = with_single_annot(GATED_FUSION_URI, submit_form=True)

    or_results = [eng.scan_bytes(or_raw, explain=False) for eng in engines]
    assert [res.verdict for res in or_results] == ["MALICIOUS", "MALICIOUS"]
    assert abs(or_results[0].malware_probability - or_results[1].malware_probability) <= 1e-5
    for res in or_results:
        assert res.forensic_dossier["uri_ml_analysis"]["tier"] == "or_gate"
        head6 = _uri_head_prediction(res)
        assert head6["model_flagged"] is True
        assert head6["evidence_status"] in {"observed", "model_signal"}

    alt_or_results = [eng.scan_bytes(alt_or_raw, explain=False) for eng in engines]
    assert [res.verdict for res in alt_or_results] == ["MALICIOUS", "MALICIOUS"]
    assert abs(alt_or_results[0].malware_probability - alt_or_results[1].malware_probability) <= 1e-5
    for res in alt_or_results:
        assert res.forensic_dossier["uri_ml_analysis"]["tier"] == "or_gate"
        head6 = _uri_head_prediction(res)
        assert head6["model_flagged"] is True
        assert head6["evidence_status"] == "model_signal"

    uncorr_results = [eng.scan_bytes(uncorr_raw, explain=False) for eng in engines]
    assert [res.verdict for res in uncorr_results] == ["BENIGN", "BENIGN"]
    assert abs(uncorr_results[0].malware_probability - uncorr_results[1].malware_probability) <= 1e-5
    for res in uncorr_results:
        uri_ml = res.forensic_dossier["uri_ml_analysis"]
        assert uri_ml["tier"] == "gated_fusion"
        assert uri_ml["gated_fusion_triggered"] is False
        assert _uri_head_prediction(res)["model_flagged"] is False

    corr_results = [eng.scan_bytes(corr_raw, explain=False) for eng in engines]
    assert [res.verdict for res in corr_results] == ["MALICIOUS", "MALICIOUS"]
    assert abs(corr_results[0].malware_probability - corr_results[1].malware_probability) <= 1e-5
    for res in corr_results:
        uri_ml = res.forensic_dossier["uri_ml_analysis"]
        assert uri_ml["tier"] == "gated_fusion"
        assert uri_ml["gated_fusion_triggered"] is True
        assert _uri_head_prediction(res)["model_flagged"] is True

    with pikepdf.open(io.BytesIO(or_raw)) as pdf:
        buf = io.BytesIO()
        pdf.save(buf, encryption=pikepdf.Encryption(owner="owner-pw", user="user-pw", R=4))
        locked_raw = buf.getvalue()

    locked_results = [eng.scan_bytes(locked_raw, explain=False) for eng in engines]
    assert abs(locked_results[0].malware_probability - locked_results[1].malware_probability) <= 1e-5
    for res in locked_results:
        assert res.forensic_dossier["encryption_analysis"]["password_locked"] is True
        assert res.forensic_dossier["uri_ml_analysis"]["tier"] == "benign"
        assert res.forensic_dossier["uri_ml_analysis"]["scored_url_count"] == 0
        assert _uri_head_prediction(res)["model_flagged"] is False

    threat_raw = load_real_threat_bytes()
    threat_results = [eng.scan_bytes(threat_raw, explain=False) for eng in engines]
    assert [res.verdict for res in threat_results] == ["MALICIOUS", "MALICIOUS"]
    assert abs(threat_results[0].malware_probability - threat_results[1].malware_probability) <= 1e-5


def test_pytorch_onnx_numpy_uri_head_parity() -> None:
    np_scorer = URILexicalHeadScorer(prefer_onnx=False)
    ox_scorer = URILexicalHeadScorer(prefer_onnx=True)
    assert np_scorer.backend == "numpy"
    assert ox_scorer.backend == "onnx"

    pt_model = load_uri_head_v4_npz(
        PDFURILexicalHeadV4(),
        REPO_ROOT / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz",
    )
    pt_model.eval()

    probe_urls = [
        OR_GATE_URI,
        ALT_OR_GATE_URI,
        GATED_FUSION_URI,
        BENIGN_DEEP_URI,
        "https://www.iana.org",
    ]
    scaled = np_scorer.extract_scaled_batch(probe_urls)
    with torch.no_grad():
        pt_logits = pt_model(torch.from_numpy(scaled)).cpu().numpy().reshape(-1)
    np_logits = np_scorer.predict_raw_logits(probe_urls)
    ox_logits = ox_scorer.predict_raw_logits(probe_urls)
    assert float(np.max(np.abs(pt_logits - np_logits))) < 1e-5
    assert float(np.max(np.abs(pt_logits - ox_logits))) < 1e-5

    np_probs = np_scorer.score_urls(probe_urls)
    ox_probs = ox_scorer.score_urls(probe_urls)
    assert float(np.max(np.abs(np_probs - ox_probs))) < 1e-5


def test_eight_of_eight_heads_contract_and_api_health() -> None:
    contract = json.loads((REPO_ROOT / "configs" / "multilabel_threat_v4_contract.json").read_text(encoding="utf-8"))
    labels = contract["labels"]
    assert len(labels) == 8
    assert sum(1 for item in labels if item.get("model_flag_enabled") is True) == 8
    head6 = labels[6]
    assert head6["id"] == "suspicious_uri_redirect"
    assert head6["model_flag_enabled"] is True
    assert float(head6["uri_t_low"]) == pytest.approx(0.5)
    assert float(head6["threshold"]) == pytest.approx(0.991)

    with TestClient(dev_app) as dev_client, TestClient(prod_web.app) as prod_client:
        for client in (dev_client, prod_client):
            resp = client.get("/api/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "healthy"
            assert body["multilabel_total_heads"] == 8
            assert body["multilabel_enabled_heads"] == 8
            assert body["uri_lexical_head_loaded"] is True


def test_cdr_in_place_or_gate_excision_preserves_benign_links_and_content(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    def add_mixed_links(pdf: pikepdf.Pdf) -> None:
        page0 = pdf.pages[0].obj
        page0.Annots = pikepdf.Array(
            [
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Link,
                        Rect=pikepdf.Array([10, 10, 50, 50]),
                        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=OR_GATE_URI),
                    )
                ),
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Link,
                        Rect=pikepdf.Array([60, 10, 100, 50]),
                        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=BENIGN_ORDINARY_LINK),
                    )
                ),
            ]
        )

    raw = _mutate_benign_pdf(add_mixed_links)
    disarmer = PDFDisarmer()
    cleaned, audit = disarmer.sanitize_bytes(raw, file_name="mixed_links.pdf")
    _assert_cdr_integrity(raw, cleaned, audit)

    with pikepdf.open(io.BytesIO(cleaned)) as clean_pdf:
        annots = clean_pdf.pages[0].obj.get("/Annots") or []
        uris = [
            str(annot.get("/A", {}).get("/URI"))
            for annot in annots
            if isinstance(annot, pikepdf.Dictionary) and isinstance(annot.get("/A"), pikepdf.Dictionary)
        ]
    assert OR_GATE_URI not in uris
    assert BENIGN_ORDINARY_LINK in uris

    for engine in engines:
        res = engine.scan_bytes(cleaned, explain=False)
        assert res.verdict == "BENIGN"
        assert res.forensic_dossier["uri_ml_analysis"]["tier"] == "benign"


def test_uri_head_resolves_hf_bundle_layout_without_production_dir() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp)
        (bundle / "configs").mkdir()
        (bundle / "models").mkdir()
        for cname in ("onnx_manifest.json", "uri_lexical_head_v4_contract.json"):
            shutil.copy2(REPO_ROOT / "production" / "configs" / cname, bundle / "configs" / cname)
        shutil.copy2(
            REPO_ROOT / "production" / "models" / "uri_lexical_head_v4.onnx",
            bundle / "models" / "uri_lexical_head_v4.onnx",
        )

        by_manifest = URILexicalHeadScorer(manifest_path=bundle / "configs" / "onnx_manifest.json", prefer_onnx=True)
        by_contract = URILexicalHeadScorer(
            contract_path=bundle / "configs" / "uri_lexical_head_v4_contract.json", prefer_onnx=True
        )
        assert by_manifest.model_loaded is True and by_manifest.backend == "onnx"
        assert by_contract.model_loaded is True and by_contract.backend == "onnx"


def test_score_pdf_uris_reserves_qr_budget_and_reports_truncation() -> None:
    scorer = URILexicalHeadScorer(prefer_onnx=False)
    bare_links = [
        {
            "raw_uri": f"https://docs.google.com/forms/d/fixture-{chr(97 + idx // 26)}{chr(97 + idx % 26)}/viewform",
            "source": "annot_uri",
        }
        for idx in range(256)
    ]
    res = scorer.score_pdf_uris(bare_links, qr_uris=[OR_GATE_URI])
    assert res["tier"] == "or_gate"
    assert res["top_url"] == OR_GATE_URI
    assert res["top_url_vector"] == "qr_image"
    assert res["scored_url_count"] == 256
    assert res["truncated_candidate_count"] == 1
    assert res["vector_counts"] == {"annot_uri": 255, "qr_image": 1}


def test_structured_pdf_uri_preserves_trailing_punctuation_vs_prose() -> None:
    scorer = URILexicalHeadScorer(prefer_onnx=False)
    dotted_uri = "https://www.example.net/#appendix."
    direct_prob = float(scorer.score_urls([dotted_uri])[0])
    pdf_res = scorer.score_pdf_uris([{"raw_uri": dotted_uri, "source": "annot_uri"}])
    assert pdf_res["top_url"] == dotted_uri
    assert pdf_res["max_prob"] == pytest.approx(round(direct_prob, 6))
    assert extract_plain_text_urls("See http://www and https://example.org/docs.") == ["https://example.org/docs"]


def test_v42_tj_kerning_stream_obfuscation_brand_and_mixed_schema_rejection(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
) -> None:
    pt_engine, ox_engine = engines
    assert is_scorable_http_uri("http://www") is False
    assert is_scorable_http_uri("https://github") is False
    assert is_scorable_http_uri("http://127.0.0.1/test") is False
    assert is_scorable_http_uri("http://198.51.100.44/login") is True
    assert (
        is_allowlisted_uri("https://proceedings.neurips.cc/paper/2020/file/1457c0d6bfcb4967418bfb8ac142f64a-Paper.pdf")
        is True
    )

    # TJ kerning must reconstruct without truncated http://www, while separate Tj ops never merge
    def add_kerned_streams(pdf: pikepdf.Pdf) -> None:
        page0 = pdf.pages[0].obj
        _append_page_stream(
            pdf,
            page0,
            b"\nBT /F1 10 Tf 40 700 Td [(https://www)-15(.example.org/docs/guide.pdf)] TJ "
            b"0 -14 Td (https://split-a) Tj 0 -14 Td (.example.org/b) Tj ET\n",
        )

    kerned_raw = _mutate_benign_pdf(add_kerned_streams)
    extracted = pt_engine.ingestion.ingest(kerned_raw).get("extracted_uris") or []
    extracted_urls = [str(item.get("raw_uri") or item.get("uri") or "") for item in extracted]
    assert "https://www.example.org/docs/guide.pdf" in extracted_urls
    assert "http://www" not in extracted_urls
    assert "https://www" not in extracted_urls
    assert "https://split-a.example.org/b" not in extracted_urls

    # Malformed stream with raw TJ operators must not manufacture truncated single-label http://www
    def add_broken_tj_stream(pdf: pikepdf.Pdf) -> None:
        _append_page_stream(pdf, pdf.pages[0].obj, b"\nBT [(http://www)-15(.ietf.org)] TJ [\x00\xff/broken\n")

    broken_raw = _mutate_benign_pdf(add_broken_tj_stream)
    broken_urls = [
        str(item.get("raw_uri") or item.get("uri") or "")
        for item in (ox_engine.ingestion.ingest(broken_raw).get("extracted_uris") or [])
    ]
    assert not any(u.rstrip("/").endswith("://www") for u in broken_urls)

    # Obfuscation narrows to authority / dangerous path escapes; path brand restricted to hosting abuse roots
    idx_obf = URI_LEXICAL_FEATURE_NAMES.index("has_obfuscation")
    idx_brand = URI_LEXICAL_FEATURE_NAMES.index("brand_in_untrusted_host")
    scorer = pt_engine.uri_head
    kw = {
        "tld_legit_probs": scorer.tld_legit_probs,
        "char_probs": scorer.char_probs,
        "default_tld_prob": scorer.default_tld_prob,
        "default_char_prob": scorer.default_char_prob,
    }
    assert (
        extract_url_lexical_features("https://www.example-publisher.org/files/Annual%20Report%202024.pdf", **kw)[
            idx_obf
        ]
        == 0.0
    )
    assert extract_url_lexical_features("https://evil.example/%6c%6f%67%69%6e", **kw)[idx_obf] == 1.0
    assert extract_url_lexical_features("https://evil.example/a%2e%2e/b", **kw)[idx_obf] == 1.0
    gh_commit = "https://github.com/google-research/bert/commit/eedf5716ce1268e56f0a50264a88cafad334ac61"
    assert extract_url_lexical_features(gh_commit, **kw)[idx_brand] == 0.0
    assert float(scorer.score_urls([gh_commit])[0]) < scorer.t_high

    stale_v41 = dict(scorer.contract)
    stale_v41["schema_version"] = "uri_lexical_v4.1"
    with pytest.raises(ValueError, match="invalid_uri_lexical_schema_version"):
        validate_uri_lexical_contract(stale_v41)


def test_v42_maker_checker_invariants(
    engines: tuple[MalPDFScannerEngine, ONNXMalPDFScannerEngine],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pt_engine, ox_engine = engines
    scorer = pt_engine.uri_head
    kw = {
        "tld_legit_probs": scorer.tld_legit_probs,
        "char_probs": scorer.char_probs,
        "default_tld_prob": scorer.default_tld_prob,
        "default_char_prob": scorer.default_char_prob,
    }
    idx_brand = URI_LEXICAL_FEATURE_NAMES.index("brand_in_untrusted_host")

    # Non-dotted / hex / octal / mapped loopback IP encodings must be blocked before scoring
    for bad_ip in (
        "http://0x7f000001/login",
        "http://2130706433/login",
        "http://0177.0.0.1/login",
        "http://[::ffff:127.0.0.1]/login",
    ):
        assert is_scorable_http_uri(bad_ip) is False
    assert _parse_ip_address("0177.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
    assert _is_ip_host("0177.0.0.1") is True
    assert is_scorable_http_uri("http://0306.063.0144.054/login") is True
    assert is_scorable_http_uri("http://198.51.100.44/login") is True

    # Word boundary around 'booking' avoids matching booking2 while catching booking-portal
    assert extract_url_lexical_features("https://booking2.example/docs", **kw)[idx_brand] == 0.0
    assert extract_url_lexical_features("https://booking-portal.example/docs", **kw)[idx_brand] == 1.0

    # Fixed 36/128/64 + 0.15 dropout contract must reject type/dimension/NaN mismatches
    for field, bad_val in (
        ("in_dim", 28),
        ("in_dim", 36.0),
        ("hidden_dim", 64),
        ("hidden_dim", True),
        ("bottleneck_dim", 32),
        ("dropout", 0.2),
        ("dropout", 0.1499999),
        ("dropout", 0.1500001),
        ("dropout", float("nan")),
    ):
        tampered = json.loads(json.dumps(scorer.contract))
        tampered["model_config"][field] = bad_val
        with pytest.raises(ValueError, match="invalid_uri_lexical_model_config"):
            validate_uri_lexical_contract(tampered)

    # Short hex IPv4 must agree between _is_ip_host/_parse_ip_address/registrable_domain; bad octal & Unicode digits rejected
    assert _is_ip_host("0x8080808") is True
    assert is_scorable_http_uri("http://0x8080808/login") is True
    assert registrable_domain("0x8080808") == "8.8.8.8"
    assert registrable_domain("::ffff:127.0.0.1") == "127.0.0.1"
    assert is_scorable_http_uri("http://0188.0.0.1/login") is False
    assert is_scorable_http_uri("http://\u00b2/login") is False
    assert extract_plain_text_urls("See https://[2001:db8::1]/guide and (https://[2001:db8::1]).") == [
        "https://[2001:db8::1]/guide",
        "https://[2001:db8::1]",
    ]

    # pdfa.org XML namespace filter must keep ISO 32000-2 document URLs extracted & benign
    assert is_xml_xmp_namespace_uri("http://www.pdfa.org/ns/xmp/") is True
    assert is_xml_xmp_namespace_uri("https://pdfa.org/resource/iso-32000-2/") is False
    iso_url = "https://pdfa.org/resource/iso-32000-2/"

    def add_iso_annot(pdf: pikepdf.Pdf) -> None:
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([20, 20, 120, 40]),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(iso_url)),
            )
        )
        pdf.pages[0].obj["/Annots"] = pikepdf.Array([annot])

    iso_raw = _mutate_benign_pdf(add_iso_annot)
    iso_extracted = [
        str(u.get("raw_uri") or "") for u in (ox_engine.ingestion.ingest(iso_raw).get("extracted_uris") or [])
    ]
    assert iso_url in iso_extracted
    assert ox_engine.scan_bytes(iso_raw, file_name="iso32000.pdf", explain=False).verdict == "BENIGN"

    # TJ word gap must preserve space between URL and adjacent word; failed quote-op stream stays discarded
    def add_tj_gap_stream(pdf: pikepdf.Pdf) -> None:
        _append_page_stream(
            pdf,
            pdf.pages[0].obj,
            b"\nBT /F1 10 Tf [(https://example.org/guide)-1000(Reference)] TJ ET\n",
        )

    gap_raw = _mutate_benign_pdf(add_tj_gap_stream)
    gap_urls = [str(u.get("raw_uri") or "") for u in (ox_engine.ingestion.ingest(gap_raw).get("extracted_uris") or [])]
    assert "https://example.org/guide" in gap_urls
    assert "https://example.org/guideReference" not in gap_urls

    def add_broken_quote_stream(pdf: pikepdf.Pdf) -> None:
        _append_page_stream(
            pdf,
            pdf.pages[0].obj,
            b"\nBT /F1 10 Tf (https://broken-quote.example/x) ' ET\n[\x00\xff/broken",
        )

    quote_raw = _mutate_benign_pdf(add_broken_quote_stream)
    quote_urls = [
        str(u.get("raw_uri") or "") for u in (ox_engine.ingestion.ingest(quote_raw).get("extracted_uris") or [])
    ]
    assert "https://broken-quote.example/x" not in quote_urls

    # Unrounded OR-gate helper must match raw score_urls output and ignore bare dual-use hosts
    probe_url = "https://xq92-m4k1p.top/k81/d/index.php?e=1"
    expected_prob = float(scorer.score_urls([probe_url])[0])
    got_prob = scorer.max_or_eligible_prob(
        [
            {"raw_uri": probe_url, "source": "pdf_annot"},
            {"raw_uri": "https://docs.google.com/document/d/x/edit", "source": "pdf_annot"},
        ]
    )
    assert got_prob == pytest.approx(expected_prob, rel=0.0, abs=1e-6)

    # Inline-image BI malformed stream & ContentStream AssertionError must never crash ingestion or scan_bytes
    def add_malformed_bi_stream(pdf: pikepdf.Pdf) -> None:
        _append_page_stream(
            pdf,
            pdf.pages[0].obj,
            b"\nBI /W 1 /H 1 /BPC 1 /CS /G ID \x00\xff\nBT /F1 10 Tf (https://safe-bi.example.org/ok) Tj ET\n",
        )

    bi_raw = _mutate_benign_pdf(add_malformed_bi_stream)
    bi_res = ox_engine.ingestion.ingest(bi_raw)
    assert isinstance(bi_res.get("extracted_uris"), list)

    def _raise_assertion(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("simulated ContentStream inline image assertion")

    def add_annot_and_stream(pdf: pikepdf.Pdf) -> None:
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([20, 20, 120, 40]),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String("https://survives-bi.example.invalid/doc")),
            )
        )
        pdf.pages[0].obj["/Annots"] = pikepdf.Array([annot])

    annot_raw = _mutate_benign_pdf(add_annot_and_stream)
    with monkeypatch.context() as mp:
        mp.setattr("malpdf.scanner.ingestion.ContentStream", _raise_assertion)
        res_assert = ox_engine.ingestion.ingest(annot_raw)
        scan_assert = ox_engine.scan_bytes(annot_raw, file_name="bi_assert.pdf", explain=False)
    extracted_after_assert = [str(u.get("raw_uri") or "") for u in (res_assert.get("extracted_uris") or [])]
    assert "https://survives-bi.example.invalid/doc" in extracted_after_assert
    assert scan_assert.verdict == "BENIGN"
