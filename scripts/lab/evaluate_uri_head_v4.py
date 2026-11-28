"""Independent Windows DEV evaluation comparing 7/8 baseline vs 8/8 URI head on held-out Test URLs and fixtures."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time
from typing import Any

import numpy as np
import pymupdf as fitz
import torch

REPO = Path(__file__).resolve().parents[2]
for p in (REPO, REPO / "src", REPO / "production"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from scripts.lab.train_uri_lexical_head_v4 import (
    _BENIGN_DEEP_PATHS,
    DEFAULT_REPORT_ROOT,
    PHIUSIIL_CSV_PATH,
    PHIUSIIL_ZIP_PATH,
    PHIUSIIL_ZIP_SHA256,
    REALWORLD_BENIGN_CHALLENGE_URLS,
    _build_annot_pdf,
    _build_flate_stream_pdf,
    _build_js_launchurl_pdf,
    _domain_grouped_split,
    _load_phiusiil_rows,
    compute_phiusiil_split_manifest_sha256,
)

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.models.uri_lexical_head_v4 import (
    PDFURILexicalHeadV4,
    URILexicalHeadV4Config,
    load_uri_head_v4_npz,
)
from malpdf.scanner.engine import MalPDFScannerEngine
from malpdf.scanner.uri_lexical import _split_url_host, canonicalize_extracted_uri, is_allowlisted_uri
from onnx_engine import ONNXMalPDFScannerEngine

DEFAULT_OUT_ROOT = REPO / "reports" / "experiments" / "uri_head_independent_eval"

PATH_CHALLENGE_URLS: tuple[str, ...] = REALWORLD_BENIGN_CHALLENGE_URLS


def _git_rev() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    except Exception:
        return "unknown"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_cdr_invariants(raw_pdf: bytes, disarmer: PDFDisarmer, label: str) -> dict[str, Any]:
    cleaned, audit = disarmer.sanitize_bytes(raw_pdf, file_name=f"{label}.pdf")
    with fitz.open(stream=raw_pdf, filetype="pdf") as orig_doc, fitz.open(stream=cleaned, filetype="pdf") as clean_doc:
        orig_pages = len(orig_doc)
        clean_pages = len(clean_doc)
        orig_text = "\n".join(p.get_text("text") for p in orig_doc).strip()
        clean_text = "\n".join(p.get_text("text") for p in clean_doc).strip()
    assert audit.is_sanitized, f"{label}: expected is_sanitized=True"
    assert len(cleaned) > 0.8 * len(raw_pdf), f"{label}: size shrunk below 80%"
    assert clean_pages == orig_pages, f"{label}: page count mismatch {clean_pages} != {orig_pages}"
    assert len(clean_text) > 0 and clean_text == orig_text, f"{label}: extracted text altered"
    return {
        "is_sanitized": bool(audit.is_sanitized),
        "raw_bytes": len(raw_pdf),
        "cleaned_bytes": len(cleaned),
        "size_ratio": round(len(cleaned) / max(len(raw_pdf), 1), 4),
        "pages": clean_pages,
        "text_chars": len(clean_text),
    }


def _check_uri_head_backend_logits(pt: MalPDFScannerEngine, ox: ONNXMalPDFScannerEngine) -> float:
    assert pt.uri_head.backend == "numpy", f"expected pt.uri_head.backend=='numpy', got {pt.uri_head.backend}"
    assert ox.uri_head.backend == "onnx", f"expected ox.uri_head.backend=='onnx', got {ox.uri_head.backend}"
    contract = pt.uri_head.contract
    npz_path = REPO / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz"
    pt_uri = load_uri_head_v4_npz(PDFURILexicalHeadV4(URILexicalHeadV4Config(**contract["model_config"])), npz_path)
    pt_uri.eval()
    scaled = pt.uri_head.extract_scaled_batch(list(PATH_CHALLENGE_URLS))
    with torch.no_grad():
        torch_logits = pt_uri(torch.from_numpy(scaled)).cpu().numpy().reshape(-1)
    np_logits = pt.uri_head.predict_raw_logits(list(PATH_CHALLENGE_URLS))
    ox_logits = ox.uri_head.predict_raw_logits(list(PATH_CHALLENGE_URLS))
    np_probs = pt.uri_head.score_urls(list(PATH_CHALLENGE_URLS))
    ox_probs = ox.uri_head.score_urls(list(PATH_CHALLENGE_URLS))
    return float(
        max(
            np.max(np.abs(torch_logits - np_logits)),
            np.max(np.abs(torch_logits - ox_logits)),
            np.max(np.abs(np_logits - ox_logits)),
            np.max(np.abs(np_probs - ox_probs)),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-per-vector", type=int, default=50)
    parser.add_argument("--n-benign-pdfs", type=int, default=150)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--train-report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    args = parser.parse_args()

    if _sha256_file(PHIUSIIL_ZIP_PATH) != PHIUSIIL_ZIP_SHA256:
        raise ValueError("phiusiil_zip_sha256_mismatch")
    rows, csv_sha = _load_phiusiil_rows(PHIUSIIL_CSV_PATH)
    tr_idx, va_idx, te_idx = _domain_grouped_split(rows, seed=args.seed)
    eval_split_sha = compute_phiusiil_split_manifest_sha256(rows, tr_idx, va_idx, te_idx)
    te_rows = [rows[i] for i in te_idx]

    rng = np.random.default_rng(args.seed + 7)
    te_phish = [u for u, y, _ in te_rows if y == 1 and not is_allowlisted_uri(u)]
    te_legit = [u for u, y, _ in te_rows if y == 0 and not is_allowlisted_uri(u)]
    rng.shuffle(te_phish)
    rng.shuffle(te_legit)

    pt = MalPDFScannerEngine(device="cpu")
    ox = ONNXMalPDFScannerEngine()
    assert pt.is_v4 and ox.is_v4
    assert pt.uri_head.model_loaded and ox.uri_head.model_loaded
    expected_npz_sha = str(ox.uri_head.contract["weights_npz_sha256"])
    if str(pt.uri_head.contract["weights_npz_sha256"]) != expected_npz_sha:
        raise RuntimeError("pt_ox_weights_npz_sha256_mismatch")
    matched_methodologies: list[tuple[str, dict[str, Any]]] = []
    for meth_path in sorted(args.train_report_root.glob("run_*/locked_methodology.json")):
        try:
            meth_data = json.loads(meth_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(meth_data.get("weights_npz_sha256") or "") == expected_npz_sha:
            matched_methodologies.append((str(meth_path.parent.name), meth_data))
    if not matched_methodologies:
        raise RuntimeError(f"missing_locked_methodology_for_weights:{expected_npz_sha}")
    matched_train_run_id, matched_meth = matched_methodologies[-1]
    recorded_seed = matched_meth.get("seed")
    if type(recorded_seed) is not int or recorded_seed != args.seed:
        raise RuntimeError(f"seed_mismatch:{args.seed}!={recorded_seed!r}")
    if str(matched_meth.get("source_dataset_csv_sha256") or "") != csv_sha:
        raise RuntimeError("phiusiil_csv_sha256_methodology_mismatch")
    if str(matched_meth.get("phiusiil_split_manifest_sha256") or "") != eval_split_sha:
        raise RuntimeError("phiusiil_split_manifest_sha256_mismatch")
    logit_parity = _check_uri_head_backend_logits(pt, ox)

    benign_base = load_real_benign_bytes()
    threat_base = load_real_threat_bytes()

    phish_cases: list[tuple[str, str, bytes]] = []
    k = args.n_per_vector
    for idx in range(min(k, len(te_phish) // 3)):
        phish_cases.append(("annot", te_phish[idx], _build_annot_pdf(benign_base, [te_phish[idx]])))
        u_fl = te_phish[k + idx]
        phish_cases.append(("flate", u_fl, _build_flate_stream_pdf(benign_base, [u_fl])))
        u_js = te_phish[2 * k + idx]
        phish_cases.append(("js_launch", u_js, _build_js_launchurl_pdf(benign_base, u_js)))

    benign_cases: list[bytes] = []
    cursor = 0
    for idx in range(args.n_benign_pdfs):
        cnt = int(rng.integers(5, 16))
        urls: list[str] = []
        for j in range(cnt):
            raw_u = te_legit[(cursor + j) % len(te_legit)]
            if idx % 2 == 1:
                sch, _nl, host, path, query = _split_url_host(raw_u)
                if path in ("", "/") and not query:
                    raw_u = f"{sch}://{host}{_BENIGN_DEEP_PATHS[(idx + j) % len(_BENIGN_DEEP_PATHS)]}"
            urls.append(raw_u)
        cursor += cnt
        benign_cases.append(
            _build_annot_pdf(benign_base, urls) if idx % 2 == 0 else _build_flate_stream_pdf(benign_base, urls)
        )

    per_vec_7_verdict: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_7_head6: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_pt_verdict: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_ox_verdict: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_pt_head6: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_ox_head6: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_pt_uri_cov: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    per_vec_8_ox_uri_cov: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    max_prob_diff = 0.0
    verdict_tier_mismatches = 0
    lat_phish_ms: list[float] = []

    orig_ox_loaded = ox.uri_head.model_loaded
    try:
        ox.uri_head.model_loaded = False
        for vec_name, _url, pdf_bytes in phish_cases:
            r7 = ox.scan_bytes(pdf_bytes, file_name=f"test7_{vec_name}.pdf", explain=False)
            h7 = next(h for h in r7.threat_taxonomy["ml_label_predictions"] if h["id"] == "suspicious_uri_redirect")
            per_vec_7_verdict[vec_name].append(r7.verdict == "MALICIOUS")
            per_vec_7_head6[vec_name].append(bool(h7["model_flagged"] or h7["detected"]))
    finally:
        ox.uri_head.model_loaded = orig_ox_loaded

    for vec_name, _url, pdf_bytes in phish_cases:
        t0 = time.perf_counter()
        r_ox = ox.scan_bytes(pdf_bytes, file_name=f"test_{vec_name}.pdf", explain=False)
        lat_phish_ms.append((time.perf_counter() - t0) * 1000.0)
        r_pt = pt.scan_bytes(pdf_bytes, file_name=f"test_{vec_name}.pdf", explain=False)

        max_prob_diff = max(max_prob_diff, abs(float(r_ox.malware_probability) - float(r_pt.malware_probability)))
        ox_h6 = next(h for h in r_ox.threat_taxonomy["ml_label_predictions"] if h["id"] == "suspicious_uri_redirect")
        pt_h6 = next(h for h in r_pt.threat_taxonomy["ml_label_predictions"] if h["id"] == "suspicious_uri_redirect")
        max_prob_diff = max(max_prob_diff, abs(float(ox_h6["probability"]) - float(pt_h6["probability"])))
        if (
            r_ox.verdict != r_pt.verdict
            or r_ox.forensic_dossier["uri_ml_analysis"]["tier"] != r_pt.forensic_dossier["uri_ml_analysis"]["tier"]
        ):
            verdict_tier_mismatches += 1

        per_vec_8_ox_verdict[vec_name].append(r_ox.verdict == "MALICIOUS")
        per_vec_8_pt_verdict[vec_name].append(r_pt.verdict == "MALICIOUS")
        per_vec_8_ox_head6[vec_name].append(
            r_ox.verdict == "MALICIOUS" and bool(ox_h6["model_flagged"] or ox_h6["detected"])
        )
        per_vec_8_pt_head6[vec_name].append(
            r_pt.verdict == "MALICIOUS" and bool(pt_h6["model_flagged"] or pt_h6["detected"])
        )
        per_vec_8_ox_uri_cov[vec_name].append(
            r_ox.forensic_dossier["uri_ml_analysis"]["tier"] in {"or_gate", "gated_fusion"}
        )
        per_vec_8_pt_uri_cov[vec_name].append(
            r_pt.forensic_dossier["uri_ml_analysis"]["tier"] in {"or_gate", "gated_fusion"}
        )

    ben_fp_ox = 0
    ben_fp_pt = 0
    ben_h6_flagged = 0
    lat_ben_ms: list[float] = []
    for idx, pdf_bytes in enumerate(benign_cases):
        t0 = time.perf_counter()
        r_ox = ox.scan_bytes(pdf_bytes, file_name=f"ben_{idx}.pdf", explain=False)
        lat_ben_ms.append((time.perf_counter() - t0) * 1000.0)
        r_pt = pt.scan_bytes(pdf_bytes, file_name=f"ben_{idx}.pdf", explain=False)
        ox_h6 = next(h for h in r_ox.threat_taxonomy["ml_label_predictions"] if h["id"] == "suspicious_uri_redirect")
        pt_h6 = next(h for h in r_pt.threat_taxonomy["ml_label_predictions"] if h["id"] == "suspicious_uri_redirect")
        max_prob_diff = max(
            max_prob_diff,
            abs(float(r_ox.malware_probability) - float(r_pt.malware_probability)),
            abs(float(ox_h6["probability"]) - float(pt_h6["probability"])),
        )
        if (
            r_ox.verdict != r_pt.verdict
            or r_ox.forensic_dossier["uri_ml_analysis"]["tier"] != r_pt.forensic_dossier["uri_ml_analysis"]["tier"]
        ):
            verdict_tier_mismatches += 1
        ben_fp_ox += int(r_ox.verdict == "MALICIOUS")
        ben_fp_pt += int(r_pt.verdict == "MALICIOUS")
        ben_h6_flagged += int(bool(ox_h6["model_flagged"]))

    path_challenge_details: list[dict[str, Any]] = []
    path_challenge_or_gate_fp = 0
    path_challenge_verdict_fp = 0
    for idx, ch_url in enumerate(PATH_CHALLENGE_URLS):
        pdf_bytes = _build_annot_pdf(benign_base, [ch_url])
        r_ox = ox.scan_bytes(pdf_bytes, file_name=f"challenge_{idx}.pdf", explain=False)
        r_pt = pt.scan_bytes(pdf_bytes, file_name=f"challenge_{idx}.pdf", explain=False)
        max_prob_diff = max(max_prob_diff, abs(float(r_ox.malware_probability) - float(r_pt.malware_probability)))
        if (
            r_ox.verdict != r_pt.verdict
            or r_ox.forensic_dossier["uri_ml_analysis"]["tier"] != r_pt.forensic_dossier["uri_ml_analysis"]["tier"]
        ):
            verdict_tier_mismatches += 1
        ox_uri = r_ox.forensic_dossier["uri_ml_analysis"]
        ch_canon = canonicalize_extracted_uri(ch_url)
        if ch_canon is None:
            raise RuntimeError(f"invalid_challenge_url:{ch_url}")
        ch_clean, _ = ch_canon
        extracted_ch = ox.ingestion.ingest(pdf_bytes).get("extracted_uris") or []
        extracted_clean: set[str] = set()
        for item in extracted_ch:
            if isinstance(item, dict):
                item_canon = canonicalize_extracted_uri(str(item.get("raw_uri") or item.get("uri") or ""))
                if item_canon is not None:
                    extracted_clean.add(item_canon[0])
        if ch_clean not in extracted_clean:
            raise RuntimeError(f"challenge_url_missing_from_ingestion_extraction:{ch_url}")
        if not is_allowlisted_uri(ch_clean):
            admitted_clean = {cand for cand, _vec in ox.uri_head._evaluate_pdf_candidates(extracted_ch)["candidates"]}
            if ch_clean not in admitted_clean:
                raise RuntimeError(f"challenge_url_not_admitted_by_uri_head:{ch_url}")
        if ox_uri["tier"] == "or_gate":
            path_challenge_or_gate_fp += 1
        if r_ox.verdict == "MALICIOUS":
            path_challenge_verdict_fp += 1
        path_challenge_details.append(
            {
                "url": ch_url,
                "prob": float(ox_uri["max_prob"]),
                "tier": str(ox_uri["tier"]),
                "verdict": str(r_ox.verdict),
            }
        )

    disarmer = PDFDisarmer()
    cdr_checks = {
        "real_benign": _verify_cdr_invariants(benign_base, disarmer, "real_benign"),
        "real_threat": _verify_cdr_invariants(threat_base, disarmer, "real_threat"),
        "clean_container_phish_annot": _verify_cdr_invariants(phish_cases[0][2], disarmer, "phish_annot"),
    }

    ox_vec_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_ox_verdict.items()}
    pt_vec_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_pt_verdict.items()}
    ox_head6_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_ox_head6.items()}
    pt_head6_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_pt_head6.items()}
    ox_cov_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_ox_uri_cov.items()}
    pt_cov_recalls = {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_8_pt_uri_cov.items()}
    ben_fpr_ox = round(ben_fp_ox / max(len(benign_cases), 1), 6)
    ben_fpr_pt = round(ben_fp_pt / max(len(benign_cases), 1), 6)

    gates_passed = (
        ox_vec_recalls["annot"] >= 0.35
        and ox_vec_recalls["flate"] >= 0.35
        and pt_vec_recalls["annot"] >= 0.35
        and pt_vec_recalls["flate"] >= 0.35
        and ox_head6_recalls["annot"] >= 0.35
        and ox_head6_recalls["flate"] >= 0.35
        and pt_head6_recalls["annot"] >= 0.35
        and pt_head6_recalls["flate"] >= 0.35
        and ox_cov_recalls["annot"] >= 0.50
        and ox_cov_recalls["flate"] >= 0.50
        and pt_cov_recalls["annot"] >= 0.50
        and pt_cov_recalls["flate"] >= 0.50
        and ben_fpr_ox <= 0.01
        and ben_fpr_pt <= 0.01
        and path_challenge_or_gate_fp == 0
        and path_challenge_verdict_fp == 0
        and verdict_tier_mismatches == 0
        and max_prob_diff < 1e-5
        and logit_parity < 1e-5
    )

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "schema_version": ox.uri_head.schema_version,
        "backends": {"scanner_numpy_backend": pt.uri_head.backend, "scanner_onnx_backend": ox.uri_head.backend},
        "test_phishing_total": len(phish_cases),
        "test_benign_multilink_total": len(benign_cases),
        "t_high": ox.uri_head.t_high,
        "baseline_7of8": {
            "verdict_recall_overall": round(float(np.mean([v for sub in per_vec_7_verdict.values() for v in sub])), 4),
            "verdict_recall_by_vector": {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_7_verdict.items()},
            "head6_recall_overall": round(float(np.mean([v for sub in per_vec_7_head6.values() for v in sub])), 4),
            "head6_recall_by_vector": {k2: round(float(np.mean(v)), 4) for k2, v in per_vec_7_head6.items()},
        },
        "unlocked_8of8_onnx": {
            "verdict_recall_overall": round(
                float(np.mean([v for sub in per_vec_8_ox_verdict.values() for v in sub])), 4
            ),
            "verdict_recall_by_vector": ox_vec_recalls,
            "head6_recall_overall": round(float(np.mean([v for sub in per_vec_8_ox_head6.values() for v in sub])), 4),
            "head6_recall_by_vector": ox_head6_recalls,
            "tier1_plus_tier2_coverage_by_vector": ox_cov_recalls,
            "benign_multilink_fp": ben_fp_ox,
            "benign_multilink_fpr": ben_fpr_ox,
            "benign_head6_flagged": ben_h6_flagged,
        },
        "unlocked_8of8_numpy_scanner": {
            "verdict_recall_overall": round(
                float(np.mean([v for sub in per_vec_8_pt_verdict.values() for v in sub])), 4
            ),
            "verdict_recall_by_vector": pt_vec_recalls,
            "head6_recall_overall": round(float(np.mean([v for sub in per_vec_8_pt_head6.values() for v in sub])), 4),
            "head6_recall_by_vector": pt_head6_recalls,
            "tier1_plus_tier2_coverage_by_vector": pt_cov_recalls,
            "benign_multilink_fp": ben_fp_pt,
            "benign_multilink_fpr": ben_fpr_pt,
        },
        "path_challenge": {
            "total": len(PATH_CHALLENGE_URLS),
            "or_gate_fp": path_challenge_or_gate_fp,
            "verdict_fp": path_challenge_verdict_fp,
            "details": path_challenge_details,
        },
        "verdict_tier_mismatches": verdict_tier_mismatches,
        "pytorch_numpy_onnx_max_logit_diff": round(logit_parity, 8),
        "pytorch_onnx_max_prob_diff": round(max_prob_diff, 8),
        "latency_ms": {
            "phish_median": round(statistics.median(lat_phish_ms), 2),
            "benign_multilink_median": round(statistics.median(lat_ben_ms), 2),
        },
        "cdr_integrity": cdr_checks,
        "gates_passed": gates_passed,
    }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out_dir = args.out_root / f"run_{stamp}_{_git_rev()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "locked_methodology.json").write_text(
        json.dumps(
            {
                "phiusiil_zip_sha256": PHIUSIIL_ZIP_SHA256,
                "phiusiil_csv_sha256": csv_sha,
                "phiusiil_split_manifest_sha256": eval_split_sha,
                "matched_train_run_id": matched_train_run_id,
                "weights_npz_sha256": expected_npz_sha,
                "seed": args.seed,
                "split": "held-out registrable-domain-disjoint PhiUSIIL Test",
                "uri_contract_sha256": _sha256_file(
                    REPO / "production" / "configs" / "uri_lexical_head_v4_contract.json"
                ),
                "uri_onnx_sha256": _sha256_file(REPO / "production" / "models" / "uri_lexical_head_v4.onnx"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    return 0 if gates_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
