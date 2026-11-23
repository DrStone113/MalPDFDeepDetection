"""Real byte-level hard-benign and adversarial evasion stress suite on REMnux."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

import lightgbm as lgb
import numpy as np
import torch
import xgboost as xgb

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from malpdf.features.contract_v3 import FEATURES, RobustTransform  # noqa: E402
from malpdf.models.pdf_transgraph_v3 import (  # noqa: E402
    PDFTransGraphV3,
    TransGraphV3Config,
    extract_graph_summary_features,
    load_v3_weights_npz,
)
from scripts.lab.train_eval_transgraph_v3 import (  # noqa: E402
    REGIME_B_INDICES,
    apply_temperature,
    gather_graph_list_batch,
    prob_to_logits,
    slice_regime_inputs,
)

PROSPECTIVE_THR = 0.0809010898526184


def append_incremental_pdf_bytes(raw: bytes, producer_note: str = "MalPDF Incremental") -> bytes:
    """Append a valid PDF incremental xref update referencing an added /Info object."""
    m_root = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", raw)
    m_size = list(re.finditer(rb"/Size\s+(\d+)", raw))
    m_sx = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", raw))
    if not m_root or not m_size or not m_sx:
        raise ValueError("missing_classic_xref_markers_for_incremental_update")
    root_ref = m_root.group(1).decode("ascii")
    obj_id = int(m_size[-1].group(1))
    prev_sx = int(m_sx[-1].group(1))

    base = raw if raw.endswith(b"\n") else raw + b"\n"
    obj_offset = len(base)
    safe_note = re.sub(r"[^A-Za-z0-9 _.-]", "", producer_note)
    obj_bytes = f"{obj_id} 0 obj\n<< /Producer ({safe_note}) >>\nendobj\n".encode("ascii")
    xref_offset = obj_offset + len(obj_bytes)
    xref_bytes = (
        f"xref\n{obj_id} 1\n{obj_offset:010d} 00000 n \n"
        f"trailer\n<< /Size {obj_id + 1} /Root {root_ref} /Info {obj_id} 0 R /Prev {prev_sx} >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return base + obj_bytes + xref_bytes


REMOTE_WORKER_SOURCE = r'''
import hashlib, importlib.util, json, re, shutil, sys
from pathlib import Path
import pikepdf

sys.path.insert(0, "/home/remnux/MalPDFDeepDetection/src")
from malpdf.extraction import extract_pdf
from malpdf.extraction.graph_projection_v2 import project_graph_bundle_v2

spec = importlib.util.spec_from_file_location("contract_v3", "/tmp/malpdf-byte-stress/contract_v3.py")
contract_v3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract_v3)
FEATURES = contract_v3.FEATURES
project_features = contract_v3.project_features

def append_inc(raw, note):
    m_root = re.search(rb"/Root\s+(\d+\s+\d+\s+R)", raw)
    m_size = list(re.finditer(rb"/Size\s+(\d+)", raw))
    m_sx = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", raw))
    root_ref = m_root.group(1).decode("ascii")
    obj_id = int(m_size[-1].group(1))
    prev_sx = int(m_sx[-1].group(1))
    base = raw if raw.endswith(b"\n") else raw + b"\n"
    obj_offset = len(base)
    obj_bytes = f"{obj_id} 0 obj\n<< /Producer ({note}) >>\nendobj\n".encode("ascii")
    xref_offset = obj_offset + len(obj_bytes)
    xref_bytes = (
        f"xref\n{obj_id} 1\n{obj_offset:010d} 00000 n \n"
        f"trailer\n<< /Size {obj_id + 1} /Root {root_ref} /Info {obj_id} 0 R /Prev {prev_sx} >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return base + obj_bytes + xref_bytes

def build_variants(work, ben_src, thr_src):
    specs = []
    # 12 hard-benign real byte variants built from real_benign_document.pdf
    p = work / "benign_original.pdf"
    shutil.copyfile(ben_src, p)
    specs.append(("benign_original", "benign", p))

    for name, lin, objm in (
        ("benign_repacked", False, pikepdf.ObjectStreamMode.preserve),
        ("benign_linearized", True, pikepdf.ObjectStreamMode.preserve),
        ("benign_objstm_packed", False, pikepdf.ObjectStreamMode.generate),
    ):
        dst = work / f"{name}.pdf"
        with pikepdf.open(ben_src) as pdf:
            pdf.save(dst, deterministic_id=True, linearize=lin, object_stream_mode=objm, compress_streams=True)
        specs.append((name, "benign", dst))

    base_b = work / "_base_ben.pdf"
    with pikepdf.open(ben_src) as pdf:
        pdf.save(base_b, object_stream_mode=pikepdf.ObjectStreamMode.disable, deterministic_id=True)
    dst_b_inc = work / "benign_incremental_update.pdf"
    dst_b_inc.write_bytes(append_inc(base_b.read_bytes(), "Benign Incremental Save"))
    base_b.unlink()
    specs.append(("benign_incremental_update", "benign", dst_b_inc))

    dst_acro = work / "benign_acroform_fields.pdf"
    with pikepdf.open(ben_src) as pdf:
        w = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Widget, FT=pikepdf.Name.Tx,
            T=pikepdf.String("ApplicantName"), V=pikepdf.String("Benign Test User"),
            Rect=pikepdf.Array([50, 700, 220, 722]), P=pdf.pages[0].obj,
        ))
        pdf.pages[0].Annots = pikepdf.Array([w])
        pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([w]), DA=pikepdf.String("/Helv 12 Tf 0 g"))
        pdf.save(dst_acro, deterministic_id=True)
    specs.append(("benign_acroform_fields", "benign", dst_acro))

    dst_js = work / "benign_safe_js_alert.pdf"
    with pikepdf.open(ben_src) as pdf:
        js_act = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String('app.alert("Safe test");')))
        pdf.Root.Names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=pikepdf.Array(["SafeNotice", js_act])))
        pdf.save(dst_js, deterministic_id=True)
    specs.append(("benign_safe_js_alert", "benign", dst_js))

    dst_goto = work / "benign_safe_openaction_goto.pdf"
    with pikepdf.open(ben_src) as pdf:
        pdf.Root.OpenAction = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.XYZ, 0, 792, 0])
        pdf.save(dst_goto, deterministic_id=True)
    specs.append(("benign_safe_openaction_goto", "benign", dst_goto))

    dst_uri = work / "benign_uri_links.pdf"
    with pikepdf.open(ben_src) as pdf:
        annots = []
        for k in range(3):
            annots.append(pdf.make_indirect(pikepdf.Dictionary(
                Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([50, 680 - 25 * k, 200, 700 - 25 * k]),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(f"https://example.org/doc/{k}")),
            )))
        pdf.pages[0].Annots = pikepdf.Array(annots)
        pdf.save(dst_uri, deterministic_id=True)
    specs.append(("benign_uri_links", "benign", dst_uri))

    dst_att = work / "benign_embedded_text_file.pdf"
    with pikepdf.open(ben_src) as pdf:
        pdf.attachments["notes.txt"] = b"Benign companion text attachment for stress evaluation.\n"
        pdf.save(dst_att, deterministic_id=True)
    specs.append(("benign_embedded_text_file", "benign", dst_att))

    dst_enc = work / "benign_encrypted_empty_pw.pdf"
    with pikepdf.open(ben_src) as pdf:
        pdf.save(dst_enc, encryption=pikepdf.Encryption(owner="malpdf-owner", user="", R=4), deterministic_id=False)
    specs.append(("benign_encrypted_empty_pw", "benign", dst_enc))

    dst_pad = work / "benign_repaired_xref_padding.pdf"
    with pikepdf.open(ben_src) as pdf:
        for _ in range(25):
            with pikepdf.open(ben_src) as src_copy:
                pdf.pages.extend(src_copy.pages)
        pdf.docinfo["/Keywords"] = "Benign corporate archive padding entry " * 60
        pdf.save(dst_pad, deterministic_id=True)
    with dst_pad.open("ab") as fh:
        fh.write(b"\n% Benign trailing archive padding comment\n" * 64)
    specs.append(("benign_repaired_xref_padding", "benign", dst_pad))

    # 8 adversarial threat evasion byte variants built from real_threat_document.pdf
    tp = work / "threat_original.pdf"
    shutil.copyfile(thr_src, tp)
    specs.append(("threat_original", "threat", tp))

    for name, lin, objm in (
        ("threat_repacked", False, pikepdf.ObjectStreamMode.preserve),
        ("threat_linearized", True, pikepdf.ObjectStreamMode.preserve),
        ("threat_objstm_packed", False, pikepdf.ObjectStreamMode.generate),
    ):
        dst = work / f"{name}.pdf"
        with pikepdf.open(thr_src) as pdf:
            pdf.save(dst, deterministic_id=True, linearize=lin, object_stream_mode=objm, compress_streams=True)
        specs.append((name, "threat", dst))

    base_t = work / "_base_thr.pdf"
    with pikepdf.open(thr_src) as pdf:
        pdf.save(base_t, object_stream_mode=pikepdf.ObjectStreamMode.disable, deterministic_id=True)
    dst_t_inc = work / "threat_incremental_update.pdf"
    dst_t_inc.write_bytes(append_inc(base_t.read_bytes(), "Harmless Incremental Wrapper"))
    base_t.unlink()
    specs.append(("threat_incremental_update", "threat", dst_t_inc))

    dst_t_p50 = work / "threat_padded_50_pages.pdf"
    with pikepdf.open(thr_src) as pdf:
        for _ in range(25):
            with pikepdf.open(ben_src) as src_copy:
                pdf.pages.extend(src_copy.pages)
        pdf.save(dst_t_p50, deterministic_id=True)
    specs.append(("threat_padded_50_pages", "threat", dst_t_p50))

    dst_t_o100 = work / "threat_padded_100_objects.pdf"
    with pikepdf.open(thr_src) as pdf:
        pad_arr = pikepdf.Array([
            pdf.make_indirect(pikepdf.Stream(pdf, f"BT /F1 10 Tf 72 720 Td (Benign padding page {i}) Tj ET".encode("ascii")))
            for i in range(100)
        ])
        pdf.Root["/XBenignPad"] = pad_arr
        pdf.docinfo["/Subject"] = "Padding dilution container " * 40
        pdf.save(dst_t_o100, object_stream_mode=pikepdf.ObjectStreamMode.disable, deterministic_id=True)
    specs.append(("threat_padded_100_objects", "threat", dst_t_o100))

    dst_t_meta = work / "threat_title_metadata_bloat.pdf"
    with pikepdf.open(thr_src) as pdf:
        pdf.docinfo["/Title"] = "Quarterly Compliance Summary Report " * 80
        pdf.docinfo["/Author"] = "Corporate Documentation Team"
        pdf.docinfo["/Subject"] = "Archived administrative metadata block " * 80
        pdf.save(dst_t_meta, deterministic_id=True)
    specs.append(("threat_title_metadata_bloat", "threat", dst_t_meta))
    return specs

def main():
    root = Path("/tmp/malpdf-byte-stress")
    work = root / "generated_variants"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    try:
        specs = build_variants(work, root / "real_benign_document.pdf", root / "real_threat_document.pdf")
        rows = []
        for name, group, path in specs:
            raw_bytes = path.read_bytes()
            sha = hashlib.sha256(raw_bytes).hexdigest()
            bundle = extract_pdf(path, boundary=work, expected_sha256=sha, coalesce_checkpoints=True, include_byte_images=False)
            proj = project_graph_bundle_v2(bundle, sha)
            fields = {
                r["feature_name"]: {
                    "value": r.get("value"),
                    "status": r.get("observation_status"),
                    "scope_complete": r.get("scope_complete"),
                }
                for r in bundle["feature_store"]["records"]
            }
            vec = project_features(fields)
            g = proj["graph"]
            rows.append({
                "id": name,
                "group": group,
                "sha256": sha,
                "bytes": len(raw_bytes),
                "status": bundle["status"],
                "vector_v3": vec,
                "graph": [g["node_features"], g["node_types"], g["edge_src"], g["edge_dst"], g["edge_rel"]],
                "node_count": len(g["node_features"]),
                "edge_count": len(g["edge_src"]),
            })
        out = {"schema_version": 1, "contract": "pdf-tabular-v3", "features": list(FEATURES), "variants": rows}
        print(json.dumps(out, allow_nan=False))
    finally:
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    main()
'''


def _run_remote_generation_and_extraction() -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8", newline="\n") as tmp:
        tmp.write(REMOTE_WORKER_SOURCE.lstrip())
        local_worker = Path(tmp.name)
    try:
        subprocess.run(["ssh", "remnux-lab", "mkdir -p /tmp/malpdf-byte-stress"], check=True)
        for src_path, remote_name in (
            (REPO / "src/malpdf/features/contract_v3.py", "contract_v3.py"),
            (REPO / "tests/fixtures/real_benign_document.pdf", "real_benign_document.pdf"),
            (REPO / "tests/fixtures/real_threat_document.pdf", "real_threat_document.pdf"),
            (local_worker, "_stress_worker.py"),
        ):
            subprocess.run(["scp", str(src_path), f"remnux-lab:/tmp/malpdf-byte-stress/{remote_name}"], check=True)
        res = subprocess.run(
            [
                "ssh",
                "remnux-lab",
                "PYTHONDONTWRITEBYTECODE=1 /home/remnux/MalPDFDeepDetection/.venv/bin/python -B /tmp/malpdf-byte-stress/_stress_worker.py && rm -rf /tmp/malpdf-byte-stress",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
            timeout=300,
        )
        return json.loads(res.stdout)
    finally:
        local_worker.unlink(missing_ok=True)


def score_stress_export(
    payload: dict[str, Any],
    *,
    run_metrics_path: Path,
    art_regime_b_dir: Path,
    prospective_thr: float = PROSPECTIVE_THR,
) -> dict[str, Any]:
    """Score extracted numeric+graph stress variants with frozen Regime B models."""
    metrics_doc = json.loads(run_metrics_path.read_text(encoding="utf-8"))
    models_meta = metrics_doc["regime_b_primary"]["models"]

    rows = payload["variants"]
    if len({r["sha256"] for r in rows}) != len(rows):
        raise ValueError("duplicate_stress_variant_sha256")
    raw_73 = np.asarray([[np.nan if v is None else float(v) for v in r["vector_v3"]] for r in rows], dtype=np.float32)

    with np.load(art_regime_b_dir / "robust_transform.npz", allow_pickle=False) as sc:
        transform = RobustTransform(sc["center"], sc["scale"], sc["available"])
    scaled, miss = transform.transform(raw_73)
    tx, tm, ax, am = slice_regime_inputs(scaled, miss, "regime_b")

    graphs = [r["graph"] for r in rows]
    nx_t, nt_t, ei_t, er_t, gb_t = gather_graph_list_batch(graphs, torch.device("cpu"))
    summary_12 = extract_graph_summary_features(nt_t, ei_t, gb_t, batch_size=len(rows)).numpy()
    x_gbdt = np.concatenate((raw_73[:, REGIME_B_INDICES], summary_12), axis=1)

    probs_by_model: dict[str, np.ndarray] = {}
    cfg = TransGraphV3Config(**json.loads((art_regime_b_dir / "v3_tab_graph_ssl_inv_config.json").read_text(encoding="utf-8")))
    mdl = PDFTransGraphV3(cfg).eval()
    load_v3_weights_npz(mdl, art_regime_b_dir / "v3_tab_graph_ssl_inv.npz", map_location="cpu")
    with torch.inference_mode():
        out = mdl(torch.from_numpy(tx), None, torch.from_numpy(ax), torch.from_numpy(am), nx_t, nt_t, ei_t, er_t, gb_t)
    t_nn = float(models_meta["v3_tab_graph_ssl_inv"]["temperature"])
    probs_by_model["v3_tab_graph_ssl_inv"] = apply_temperature(out["logits"].numpy(), t_nn)
    mod_weights = out["weights"].numpy().tolist()

    xc = xgb.XGBClassifier()
    xc.load_model(str(art_regime_b_dir / "xgboost_v3.json"))
    t_xgb = float(models_meta["xgboost_v3"]["temperature"])
    probs_by_model["xgboost_v3"] = apply_temperature(prob_to_logits(xc.predict_proba(x_gbdt)[:, 1]), t_xgb)

    bst = lgb.Booster(model_file=str(art_regime_b_dir / "lightgbm_v3.txt"))
    t_lgb = float(models_meta["lightgbm_v3"]["temperature"])
    probs_by_model["lightgbm_v3"] = apply_temperature(bst.predict(x_gbdt, raw_score=True), t_lgb)

    scored_rows = []
    for i, r in enumerate(rows):
        idx_map = {n: k for k, n in enumerate(FEATURES)}
        v = r["vector_v3"]
        scored_rows.append(
            {
                "id": r["id"],
                "group": r["group"],
                "sha256": r["sha256"],
                "bytes": r["bytes"],
                "status": r["status"],
                "node_count": r["node_count"],
                "edge_count": r["edge_count"],
                "trigger_counts": {
                    k: v[idx_map[k]]
                    for k in ("lexical_JS", "lexical_JavaScript", "lexical_OpenAction", "lexical_AA", "lexical_AcroForm", "lexical_EmbeddedFile", "lexical_Encrypt", "lexical_URI")
                },
                "probabilities": {m: float(probs_by_model[m][i]) for m in probs_by_model},
                "branch_weights": [float(w) for w in mod_weights[i]],
            }
        )

    ben_rows = [r for r in scored_rows if r["group"] == "benign"]
    thr_rows = [r for r in scored_rows if r["group"] == "threat"]
    summary: dict[str, Any] = {}
    for m in probs_by_model:
        bp = np.asarray([r["probabilities"][m] for r in ben_rows])
        tp = np.asarray([r["probabilities"][m] for r in thr_rows])
        summary[m] = {
            "benign_count": len(ben_rows),
            "threat_count": len(thr_rows),
            "benign_fp_at_prospective": int((bp >= prospective_thr).sum()),
            "benign_fp_at_050": int((bp >= 0.50).sum()),
            "benign_max_prob": float(np.max(bp)),
            "threat_tp_at_prospective": int((tp >= prospective_thr).sum()),
            "threat_tp_at_050": int((tp >= 0.50).sum()),
            "threat_min_prob": float(np.min(tp)),
        }
    return {"prospective_threshold": prospective_thr, "summary": summary, "variants": scored_rows}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real byte-level stress suite on REMnux and score with frozen Regime B v3")
    parser.add_argument("--v3-run", type=Path, default=None)
    parser.add_argument("--v3-art", type=Path, default=None)
    parser.add_argument("--export-out", type=Path, default=REPO / "data/processed/pooled_bulk/offline_provenance/byte_level_stress_v3.json")
    parser.add_argument("--skip-remote", action="store_true")
    parser.add_argument("--prospective-thr", type=float, default=PROSPECTIVE_THR)
    args = parser.parse_args()

    if args.v3_run is None:
        cur = (REPO / "data/processed/pooled_bulk/offline_provenance/current_transgraph_v3_run.txt").read_text(encoding="utf-8").strip()
        args.v3_run = REPO / cur
    run_metrics = args.v3_run / "metrics.json"
    if args.v3_art is None:
        art_rel = json.loads(run_metrics.read_text(encoding="utf-8"))["artifact_directory"]
        args.v3_art = REPO / art_rel / "regime_b"

    if args.skip_remote:
        payload = json.loads(args.export_out.read_text(encoding="utf-8"))
    else:
        payload = _run_remote_generation_and_extraction()
        args.export_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    scored = score_stress_export(payload, run_metrics_path=run_metrics, art_regime_b_dir=args.v3_art, prospective_thr=args.prospective_thr)

    git_rev = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO / f"reports/experiments/byte_level_stress_v3/run_{ts}_{git_rev}"
    out_dir.mkdir(parents=True, exist_ok=True)
    locked = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revision": git_rev,
        "export_sha256": hashlib.sha256(args.export_out.read_bytes()).hexdigest(),
        "run_metrics_sha256": hashlib.sha256(run_metrics.read_bytes()).hexdigest(),
        "prospective_threshold": float(args.prospective_thr),
        "extraction_env": "remnux-lab /tmp/malpdf-byte-stress (deleted after extraction)",
    }
    (out_dir / "locked_methodology.json").write_text(json.dumps(locked, indent=2) + "\n", encoding="utf-8")
    (out_dir / "metrics.json").write_text(json.dumps(scored, indent=2) + "\n", encoding="utf-8")
    print(f"Saved byte-level stress results: {out_dir / 'metrics.json'}")
    print("SUMMARY:", json.dumps(scored["summary"], indent=2))
    for r in scored["variants"]:
        p = r["probabilities"]
        print(f"  {r['id']:30s} [{r['group']:6s}] st={r['status']:16s} nodes={r['node_count']:4d} ssl_inv={p['v3_tab_graph_ssl_inv']:.4f} xgb={p['xgboost_v3']:.4f} lgb={p['lightgbm_v3']:.4f}")


if __name__ == "__main__":
    main()
