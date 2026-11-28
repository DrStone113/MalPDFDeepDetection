from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
PROD_DIR = REPO_ROOT / "production"
DEFAULT_BUNDLE_DIR = REPO_ROOT / "artifacts" / "hf_space_bundle"

LFS_RULES = (
    "*.onnx filter=lfs diff=lfs merge=lfs -text",
    "*.pt filter=lfs diff=lfs merge=lfs -text",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_lf(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def copy_clean_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def ensure_onnx_models_exported() -> None:
    want_v4 = (REPO_ROOT / "configs" / "transgraph_v4_contract.json").is_file()
    want_ml_v4 = (REPO_ROOT / "configs" / "multilabel_threat_v4_contract.json").is_file()
    want_uri_v4 = (REPO_ROOT / "configs" / "uri_lexical_head_v4_contract.json").is_file()
    bin_onnx = PROD_DIR / "models" / ("pdf_transgraph_v4.onnx" if want_v4 else "pdf_transgraph_v3.onnx")
    ml_onnx = PROD_DIR / "models" / ("multilabel_threat_net_v4.onnx" if want_ml_v4 else "multilabel_threat_net_v2.onnx")
    uri_onnx = PROD_DIR / "models" / "uri_lexical_head_v4.onnx"
    manifest = PROD_DIR / "configs" / "onnx_manifest.json"
    contract = PROD_DIR / "configs" / ("transgraph_v4_contract.json" if want_v4 else "transgraph_v3_contract.json")
    ml_contract = (
        PROD_DIR
        / "configs"
        / ("multilabel_threat_v4_contract.json" if want_ml_v4 else "multilabel_threat_contract.json")
    )
    uri_contract = PROD_DIR / "configs" / "uri_lexical_head_v4_contract.json"
    required = [bin_onnx, ml_onnx, manifest, contract, ml_contract]
    if want_uri_v4:
        required.extend((uri_onnx, uri_contract))
    need_export = not all(path.is_file() for path in required)
    if not need_export:
        manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
        meta = manifest_doc.get("binary_model") or {}
        ml_meta = manifest_doc.get("multilabel_model") or {}
        uri_meta = manifest_doc.get("uri_lexical_model") or {}
        if (
            meta.get("filename") != bin_onnx.name
            or meta.get("sha256") != _sha256(bin_onnx)
            or ml_meta.get("filename") != ml_onnx.name
            or ml_meta.get("sha256") != _sha256(ml_onnx)
            or (
                want_uri_v4
                and (
                    uri_meta.get("filename") != uri_onnx.name
                    or uri_meta.get("sha256") != _sha256(uri_onnx)
                    or uri_meta.get("contract_sha256") != _sha256_lf(REPO_ROOT / "configs" / uri_contract.name)
                )
            )
        ):
            need_export = True
    if not need_export:
        return
    deploy_dir = str(Path(__file__).resolve().parent)
    if deploy_dir not in sys.path:
        sys.path.insert(0, deploy_dir)
    from export_onnx_models import export_and_verify

    export_and_verify()


def verify_bundle_manifest_integrity(target_dir: Path) -> None:
    manifest_path = target_dir / "configs" / "onnx_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    binary_meta = manifest["binary_model"]
    bin_file = target_dir / "models" / binary_meta["filename"]
    if not bin_file.is_file() or _sha256(bin_file) != binary_meta["sha256"]:
        raise ValueError("hf_bundle_binary_onnx_sha256_mismatch")
    is_v4 = binary_meta["filename"] == "pdf_transgraph_v4.onnx"
    contract_file = target_dir / "configs" / ("transgraph_v4_contract.json" if is_v4 else "transgraph_v3_contract.json")
    if not contract_file.is_file() or _sha256_lf(contract_file) != binary_meta["contract_sha256"]:
        raise ValueError("hf_bundle_contract_sha256_mismatch")
    if is_v4:
        for stale_rel in (
            Path("models/pdf_transgraph_v3.onnx"),
            Path("models/pdf_transgraph_v2.onnx"),
        ):
            stale_path = target_dir / stale_rel
            if stale_path.exists():
                stale_path.unlink()
        conf_file = target_dir / "configs" / "conformal_calibration_v4.json"
        expected_conf = binary_meta.get("conformal_sha256")
        if not conf_file.is_file() or (expected_conf and _sha256_lf(conf_file) != expected_conf):
            raise ValueError("hf_bundle_conformal_v4_sha256_mismatch")

    ml_meta = manifest.get("multilabel_model") or {}
    ml_filename = str(ml_meta.get("filename") or "")
    ml_file = target_dir / "models" / ml_filename
    if not ml_filename or not ml_file.is_file() or _sha256(ml_file) != ml_meta.get("sha256"):
        raise ValueError("hf_bundle_multilabel_onnx_sha256_mismatch")
    if ml_filename == "multilabel_threat_net_v4.onnx":
        ml_c_name = str(ml_meta.get("contract_filename") or "multilabel_threat_v4_contract.json")
        ml_c_file = target_dir / "configs" / ml_c_name
        if not ml_c_file.is_file() or _sha256_lf(ml_c_file) != ml_meta.get("contract_sha256"):
            raise ValueError("hf_bundle_multilabel_v4_contract_sha256_mismatch")
        for stale_ml_rel in (
            Path("models/multilabel_threat_net_v2.onnx"),
            Path("configs/multilabel_threat_contract.json"),
        ):
            stale_ml_path = target_dir / stale_ml_rel
            if stale_ml_path.exists():
                stale_ml_path.unlink()
        bundle_src = str(target_dir / "src")
        if bundle_src not in sys.path:
            sys.path.insert(0, bundle_src)
        from malpdf.models.v4_graph_numpy import EXPECTED_MULTILABEL_HEAD_IDS_V4, validate_multilabel_v4_contract_np
        from malpdf.scanner.uri_head import validate_uri_lexical_contract

        validate_multilabel_v4_contract_np(json.loads(ml_c_file.read_text(encoding="utf-8")))
        uri_meta = manifest.get("uri_lexical_model") or {}
        uri_filename = str(uri_meta.get("filename") or "")
        uri_file = target_dir / "models" / uri_filename
        uri_c_name = str(uri_meta.get("contract_filename") or "uri_lexical_head_v4_contract.json")
        uri_c_file = target_dir / "configs" / uri_c_name
        if not uri_filename or not uri_file.is_file() or _sha256(uri_file) != uri_meta.get("sha256"):
            raise ValueError("hf_bundle_uri_onnx_sha256_mismatch")
        if not uri_c_file.is_file() or _sha256_lf(uri_c_file) != uri_meta.get("contract_sha256"):
            raise ValueError("hf_bundle_uri_contract_sha256_mismatch")
        validate_uri_lexical_contract(json.loads(uri_c_file.read_text(encoding="utf-8")))
        import os
        import subprocess

        smoke_env = {**os.environ, "MALPDF_REVIEWED_FIXTURES": str(REPO_ROOT / "tests" / "fixtures")}
        smoke_code = (
            "import json, sys; from pathlib import Path; "
            f"b = Path({str(target_dir)!r}); sys.path[:0] = [str(b), str(b / 'src')]; "
            "from onnx_engine import ONNXMalPDFScannerEngine; "
            "from onnx_taxonomy import ONNXThreatTaxonomyClassifier; "
            "from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes; "
            "sc = ONNXMalPDFScannerEngine(model_path=b/'models'/'pdf_transgraph_v4.onnx', "
            "scaler_path=b/'configs'/'tabular_scaler.json', manifest_path=b/'configs'/'onnx_manifest.json'); "
            "sc.taxonomy = ONNXThreatTaxonomyClassifier(contract_path=b/'configs'/'multilabel_threat_v4_contract.json', "
            "onnx_path=b/'models'/'multilabel_threat_net_v4.onnx', manifest_path=b/'configs'/'onnx_manifest.json', uri_head=sc.uri_head); "
            "assert sc.weights_loaded and sc.taxonomy.ml_weights_loaded and sc.taxonomy.is_v4 and sc.uri_head.model_loaded and sc.uri_head.backend == 'onnx'; "
            "from malpdf.cdr.engine import _get_uri_lexical_scorer; cdr_uri = _get_uri_lexical_scorer(); "
            "assert cdr_uri is not None and cdr_uri.model_loaded and cdr_uri.backend == 'onnx'; "
            "assert sum(1 for h in sc.taxonomy.label_defs if h.get('model_flag_enabled', True)) == 8; "
            "rb = sc.scan_bytes(load_real_benign_bytes(), explain=True); "
            "rt = sc.scan_bytes(load_real_threat_bytes(), explain=True); "
            "assert rb.verdict == 'BENIGN' and rt.verdict == 'MALICIOUS'; "
            "assert rb.threat_taxonomy['classification_source'] == 'multilabel_neural_model_v4'; "
            "assert rt.threat_taxonomy['classification_source'] == 'multilabel_neural_model_v4'; "
            "assert rb.threat_taxonomy['model_flagged_count'] == 0; "
            f"assert tuple(h['id'] for h in rb.threat_taxonomy['ml_label_predictions']) == {EXPECTED_MULTILABEL_HEAD_IDS_V4!r}; "
            "assert rt.threat_taxonomy['detected_count'] >= 4"
        )
        subprocess.run([sys.executable, "-c", smoke_code], check=True, env=smoke_env)
    if not (target_dir / "sidecar_9router.py").is_file():
        raise ValueError("hf_bundle_missing_sidecar_9router")
    if not (target_dir / "9router_space" / "hf_supervisor.mjs").is_file():
        raise ValueError("hf_bundle_missing_hf_supervisor_mjs")


def prepare_bundle(target_dir: Path) -> None:
    ensure_onnx_models_exported()
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    legacy_artifacts_dir = target_dir / "artifacts"
    if legacy_artifacts_dir.exists():
        shutil.rmtree(legacy_artifacts_dir)

    prod_root_files = [
        "app.py",
        "web_service.py",
        "sidecar_9router.py",
        "onnx_engine.py",
        "onnx_taxonomy.py",
        "requirements.txt",
    ]
    for fname in prod_root_files:
        src_file = PROD_DIR / fname
        if not src_file.is_file():
            raise FileNotFoundError(f"Missing production file: {src_file}")
        shutil.copy2(src_file, target_dir / fname)

    sup_dst_dir = target_dir / "9router_space"
    if sup_dst_dir.exists():
        shutil.rmtree(sup_dst_dir)
    sup_dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PROD_DIR / "9router_space" / "hf_supervisor.mjs", sup_dst_dir / "hf_supervisor.mjs")

    copy_clean_tree(PROD_DIR / "configs", target_dir / "configs")
    shutil.copy2(
        REPO_ROOT / "configs" / "pdf_signature_rules.json", target_dir / "configs" / "pdf_signature_rules.json"
    )
    for conf_name in ("conformal_calibration_v4.json", "conformal_calibration_v3.json"):
        conf_src = REPO_ROOT / "configs" / conf_name
        if conf_src.is_file():
            shutil.copy2(conf_src, target_dir / "configs" / conf_name)
    copy_clean_tree(PROD_DIR / "models", target_dir / "models")
    copy_clean_tree(REPO_ROOT / "src" / "malpdf", target_dir / "src" / "malpdf")
    verify_bundle_manifest_integrity(target_dir)

    gitattr_path = target_dir / ".gitattributes"
    existing_lines: list[str] = []
    if gitattr_path.is_file():
        existing_lines = gitattr_path.read_text(encoding="utf-8").splitlines()
    existing_text = "\n".join(existing_lines)
    updated = list(existing_lines)
    for rule in LFS_RULES:
        prefix = rule.split()[0] + " "
        if prefix not in existing_text:
            updated.append(rule)
    gitattr_path.write_text("\n".join(updated).rstrip() + "\n", encoding="utf-8")

    print(f"Prepared ONNX production Hugging Face Space bundle at: {target_dir}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dir", type=Path, default=DEFAULT_BUNDLE_DIR)
    args = parser.parse_args()
    prepare_bundle(args.target_dir)


if __name__ == "__main__":
    main()
