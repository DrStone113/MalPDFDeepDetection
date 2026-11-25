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
    bin_onnx = PROD_DIR / "models" / ("pdf_transgraph_v4.onnx" if want_v4 else "pdf_transgraph_v3.onnx")
    ml_onnx = PROD_DIR / "models" / "multilabel_threat_net_v2.onnx"
    manifest = PROD_DIR / "configs" / "onnx_manifest.json"
    contract = PROD_DIR / "configs" / ("transgraph_v4_contract.json" if want_v4 else "transgraph_v3_contract.json")
    need_export = not all(path.is_file() for path in (bin_onnx, ml_onnx, manifest, contract))
    if not need_export:
        meta = json.loads(manifest.read_text(encoding="utf-8")).get("binary_model") or {}
        if meta.get("filename") != bin_onnx.name or meta.get("sha256") != _sha256(bin_onnx):
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
        "onnx_engine.py",
        "onnx_taxonomy.py",
        "requirements.txt",
    ]
    for fname in prod_root_files:
        src_file = PROD_DIR / fname
        if not src_file.is_file():
            raise FileNotFoundError(f"Missing production file: {src_file}")
        shutil.copy2(src_file, target_dir / fname)

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
