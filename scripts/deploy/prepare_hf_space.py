from __future__ import annotations

import argparse
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


def copy_clean_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def ensure_onnx_models_exported() -> None:
    bin_onnx = PROD_DIR / "models" / "pdf_transgraph_v2.onnx"
    ml_onnx = PROD_DIR / "models" / "multilabel_threat_net_v2.onnx"
    manifest = PROD_DIR / "configs" / "onnx_manifest.json"
    if bin_onnx.is_file() and ml_onnx.is_file() and manifest.is_file():
        return
    deploy_dir = str(Path(__file__).resolve().parent)
    if deploy_dir not in sys.path:
        sys.path.insert(0, deploy_dir)
    from export_onnx_models import export_and_verify

    export_and_verify()


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
    copy_clean_tree(PROD_DIR / "models", target_dir / "models")
    copy_clean_tree(REPO_ROOT / "src" / "malpdf", target_dir / "src" / "malpdf")

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
