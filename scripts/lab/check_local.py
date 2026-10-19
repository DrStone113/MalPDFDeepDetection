"""Run reviewed source-only checks without discovering or processing datasets."""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import tomllib

from lab_contract import MAX_FILE, safe_path

REPO = Path(__file__).resolve().parents[2]


def command(args: list[str], timeout: int = 120) -> bytes:
    result = subprocess.run(args, cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise ValueError(f"Check failed (exit {result.returncode}): {' '.join(args)}")
    return result.stdout


def source_syntax() -> int:
    names = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).split(b"\0")
    count = 0
    for encoded in sorted(set(names) - {b""}):
        name = encoded.decode("utf-8", "strict")
        if not safe_path(name) or not name.endswith(".py"):
            continue
        path = REPO / name
        if not path.exists():
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents) or path.stat().st_size > MAX_FILE:
            raise ValueError(f"Unsafe source path/size: {name}")
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=name)
        except (SyntaxError, UnicodeError, OSError) as exc:
            raise ValueError(f"Source AST failed: {name}: {type(exc).__name__}") from None
        count += 1
    if not count:
        raise ValueError("No Python source checked")
    return count


def dependency_versions(metadata: dict) -> dict:
    from packaging.requirements import Requirement
    versions = {}
    required = metadata["project"]["dependencies"] + metadata["project"]["optional-dependencies"]["dev"]
    for declaration in required:
        requirement = Requirement(declaration)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        actual = importlib.metadata.version(requirement.name)
        if actual not in requirement.specifier:
            raise ValueError(f"Declared dependency version mismatch: {requirement.name}")
        versions[requirement.name] = actual
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdlib-only", action="store_true", help="CI source checks only; dependency/import checks remain not_checked")
    parser.add_argument("--save", action="store_true", help="Save local verification evidence under ignored artifacts/tmp/maintenance/lab_workflow")
    args = parser.parse_args()
    steps = {}
    now = datetime.now(timezone.utc)
    data = {"schema_version": 1, "generated_utc": now.isoformat(), "environment": "windows_dev" if sys.platform == "win32" else "ci_or_local_source_check", "python": sys.version.split()[0], "steps": steps, "lab_execution": "not_run", "real_pdf_processing": "not_run", "dependency_checks": "not_checked"}
    result = 0
    try:
        data["commit"] = command(["git", "rev-parse", "HEAD"]).decode("ascii").strip()
        data["dirty"] = bool(command(["git", "status", "--porcelain"]).strip())
        command([sys.executable, "scripts/security/check_repo_content.py", "--worktree"])
        steps["repository_content_guard"] = "passed"
        command(["git", "diff", "--check"])
        steps["diff_check"] = "passed"
        data["ast_file_count"] = source_syntax()
        steps["ast_syntax"] = "passed"
        metadata = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        steps["project_metadata"] = "passed"
        summary = json.loads(command([sys.executable, "-B", "scripts/lab/selftest.py", "--json"], timeout=90))
        if set(summary) != {"total", "passed", "failed", "skipped"} or summary["failed"]:
            raise ValueError("Synthetic regressions failed")
        data["synthetic_tests"] = summary
        steps["synthetic_security"] = "passed"
        if not args.stdlib_only:
            data["dependency_versions"] = dependency_versions(metadata)
            steps["declared_dependency_versions"] = "passed"
            command([sys.executable, "-m", "pip", "check"])
            steps["pip_check"] = "passed"
            command([sys.executable, "-c", "import malpdf, catboost, esprima, joblib, lightgbm, matplotlib, numpy, pandas, pikepdf, pyarrow, fitz, pypdf, yaml, sklearn, torch, torchvision, xgboost, pytest, jsonschema"], timeout=60)
            steps["reviewed_imports"] = "passed"
            data["dependency_checks"] = "passed"
        data["status"] = "passed"
    except (OSError, ValueError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as exc:
        data["status"] = "failed"
        data["error"] = str(exc)
        result = 1
    print(json.dumps(data, indent=2, sort_keys=True))
    if args.save:
        folder = REPO / "artifacts/tmp/maintenance/lab_workflow"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / (now.strftime("windows_%Y%m%dT%H%M%S%fZ") + ".json")
        with target.open("x", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(f"Saved local evidence: {target}")
    return result


if __name__ == "__main__":
    sys.exit(main())
