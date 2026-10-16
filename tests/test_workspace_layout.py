"""Workspace routing and provenance checks using synthetic files only."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from malpdf.data.kaggle_notebook import save_generated_notebook
from malpdf.provenance.research_runs import ResearchRun


@pytest.fixture
def repository(tmp_path):
    (tmp_path / ".gitignore").write_text("artifacts/**\nnotebooks/generated/\n")
    source = tmp_path / "src/malpdf/example.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n")
    for command in (["init", "-q"], ["add", "."],
                    ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "commit", "-qm", "Synthetic fixture"]):
        subprocess.run(["git", "-C", str(tmp_path), *command], check=True,
                       capture_output=True)
    source.write_text("VALUE = 2\n")
    return tmp_path


@pytest.mark.parametrize("maintenance", [False, True])
def test_run_records_dirty_source_hashes_without_copying_code(repository, maintenance):
    with ResearchRun(repository, "fixture", {"protocol": "synthetic"},
                     run_id="run_fixture", maintenance=maintenance) as run:
        expected = "artifacts/tmp/maintenance" if maintenance else "artifacts"
        assert run.artifacts == repository / expected / "fixture/run_fixture"
        assert run.state["code_worktree"]["status"] == "dirty"
        hashes = json.loads((run.artifacts / "generating_code_sha256.json").read_text())
        assert hashes == {"src/malpdf/example.py": hashlib.sha256(b"VALUE = 2\n").hexdigest()}
        assert not (run.artifacts / "generating_code").exists()
    assert (run.report / "locked_methodology.json").is_file()
    assert (run.report / "model_comparison.csv").is_file()
    assert json.loads((run.report / "run_summary.json").read_text())["status"] == "completed"
    with pytest.raises(ValueError, match="collision"):
        ResearchRun(repository, "fixture", {}, run_id="run_fixture", maintenance=maintenance)


def test_maintenance_run_refuses_symlinked_storage(repository, tmp_path):
    external = tmp_path / "other"
    external.mkdir()
    (repository / "artifacts").mkdir()
    (repository / "artifacts/tmp").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        ResearchRun(repository, "fixture", {}, run_id="run_link", maintenance=True)
    assert not list(external.iterdir())


def test_generated_notebooks_are_routed_without_overwriting(tmp_path):
    notebook = {"cells": [], "nbformat": 4}
    path = save_generated_notebook(tmp_path, "fixture", "run_fixture", "gpu.ipynb", notebook)
    assert path == tmp_path / "notebooks/generated/fixture/run_fixture/gpu.ipynb"
    assert json.loads(path.read_text()) == notebook
    with pytest.raises(FileExistsError):
        save_generated_notebook(tmp_path, "fixture", "run_fixture", "gpu.ipynb", {})
    assert json.loads(path.read_text()) == notebook


@pytest.mark.parametrize("study, run_id, filename", [
    ("../outside", "run_fixture", "gpu.ipynb"),
    ("fixture", "../outside", "gpu.ipynb"),
    ("fixture", "run_fixture", "../gpu.ipynb"),
    ("fixture", "run_fixture", "gpu.py"),
])
def test_generated_notebooks_refuse_unsafe_destinations(tmp_path, study, run_id, filename):
    with pytest.raises(ValueError, match="Unsafe"):
        save_generated_notebook(tmp_path, study, run_id, filename, {})
    assert not list(tmp_path.iterdir())


def test_generated_notebooks_refuse_symlinked_parent(tmp_path):
    (tmp_path / "notebooks").mkdir()
    external = tmp_path / "other"
    external.mkdir()
    (tmp_path / "notebooks/generated").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        save_generated_notebook(tmp_path, "fixture", "run_fixture", "gpu.ipynb", {})
    assert not list(external.iterdir())


@pytest.mark.parametrize("script", ["19_validate_pdf_evidence_v8.py", "21_validate_pdf_evidence_v9.py"])
@pytest.mark.parametrize("existing", ["directory", "dangling_symlink"])
def test_fresh_validators_preserve_existing_root_environment(tmp_path, monkeypatch, script, existing):
    source = Path(__file__).resolve().parents[1] / "scripts" / script
    spec = importlib.util.spec_from_file_location("validation_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__file__ = str(tmp_path / "scripts" / script)
    module.sys = SimpleNamespace(version_info=(3, 11), executable=sys.executable)
    module.os = SimpleNamespace(environ={}, fsencode=lambda path: b"fixture")
    monkeypatch.setattr(sys, "argv", [script])
    monkeypatch.setattr(module.importlib.metadata, "distributions", lambda: [])
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: pytest.fail("Must refuse before running commands"))
    environment = tmp_path / ".venv"
    if existing == "directory":
        environment.mkdir()
        (environment / "keep.txt").write_text("existing environment")
    else:
        environment.symlink_to(tmp_path / "missing")

    class FakeRun:
        def __init__(self, root, study, methodology, *, maintenance):
            assert maintenance is True
            self.artifacts = root / "artifacts/tmp/maintenance" / study / "run_fixture"
            self.artifacts.mkdir(parents=True)
            self.state = {}

        def __enter__(self):
            return self

        def __exit__(self, *error):
            return False

    module.ResearchRun = FakeRun
    with pytest.raises(ValueError, match="existing environment preserved"):
        module.main()
    if existing == "directory":
        assert (environment / "keep.txt").read_text() == "existing environment"
    else:
        assert environment.is_symlink()
