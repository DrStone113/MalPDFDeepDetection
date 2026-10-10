"""Test the console UI with mocked inputs/processes; no dataset access."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/18_launch_cic_offline.py"
    spec = importlib.util.spec_from_file_location("cic_offline_launcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    return module


def test_cancel_never_launches_job(launcher, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "q")
    def forbidden(*args, **kwargs):
        pytest.fail("Cancelled launcher must never start a job")
    monkeypatch.setattr(launcher.subprocess, "run", forbidden)
    assert launcher.main([]) == 0


@pytest.mark.parametrize("exit_code", [0, 1])
def test_console_attestation_uses_existing_guarded_cli_and_keeps_output(launcher, monkeypatch, exit_code):
    prompts = []
    calls = []
    def answer(prompt):
        prompts.append(prompt)
        return ""
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=exit_code)
    monkeypatch.setattr("builtins.input", answer)
    monkeypatch.setattr(launcher.subprocess, "run", run)
    assert launcher.main([]) == exit_code
    assert calls == [([
        str(launcher.ROOT / ".venv/bin/python"),
        str(launcher.ROOT / "scripts/16_benchmark_cic_static.py"),
        "run", "--prepared-run", launcher.PREPARED_RUN, "--lab-isolated",
    ], {"cwd": launcher.ROOT, "shell": False})]
    assert len(prompts) == 2 and "đóng cửa sổ" in prompts[-1]


def test_check_only_validates_metadata_without_attestation_or_subprocess(launcher, monkeypatch, capsys):
    from malpdf.experiments import cic_static_benchmark
    checked = []
    def load(root, identifier):
        checked.append((root, identifier))
        return [object()] * 64, {"fingerprint": {"code_schema": "synthetic-schema"}}, None
    def forbidden(*args, **kwargs):
        pytest.fail("Metadata check must not attest or launch a job")
    monkeypatch.setattr(cic_static_benchmark, "load_job", load)
    monkeypatch.setattr("builtins.input", forbidden)
    monkeypatch.setattr(launcher.subprocess, "run", forbidden)
    assert launcher.main(["--check"]) == 0
    assert checked == [(launcher.ROOT, launcher.PREPARED_RUN)]
    assert "chưa chạy PDF" in capsys.readouterr().out
