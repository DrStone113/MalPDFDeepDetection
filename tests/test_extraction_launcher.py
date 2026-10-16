"""Console admission/cancellation and shell transport; synthetic state only."""

import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from malpdf.extraction import jobs, launcher


@pytest.fixture
def ready(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(jobs.os, "environ", {})
    state = {"uid": 1000, "ssh_session": False, "connected_interfaces": [],
             "unknown_interfaces": [], "shared_mounts": []}
    monkeypatch.setattr(jobs, "lab_state", lambda: dict(state))
    monkeypatch.setattr(launcher, "clean_code", lambda root: None)
    monkeypatch.setattr(jobs, "_worker_count", lambda *a: 1)
    lock = {"rows": [{"split": "train"}, {"split": "validation"}],
            "configuration": {"profile": "deep-static"}}
    monkeypatch.setattr(jobs, "load_job", lambda *a: (lock, object()))
    monkeypatch.setattr(jobs, "extract_pdf", lambda *a, **k: pytest.fail("No PDF access in launcher preflight"))
    monkeypatch.setattr(jobs, "run_job", lambda *a, **k: pytest.fail("No job without confirmation"))
    terminal = SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr(launcher, "sys", SimpleNamespace(version_info=(3, 11), stdin=terminal, stdout=terminal))
    return tmp_path, home, state


def test_check_only_never_prompts_claims_or_runs(ready, monkeypatch, capsys):
    root, _, _ = ready
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("Check must not prompt"))
    assert launcher.main(["--prepared-run", "run_fixture", "--check-only"], root=root) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["operator_attested"] is False and out["pdf_bytes_read"] is False
    assert out["execution"] == "not_run"
    assert not (root / "data").exists()


@pytest.mark.parametrize("key,value", [
    ("uid", 0), ("ssh_session", True), ("connected_interfaces", ["fixture"]),
    ("unknown_interfaces", ["fixture"]), ("shared_mounts", ["fixture"]),
])
def test_bad_lab_state_check_only_refuses_without_prompt(ready, monkeypatch, key, value):
    root, _, state = ready
    state[key] = value
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("Blocked launch must not prompt"))
    assert launcher.main(["--prepared-run", "run_fixture", "--check-only"], root=root) == 2
    assert not (root / "data").exists()


@pytest.mark.parametrize("kind", ["codex_home", "codex_repo", "codex_symlink", "env", "agent", "ssh_key"])
def test_credentials_refuse_without_reading_or_echoing_values(ready, monkeypatch, capsys, kind):
    root, home, _ = ready
    if kind in {"env", "agent"}:
        jobs.os.environ["GH_TOKEN" if kind == "env" else "SSH_AUTH_SOCK"] = "SYNTHETIC_PRIVATE_SENTINEL"
    else:
        p = ((root if kind == "codex_repo" else home) / ".codex/auth.json")
        if kind == "ssh_key":
            p = home / ".ssh/id_fixture"
        p.parent.mkdir(parents=True, exist_ok=True)
        if kind == "codex_symlink":
            p.symlink_to(home / "absent")
        else:
            p.write_text("SYNTHETIC_PRIVATE_SENTINEL")
    monkeypatch.setattr(Path, "read_bytes", lambda *a, **k: pytest.fail("No credential content reads"))
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: pytest.fail("No credential content reads"))
    assert launcher.main(["--prepared-run", "run_fixture", "--check-only"], root=root) == 2
    assert "SYNTHETIC_PRIVATE_SENTINEL" not in capsys.readouterr().out
    with pytest.raises(ValueError, match="Credential presence"):
        jobs.require_extraction_lab(True, repository_root=root)


@pytest.mark.parametrize("problem", ["dirty", "ram", "claim", "claim_symlink", "output_symlink", "python"])
def test_admission_and_single_attempt_blocks(ready, monkeypatch, problem):
    root, _, _ = ready
    def denied(*args):
        raise ValueError("synthetic refusal")
    if problem == "dirty":
        monkeypatch.setattr(launcher, "clean_code", denied)
    elif problem == "ram":
        monkeypatch.setattr(jobs, "_worker_count", denied)
    elif problem == "python":
        monkeypatch.setattr(launcher.sys, "version_info", (3, 13))
    else:
        parent = root / "data/processed"
        parent.mkdir(parents=True)
        output = parent / "pdf_extraction"
        if problem == "output_symlink":
            output.symlink_to(root / "missing")
        else:
            output.mkdir()
            claim = output / "run_fixture.claim.json"
            if problem == "claim":
                claim.write_text("{}")
            else:
                claim.symlink_to(root / "missing")
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 2


@pytest.mark.parametrize("answer", ["q", "CHAY TINH", "chay tinh", " "])
def test_nonempty_input_cancels_before_agent_or_job(ready, monkeypatch, answer):
    root, _, _ = ready
    monkeypatch.setattr("builtins.input", lambda *a: answer)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 0
    assert not (root / "data").exists()


@pytest.mark.parametrize("stream", ["stdin", "stdout"])
def test_noninteractive_invocation_cannot_attest(ready, monkeypatch, stream):
    root, _, _ = ready
    monkeypatch.setattr(launcher.sys, stream, SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("No piped confirmation"))
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 2


def test_confirmed_launch_calls_runner_once_and_preserves_outcome(ready, monkeypatch, capsys):
    root, _, _ = ready
    monkeypatch.setattr("builtins.input", lambda *a: "")
    calls = []
    def run(path, identifier, **kwargs):
        calls.append((path, identifier, kwargs))
        return {"status": "completed", "rows": 2, "planned": 2, "run_id": "run_fixture_result"}
    monkeypatch.setattr(jobs, "run_job", run)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 0
    assert calls == [(root, "run_fixture", {"lab_attested": True})]
    assert "run_fixture_result" in capsys.readouterr().out


@pytest.mark.parametrize("error", [ValueError, OSError, RuntimeError, KeyboardInterrupt, EOFError])
def test_failure_or_interrupt_never_retries_or_echoes_private_error(ready, monkeypatch, capsys, error):
    root, _, _ = ready
    monkeypatch.setattr("builtins.input", lambda *a: "")
    calls = []
    def run(*a, **k):
        calls.append(True)
        raise error("SYNTHETIC_PRIVATE_SENTINEL")
    monkeypatch.setattr(jobs, "run_job", run)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == (130 if error in {KeyboardInterrupt, EOFError} else 1)
    assert len(calls) == 1
    assert "SYNTHETIC_PRIVATE_SENTINEL" not in capsys.readouterr().out


def test_metadata_failure_is_sanitized_and_cannot_run(ready, monkeypatch, capsys):
    root, _, _ = ready
    def denied(*a):
        raise ValueError("SYNTHETIC_PRIVATE_SENTINEL")
    monkeypatch.setattr(jobs, "load_job", denied)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 1
    assert "SYNTHETIC_PRIVATE_SENTINEL" not in capsys.readouterr().out


@pytest.mark.parametrize("exit_code", [0, 17])
def test_shell_wrapper_quotes_paths_keeps_credentials_and_exit_code(tmp_path, exit_code):
    root = tmp_path / "fixture with spaces"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    original = Path(__file__).resolve().parents[1] / "scripts/launch_pdf_extraction.sh"
    wrapper = scripts / original.name
    shutil.copyfile(original, wrapper)
    sentinel = root / "sentinel.py"
    sentinel.write_text('import json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"threads":[os.environ[k] for k in ("OPENBLAS_NUM_THREADS","OMP_NUM_THREADS","MKL_NUM_THREADS")],"credential_preserved":os.environ.get("GH_TOKEN")=="synthetic-fixture"}))\nsys.exit('+str(exit_code)+')\n')
    python = root / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(sentinel)) + ' "$@"\n')
    python.chmod(0o700)
    result = subprocess.run(["/bin/sh", str(wrapper), "--prepared-run", "run_fixture", "--check-only"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "GH_TOKEN": "synthetic-fixture"})
    assert result.returncode == exit_code
    data = json.loads(result.stdout)
    assert data["args"] == ["-I", str(scripts / "24_launch_pdf_extraction.py"), "--prepared-run", "run_fixture", "--check-only"]
    assert data["threads"] == ["1", "1", "1"] and data["credential_preserved"]


def test_shell_wrapper_missing_environment_refuses_without_downloading(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    wrapper = scripts / "launch_pdf_extraction.sh"
    shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts/launch_pdf_extraction.sh", wrapper)
    result = subprocess.run(["/bin/sh", str(wrapper), "--prepared-run", "run_fixture"], capture_output=True, text=True)
    assert result.returncode == 1 and "thieu .venv" in result.stdout
    assert not (tmp_path / ".venv").exists()


@pytest.mark.parametrize("case", ["success", "cancel", "unknown", "failure", "other_credential", "network", "check_only", "noninteractive"])
def test_optional_agent_cleanup_never_bypasses_remaining_guards(ready, monkeypatch, case):
    from malpdf.extraction import local_agent
    root, _, state = ready
    jobs.os.environ.update(SSH_AUTH_SOCK="synthetic_socket", SSH_AGENT_PID="12345")
    if case == "other_credential":
        jobs.os.environ["GH_TOKEN"] = "synthetic_other_credential"
    if case == "network":
        state["connected_interfaces"] = ["synthetic"]
    if case == "noninteractive":
        monkeypatch.setattr(launcher.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    calls = []
    class Agent:
        def stop(self):
            calls.append("stop")
            if case == "failure": raise ValueError("synthetic stop failure")
            jobs.os.environ.pop("SSH_AUTH_SOCK"); jobs.os.environ.pop("SSH_AGENT_PID")
        def close(self): calls.append("close")
    def probe():
        calls.append("probe")
        return None if case == "unknown" else Agent()
    monkeypatch.setattr(local_agent, "probe_local_agent", probe)
    answers = iter(["q"] if case == "cancel" else ["", "q"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    def run(*a, **k):
        calls.append("run")
        assert k == {"lab_attested": True}
        return {"status": "completed"}
    monkeypatch.setattr(jobs, "run_job", run)
    args = ["--prepared-run", "run_fixture"] + (["--check-only"] if case == "check_only" else [])
    expected = 2 if case in {"check_only", "noninteractive"} else (1 if case == "failure" else 0)
    assert launcher.main(args, root=root) == expected
    assert ("run" in calls) == (case == "success")
    assert ("stop" in calls) == (case in {"success", "failure", "other_credential"})
    if case in {"network", "check_only", "noninteractive"}: assert not calls
    if case not in {"success", "other_credential"}: assert jobs.os.environ.get("SSH_AUTH_SOCK")
    if case == "other_credential": assert jobs.os.environ.get("GH_TOKEN") == "synthetic_other_credential"
    if "stop" in calls: assert "close" in calls


def test_connected_launcher_waits_for_manual_disconnect_then_one_enter_runs(ready, monkeypatch, capsys):
    from malpdf.extraction import local_agent
    root, _, state = ready
    state["connected_interfaces"] = ["synthetic"]
    jobs.os.environ.update(SSH_AUTH_SOCK="synthetic_socket", SSH_AGENT_PID="12345")
    calls = []
    class Agent:
        def stop(self):
            assert not state["connected_interfaces"]
            calls.append("stop")
            jobs.os.environ.pop("SSH_AUTH_SOCK"); jobs.os.environ.pop("SSH_AGENT_PID")
        def close(self): calls.append("close")
    monkeypatch.setattr(local_agent, "probe_local_agent", lambda: Agent())
    def confirm(*a):
        assert not calls  # No agent stop or job before operator's Enter.
        state["connected_interfaces"] = []
        return ""
    monkeypatch.setattr("builtins.input", confirm)
    def run(*a, **k):
        calls.append("run")
        assert k == {"lab_attested": True}
        return {"status": "completed"}
    monkeypatch.setattr(jobs, "run_job", run)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 0
    assert calls == ["stop", "close", "run"]
    out = capsys.readouterr().out
    assert "Tự ngắt" in out and "CHAY TINH" not in out and "DUNG AGENT" not in out


@pytest.mark.parametrize("key,value", [
    ("ssh_session", True), ("connected_interfaces", ["synthetic"]),
    ("unknown_interfaces", ["synthetic"]), ("shared_mounts", ["synthetic"]),
])
def test_enter_while_still_blocked_waits_without_agent_or_job(ready, monkeypatch, key, value):
    from malpdf.extraction import local_agent
    root, _, state = ready
    state[key] = value
    jobs.os.environ.update(SSH_AUTH_SOCK="synthetic_socket", SSH_AGENT_PID="12345")
    monkeypatch.setattr(local_agent, "probe_local_agent", lambda: pytest.fail("No agent action before isolation"))
    answers = iter(["", "", "q"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 0
    assert jobs.os.environ["SSH_AUTH_SOCK"] == "synthetic_socket"
    assert not (root / "data").exists()


def test_network_reconnect_during_confirmation_waits_instead_of_running(ready, monkeypatch):
    root, _, state = ready
    answers = iter(["", "q"])
    def confirm(*a):
        state["connected_interfaces"] = ["synthetic_reconnected"]
        return next(answers)
    monkeypatch.setattr("builtins.input", confirm)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 0
    assert not (root / "data").exists()


def test_dirty_code_detected_after_enter_never_runs(ready, monkeypatch):
    root, _, _ = ready
    def confirm(*a):
        def dirty(*a): raise ValueError("synthetic dirty code")
        monkeypatch.setattr(launcher, "clean_code", dirty)
        return ""
    monkeypatch.setattr("builtins.input", confirm)
    assert launcher.main(["--prepared-run", "run_fixture"], root=root) == 2
    assert not (root / "data").exists()
