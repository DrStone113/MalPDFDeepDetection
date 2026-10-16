"""Verified agent lifecycle using a disposable Python socket process, no keys."""

import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile

import pytest

from malpdf.extraction import local_agent


@pytest.fixture
def agent_process(monkeypatch, request):
    if not hasattr(os, "pidfd_open"):
        pytest.skip("Linux pidfd required by optional local-agent action")
    options = getattr(request, "param", {})
    script = '''import ctypes,os,signal,socket,sys
libc=ctypes.CDLL(None)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
if libc.prctl(15,sys.argv[2].encode(),0,0,0): raise SystemExit(2)
if libc.prctl(4,None,0,0,0): raise SystemExit(2)
path=sys.argv[1]
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.bind(path);s.listen(1)
def stop(*args):
    s.close()
    if sys.argv[3]=='remove' and os.path.exists(path): os.unlink(path)
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
print('READY',flush=True)
while True: signal.pause()
'''
    # Keep AF_UNIX paths short, independent of pytest's long basetemp path.
    with tempfile.TemporaryDirectory(prefix="malpdf_agent_") as directory:
        path = Path(directory) / "s"
        process = subprocess.Popen([sys.executable, "-I", "-c", script, str(path),
            options.get("name", "ssh-agent"), "keep" if options.get("keep_socket") else "remove"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([process.stdout], [], [], 5)[0], "Fixture startup deadline"
            assert process.stdout.readline().strip() == "READY"
            monkeypatch.setenv("SSH_AGENT_PID", str(process.pid))
            monkeypatch.setenv("SSH_AUTH_SOCK", str(path))
            monkeypatch.setenv("GH_TOKEN", "synthetic_fixture_keep")
            monkeypatch.setattr(local_agent, "require_offline_lab", lambda attested: None)
            yield process, path
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            process.stdout.close(); process.stderr.close()


def test_real_verified_process_exits_socket_removed_other_credentials_preserved(agent_process):
    process, path = agent_process
    agent = local_agent.probe_local_agent()
    assert agent is not None and process.poll() is None
    try:
        agent.stop()
        assert process.wait(timeout=3) == 0 and not path.exists()
        assert "SSH_AUTH_SOCK" not in os.environ and "SSH_AGENT_PID" not in os.environ
        assert os.environ["GH_TOKEN"] == "synthetic_fixture_keep"
    finally:
        agent.close()
    assert agent.pidfd == -1


@pytest.mark.parametrize("pid", ["", "0", "1", "-2", "not_a_pid", "123456789012345"])
def test_invalid_pid_never_opens_or_signals(monkeypatch, pid):
    monkeypatch.setenv("SSH_AGENT_PID", pid)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/synthetic_missing_agent")
    monkeypatch.setattr(local_agent.os, "pidfd_open", lambda *a: pytest.fail("Invalid PID"))
    assert local_agent.probe_local_agent() is None


@pytest.mark.parametrize("agent_process", [{"name": "other_process"}], indirect=True)
def test_other_process_name_is_never_stopped(agent_process):
    process, _ = agent_process
    assert local_agent.probe_local_agent() is None
    assert process.poll() is None and os.environ.get("SSH_AUTH_SOCK")


def test_unrelated_socket_is_never_cleared_after_stopping_local_process(agent_process, monkeypatch):
    process, path = agent_process
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
        other_path = path.with_name("other")
        other.bind(str(other_path)); other.listen(1)
        monkeypatch.setenv("SSH_AUTH_SOCK", str(other_path))
        agent = local_agent.probe_local_agent(); assert agent is not None
        try:
            with pytest.raises(ValueError, match="socket remains"):
                agent.stop()
            assert process.wait(timeout=3) == 0 and os.environ["SSH_AUTH_SOCK"] == str(other_path)
        finally:
            agent.close()


def test_other_uid_is_not_accepted(agent_process, monkeypatch):
    process, _ = agent_process
    uid = os.getuid()
    monkeypatch.setattr(local_agent.os, "getuid", lambda: uid + 1)
    assert local_agent.probe_local_agent() is None and process.poll() is None


def test_selection_change_before_stop_preserves_process_and_environment(agent_process, monkeypatch):
    process, _ = agent_process
    agent = local_agent.probe_local_agent(); assert agent is not None
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/changed_synthetic_socket")
    try:
        with pytest.raises(ValueError, match="selection changed"):
            agent.stop()
        assert process.poll() is None and os.environ["SSH_AUTH_SOCK"] == "/tmp/changed_synthetic_socket"
    finally:
        agent.close()


def test_console_guard_is_rechecked_before_signalling(agent_process, monkeypatch):
    process, _ = agent_process
    agent = local_agent.probe_local_agent(); assert agent is not None
    def refuse(*a): raise ValueError("Offline LAB required")
    monkeypatch.setattr(local_agent, "require_offline_lab", refuse)
    try:
        with pytest.raises(ValueError, match="Offline LAB"):
            agent.stop()
        assert process.poll() is None and os.environ.get("SSH_AUTH_SOCK")
    finally:
        agent.close()


def test_shutdown_timeout_preserves_agent_environment(agent_process, monkeypatch):
    process, _ = agent_process
    agent = local_agent.probe_local_agent(); assert agent is not None
    monkeypatch.setattr(local_agent.signal, "pidfd_send_signal", lambda *a: None)
    monkeypatch.setattr(local_agent.select, "select", lambda *a: ([], [], []))
    try:
        with pytest.raises(ValueError, match="shutdown not confirmed"):
            agent.stop()
        assert process.poll() is None and os.environ.get("SSH_AUTH_SOCK")
    finally:
        agent.close()


@pytest.mark.parametrize("agent_process", [{"keep_socket": True}], indirect=True)
def test_surviving_socket_keeps_environment_blocked(agent_process):
    process, path = agent_process
    agent = local_agent.probe_local_agent(); assert agent is not None
    try:
        with pytest.raises(ValueError, match="socket remains"):
            agent.stop()
        assert process.wait(timeout=3) == 0 and path.exists()
        assert os.environ.get("SSH_AUTH_SOCK")
    finally:
        agent.close()


def test_exited_process_and_missing_socket_clear_only_stale_variables(agent_process):
    process, path = agent_process
    process.terminate(); assert process.wait(timeout=3)==0
    assert not path.exists()
    assert local_agent.probe_local_agent() is None
    assert local_agent.clear_stale_agent() is True
    assert 'SSH_AUTH_SOCK' not in os.environ and 'SSH_AGENT_PID' not in os.environ
    assert os.environ['GH_TOKEN']=='synthetic_fixture_keep'


@pytest.mark.parametrize('case',['live','live_missing_socket','existing_socket','dangling_socket','permission','selection_change','socket_appears','offline_guard'])
def test_stale_cleanup_preserves_unknown_live_or_changed_state(agent_process,monkeypatch,case):
    process,path=agent_process
    if case not in {'live','live_missing_socket'}:
        process.terminate();process.wait(timeout=3)
    if case=='live_missing_socket':path.unlink()
    if case=='existing_socket':path.write_text('synthetic placeholder')
    if case=='dangling_socket':path.symlink_to(path.with_name('missing_target'))
    if case=='permission':
        def denied(*a):raise PermissionError('synthetic')
        monkeypatch.setattr(local_agent.os,'pidfd_open',denied)
    if case=='selection_change':
        def changed(*a):
            monkeypatch.setenv('SSH_AUTH_SOCK',str(path.with_name('changed')))
            raise ProcessLookupError('synthetic ESRCH')
        monkeypatch.setattr(local_agent.os,'pidfd_open',changed)
    if case=='socket_appears':
        def appeared(*a):
            path.write_text('synthetic appeared')
            raise ProcessLookupError('synthetic ESRCH')
        monkeypatch.setattr(local_agent.os,'pidfd_open',appeared)
    if case=='offline_guard':
        def blocked(*a):raise ValueError('Offline LAB required')
        monkeypatch.setattr(local_agent,'require_offline_lab',blocked)
        with pytest.raises(ValueError,match='Offline LAB'):local_agent.clear_stale_agent()
    else:
        assert local_agent.clear_stale_agent() is False
    assert os.environ.get('SSH_AUTH_SOCK') and os.environ['SSH_AGENT_PID']==str(process.pid)
    assert os.environ['GH_TOKEN']=='synthetic_fixture_keep'
    if case in {'live','live_missing_socket'}:assert process.poll() is None


@pytest.mark.parametrize('pid',['','0','1','-2','not_a_pid','123456789012345'])
def test_stale_cleanup_invalid_selection_never_checks_pid_or_clears(monkeypatch,pid):
    monkeypatch.setenv('SSH_AGENT_PID',pid);monkeypatch.setenv('SSH_AUTH_SOCK','/tmp/synthetic_missing_agent')
    monkeypatch.setattr(local_agent.os,'pidfd_open',lambda *a:pytest.fail('Invalid selection'))
    assert local_agent.clear_stale_agent() is False
    assert os.environ['SSH_AUTH_SOCK']=='/tmp/synthetic_missing_agent' and os.environ['SSH_AGENT_PID']==pid
