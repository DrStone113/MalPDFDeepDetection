"""Stop only the verified local OpenSSH agent selected by the console session."""

from dataclasses import dataclass
import os
from pathlib import Path
import select
import signal
import stat

from malpdf.static.lab_guard import require_offline_lab


def _read(path, cap):
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError("Agent metadata limit")
    return data


@dataclass
class LocalAgent:
    pid: int
    pidfd: int
    socket: Path
    identity: tuple
    proc: Path
    env_pid: str
    env_socket: str

    def close(self):
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1

    def verify(self):
        if self.pidfd < 0 or select.select([self.pidfd], [], [], 0)[0]:
            raise ValueError("Agent no longer alive")
        if os.environ.get("SSH_AGENT_PID") != self.env_pid or os.environ.get("SSH_AUTH_SOCK") != self.env_socket:
            raise ValueError("Agent selection changed")
        process = self.proc / str(self.pid)
        owners = [line.split()[1:] for line in _read(process / "status", 8192).splitlines() if line.startswith(b"Uid:")]
        if (owners != [[str(os.getuid()).encode()] * 4]
                or _read(process / "comm", 64).strip() != b"ssh-agent"):
            raise ValueError("Not the current user's local ssh-agent")
        info = self.socket.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or (info.st_dev, info.st_ino) != self.identity:
            raise ValueError("Agent socket identity changed")

    def stop(self):

        require_offline_lab(True)
        self.verify()

        signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)
        if not select.select([self.pidfd], [], [], 3)[0]:
            raise ValueError("Agent shutdown not confirmed")
        if self.socket.exists() or self.socket.is_symlink():
            raise ValueError("Agent socket remains; environment preserved")
        if os.environ.get("SSH_AGENT_PID") != self.env_pid or os.environ.get("SSH_AUTH_SOCK") != self.env_socket:
            raise ValueError("Agent environment changed; environment preserved")


        os.environ.pop("SSH_AUTH_SOCK", None)
        os.environ.pop("SSH_AGENT_PID", None)


def probe_local_agent(*, proc=Path("/proc")):
    """Read process/socket metadata; no key listing, secret reads or signals."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return None
    pid = os.environ.get("SSH_AGENT_PID", "")
    name = os.environ.get("SSH_AUTH_SOCK", "")
    if not pid.isascii() or not pid.isdecimal() or len(pid) > 10 or int(pid) <= 1:
        return None
    if not name or len(name) > 4096 or "\n" in name or "\r" in name or not Path(name).is_absolute():
        return None
    fd = -1
    try:
        fd = os.pidfd_open(int(pid))
        socket = Path(name)
        info = socket.lstat()
        agent = LocalAgent(int(pid), fd, socket, (info.st_dev, info.st_ino), Path(proc), pid, name)
        agent.verify()
        return agent
    except (OSError, ValueError):
        if fd >= 0:
            os.close(fd)
        return None


def clear_stale_agent():
    """Clear two stale variables only when both the PID and socket are absent.

    Requires offline console attestation. An inaccessible PID/path, live or
    reused PID, existing/dangling socket, or changed selection stays blocked.
    No signals, protocol messages, key reads or credential-file changes.
    """
    if not hasattr(os, "pidfd_open"):
        return False
    pid = os.environ.get("SSH_AGENT_PID", "")
    name = os.environ.get("SSH_AUTH_SOCK", "")
    if not pid.isascii() or not pid.isdecimal() or len(pid) > 10 or int(pid) <= 1:
        return False
    if not name or len(name) > 4096 or "\n" in name or "\r" in name or not Path(name).is_absolute():
        return False
    require_offline_lab(True)
    endpoint = Path(name)
    try:
        if any(parent.is_symlink() for parent in endpoint.parents):
            return False
        endpoint.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    else:
        return False
    try:
        fd = os.pidfd_open(int(pid))
    except ProcessLookupError:
        pass
    except OSError:
        return False
    else:
        os.close(fd)
        return False
    try:
        endpoint.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    else:
        return False
    if os.environ.get("SSH_AGENT_PID") != pid or os.environ.get("SSH_AUTH_SOCK") != name:
        return False
    os.environ.pop("SSH_AUTH_SOCK", None)
    os.environ.pop("SSH_AGENT_PID", None)
    return True
