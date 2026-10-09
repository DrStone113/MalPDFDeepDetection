"""Read-only offline checks; never change the NIC used by the active session."""

import os
from pathlib import Path


def lab_state(sys_net=Path("/sys/class/net"), mounts=Path("/proc/mounts")):
    connected = []
    uncertain = []
    for entry in sys_net.iterdir():
        if entry.name == "lo":
            continue
        try:
            flags = int((entry / "flags").read_text().strip(), 16)
            carrier = (entry / "carrier").read_text().strip()
        except OSError:
            try:
                flags = int((entry / "flags").read_text().strip(), 16)
            except OSError:
                uncertain.append(entry.name)
                continue
            if flags & 1:
                uncertain.append(entry.name)
            continue
        if flags & 1 and carrier != "0":
            connected.append(entry.name)
    shared = []
    for line in mounts.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3 and ("hgfs" in fields[2].lower() or fields[2] in {"vboxsf", "9p", "virtiofs"}):
            shared.append(fields[1])
    return {"uid": os.getuid(), "connected_interfaces": connected,
            "unknown_interfaces": uncertain, "shared_mounts": shared,
            "ssh_session": bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"))}


def require_offline_lab(attested, *, state=None):
    state = lab_state() if state is None else state
    if (attested is not True or state["uid"] == 0 or state["ssh_session"]
            or state["connected_interfaces"] or state["unknown_interfaces"] or state["shared_mounts"]):
        raise ValueError("Offline LAB required: console, disconnected NICs, non-root, no shared mounts; confirm hypervisor clipboard/drag-drop are disabled")
    return state
