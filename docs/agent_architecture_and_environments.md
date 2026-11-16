# Agent Architecture and Environments

This document details the multi-environment architecture, transport layers, SSH permission boundaries, and data handoff contracts for autonomous and operator operations in `MalPDFDeepDetection`.

## 1. Authoritative Architecture and Scope

The project researches malicious PDF detection using static, dynamic, tabular, and image-derived features. The architecture is intentionally partitioned into **two distinct security environments**. A single VM never combines development, GPU training, and untrusted malware inspection.

| Role | Environment | Responsibilities |
| --- | --- | --- |
| **DEV / source of truth** | Windows 11, `C:\Project\MalPDFDeepDetection` | VS Code, Codex, code changes, local Git, GitHub, safe tests, training on approved safe data, CUDA on the Windows NVIDIA GPU |
| **LAB / untrusted-input analysis** | REMnux `Lab` (`C:\VirtualMachine\Lab\Lab.vmx`, Ubuntu 24.04.5 LTS, `.venv` Python 3.12.3), VMware, `/home/remnux/MalPDFDeepDetection` | Isolated inspection of suspicious PDFs, extractor edge-case tests, safe corpus generation, and extraction of controlled diagnostic exports |
| **Transport** | VMware VMnet1 Host-only (`ethernet1` / `ens34` on `Lab`, resolved dynamically by IP), Windows `192.168.217.1` ↔ REMnux `192.168.217.10`; Phase-1 `NAT` adapter (`ethernet0` / `ens33`) kept `down` outside clean Phase-1 installs (`startConnected = "FALSE"` recommended in `Lab.vmx`) | SSH for automated staging, deployment, safe testing, and pre-staged job execution; stateful `iptables` blocks VM-initiated `NEW` outbound connections |
| **Version control** | Local Git on Windows, GitHub `origin` (`DrStone113/MalPDFDeepDetection`) | Primary source history and collaboration; LAB is not the upstream source of truth |

The SSH alias `remnux-lab` (direct endpoint `remnux@192.168.217.10`) is configured with the dedicated private key `~/.ssh/id_ed25519_remnux` and passwordless `sudo` privileges for all automated staging and remote management operations.

**The agent's editing workspace is always the Windows repository.**
- Do not open or operate as a Remote-SSH workspace for ordinary development.
- Do not edit tracked source directly on REMnux.
- Do not use the LAB VM as a CUDA device or presume GPU passthrough is available.

---

## 2. SSH Permissions and Operational Division

```
                      [ Windows Workspace (Agent) ]
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
[ Autonomous Operations (via SSH `remnux-lab`) ]         [ Operator Gate ]
- Remote SSH health checks & environment verification     - Running parsers/extractors
- Code deployment, bootstrap & snapshot synchronization     against raw/suspicious PDFs
  (`setup_gateway.py`, `setup_runner.py`)                 - Network topology changes
- Managing gateway policies & runner helpers via sudo     - Host privilege elevation
- Generating safe structural samples                      - Deleting persistent raw data
- Running syntax/synthetic tests
- Pre-staging & queuing offline jobs (`queued.json`)
- Ingesting sanitized error reports & metrics
```

### Standing Authorization (Autonomous Agent Actions)

The agent is authorized to connect to REMnux via SSH (`remnux@192.168.217.10` or alias `remnux-lab`) using `~/.ssh/id_ed25519_remnux` without human confirmation for:
1. Running read-only health checks (`git status`, `python3 --version`, disk space, process status).
2. Syncing code from Windows to the LAB working directory or creating versioned test snapshots.
3. Managing virtual environments, installing/updating dependencies via `pip`, and checking libraries on REMnux.
4. Installing, verifying, and upgrading lab gateway and runner helpers (`setup_gateway.py --install`, `setup_runner.py --install`) using passwordless `sudo`.
5. Running generator scripts to build safe edge-case test files under `data/safe_samples/`.
6. Running automated tests against synthetic fixtures and the safe edge-case corpus.
7. **Pre-loading jobs:** Staging the job manifest, transferring the release payload, and queuing the job under `/var/lib/malpdf/jobs/<job_id>` so no arguments or paths are needed at execution time.
8. Retrieving and inspecting sanitized diagnostic summaries, exit codes, and structured error logs after an execution.

---

## 3. Hardened SSH Client Defaults

Use the Windows OpenSSH client with disabled agent/X11 forwarding and strict host key checks:

```powershell
ssh -a -x -o ClearAllForwardings=yes -o ForwardAgent=no -o ForwardX11=no -o StrictHostKeyChecking=yes -o PermitLocalCommand=no -o RequestTTY=no remnux@192.168.217.10 "<command>"
```

If the SSH aliases `remnux-lab` and `remnux-lab-audit` are defined in `~/.ssh/config`, ensure they include:

```sshconfig
Host remnux-lab
    HostName 192.168.217.10
    User remnux
    IdentityFile ~/.ssh/id_ed25519_remnux
    IdentitiesOnly yes
    ForwardAgent no
    ForwardX11 no
    ClearAllForwardings yes
    StrictHostKeyChecking yes
    PermitLocalCommand no
    RequestTTY no

Host remnux-lab-audit
    HostName 192.168.217.10
    User malpdf-audit
    IdentityFile ~/.ssh/id_ed25519_malpdf_audit
    IdentitiesOnly yes
    ForwardAgent no
    ForwardX11 no
    ClearAllForwardings yes
    StrictHostKeyChecking yes
    PermitLocalCommand no
    RequestTTY no
    BatchMode yes
```

---

## 4. Data Handoff Protocol (LAB → Windows)

Only structured, non-executable artifacts may be fetched automatically from REMnux to Windows DEV:
- JSON status reports, schema-validated metrics, and summary tables.
- Sanitized error tracebacks (scrubbed of raw binary payloads or decrypted shellcode).
- Numeric feature matrices (e.g., Markov transition arrays, structural token count vectors).

**Strict Negative Invariant:**
Never export raw PDFs, unpacked payloads, arbitrary memory dumps, or raw binary caches to Windows DEV.

---

## 5. Stateful 1-Way Firewall & Phase 1 / Phase 2 NAT Control

Use `scripts/lab/lab_firewall.sh` on REMnux `Lab` (run as `root` via `sudo`) to enforce stateful 1-way Host-Only SSH (dynamically detecting whichever interface holds `192.168.217.10/24` — `ens34` on `Lab` — and managing secondary `NAT` interface `ens33`; see [2026-11-16 Lab VM rebuild report](../reports/progress/lab_vm_rebuild_and_bulk_corpus_2026-11-16.md)):

- `sudo sh scripts/lab/lab_firewall.sh install-boot` — installs `/usr/local/sbin/malpdf-firewall` and enables `malpdf-firewall.service` so every boot/snapshot revert starts in `phase2`.
- `sudo /usr/local/sbin/malpdf-firewall phase2` — brings all non-Host-Only (`NAT`) interfaces `down`, flushes their addresses, drops all IPv6 traffic outside `lo`, and applies atomic IPv4 `iptables-restore` rules (`INPUT`/`FORWARD`/`OUTPUT` default `DROP`, `ESTABLISHED,RELATED` allowed, inbound TCP/22 `NEW` allowed only from `192.168.217.1` on the Host-Only NIC, all VM-initiated `NEW` outbound on the Host-Only NIC and RFC1918 LAN ranges dropped).
- `sudo /usr/local/sbin/malpdf-firewall phase1` — clean-VM setup only: brings up the secondary `NAT` interface via `/etc/netplan/60-malpdf-nat.yaml` (`activation-mode: manual`, `dhcp4: true`) to install packages/datasets while keeping Host-Only and RFC1918 LAN outbound blocked. Return to `phase2` before taking a clean snapshot, and never re-enable `phase1` on a post-PDF VM without reverting to a clean snapshot first.
- `sudo /usr/local/sbin/malpdf-firewall status` — prints JSON showing `host_only_if`, `nat_ifs`, `nat_up`, chain policies, and active mode (`phase2_locked` / `phase1_nat`).
