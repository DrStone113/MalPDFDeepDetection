# REMnux `Lab` VM Rebuild, 1-Way Firewall & Bulk PDF Corpus Acquisition — 2026-11-16

Base commit: `9117c2be55049013325ec96f1aca72b1b65ab9cf`.

## Summary of Architecture & Infrastructure Changes

Rebuilt an isolated analysis VM (`Lab` at `C:\VirtualMachine\Lab\Lab.vmx`, Ubuntu `24.04.5 LTS`, `8 vCPU`, `8192 MiB` RAM) replacing the damaged prior REMnux disk, deployed a stateful 1-way firewall + Phase 1/2 NAT controller, restored the LAB gateway/runner toolchain, acquired an additional `<= 20 GB` bulk raw PDF batch, and updated repository documentation and [AGENTS.md](../../AGENTS.md) so architecture and progress tracking stay current.

### 1. Rebuilt `Lab` VM Topology & 1-Way Isolation
- **Interfaces (`Lab` guest):** Host-only VMnet1 is assigned statically to `ens34` (`192.168.217.10/24`, VMware `ethernet1`); Phase-1 `NAT` is `ens33` (VMware `ethernet0`), kept `down` in `phase2_locked` outside clean initial provisioning/corpus downloads.
- **Stateful 1-Way Firewall ([scripts/lab/lab_firewall.sh](../../scripts/lab/lab_firewall.sh)):**
  - Installed at `/usr/local/sbin/malpdf-firewall` with boot unit `malpdf-firewall.service`.
  - Dynamically detects the Host-Only NIC holding `192.168.217.10/` (`ens34`) and secondary NAT NIC(s) (`ens33`).
  - `phase2` (boot default, `phase2_locked`): brings `NAT` `down`, flushes its addresses, sets IPv6 `INPUT`/`FORWARD`/`OUTPUT` to `DROP`, sets IPv4 `INPUT`/`FORWARD`/`OUTPUT` to `DROP`, permits `ESTABLISHED,RELATED` and inbound TCP/22 `NEW` only from `192.168.217.1/32` on Host-Only, and drops all VM-initiated `NEW` outbound on Host-Only and RFC1918 ranges.
  - `phase1` (`phase1_nat`): activates `NAT` via `/etc/netplan/60-malpdf-nat.yaml` (`activation-mode: manual`) exclusively on clean VM states while keeping Host-Only outbound blocked.
- **LAB Harness Updates:**
  - [scripts/lab/lab_vmware.py](../../scripts/lab/lab_vmware.py): updated `VMX` to `C:/VirtualMachine/Lab/Lab.vmx` and added `'host_only_nat_disconnected'` classification when the secondary NAT adapter has `startConnected = "FALSE"`.
  - [scripts/lab/lab_jobs.py](../../scripts/lab/lab_jobs.py): added `_interface_active()` in `host_only_network()` so admin-down/carrierless unconfigured secondary NICs do not fail Host-Only checks, while `offline` PDF runs continue to enforce 0 connected NICs and no active SSH session via [src/malpdf/static/lab_guard.py](../../src/malpdf/static/lab_guard.py).
  - Updated VMware isolation selftests in [scripts/lab/selftest_offline.py](../../scripts/lab/selftest_offline.py) and [scripts/lab/selftest_workflow.py](../../scripts/lab/selftest_workflow.py).
- **Migrated Baseline, Runtime & Services on `Lab`:**
  - Copied `data/raw` (`1,452` CIC baselines, `1.3 GB`), `data/processed` (`2.5 GB`), and `third_party/arlington-pdf-model` (`610` TSV tables, pinned commit `b7d880b7a3d3c8f505c025f17763397475e90503`) read-only from `C:\VirtualMachine\Remnux-disk1.vmdk` before detaching that disk (`scsi0:1.present` absent).
  - Created Python `3.12.3` `.venv` with CPU PyTorch and declared dev dependencies; installed read-only/gateway/runner helpers (`/etc/malpdf/runner.json` -> `.venv/bin/python`).

### 2. Bulk PDF Corpus Acquisition (`data/raw/bulk_20261116` on `Lab`)
- Implemented [scripts/lab/acquire_bulk_pdf_corpus.py](../../scripts/lab/acquire_bulk_pdf_corpus.py) and synthetic unit tests in [tests/test_bulk_pdf_acquisition.py](../../tests/test_bulk_pdf_acquisition.py) (`resumable` HTTP streaming, 3 parallel workers, path-traversal/symlink/pickle filtering, streaming archive extraction with immediate `.zip`/`.7z` deletion, `<= 20,000,000,000`-byte queue cap).
- Executed on `Lab` under temporary `phase1` NAT and automatically locked back to `phase2_locked` (`errors: []`):
  - **Queue cap:** `19,401,175,744` B (`queue_manifest.json` <= `20,000,000,000` B); `0` `.zip`/`.7z`/`.part`/`.pkl` left in `_work/`.
  - **Disk usage after extraction:** `20,815,395,078` B in `data/raw/bulk_20261116` (`pdfs/`: `43,854` files / `20,764,431,073` B; `metadata/`: `35,478,928` B; `/dev/sda2`: `50G`/`98G` used, `44G` free).
  - **Manifest (`manifest.csv`, `52,049` lines = header + `52,048` extracted PDFs):**
    - `zenodo_3464032_malware_2017` (`2017-12-05-PDF.7z`): `12,761` PDFs (`12,761` unique; `1,452` overlap CIC `1,452`; `2,629` net new vs `21,414` baseline).
    - `vapd_v5` (`vapd_src.zip`): `19,335` PDFs (`19,288` unique; `0` overlap CIC `1,452`; `25` net new vs `21,414` baseline; `41` unsafe paths/pickles skipped).
    - `govdocs1_sample` (`sample/` + `index/` parquets): `5,000` unique PDFs (`0` overlap CIC `1,452`; `4,992` net new vs `21,414` baseline).
    - `safedocs` (`15` smallest `cc-main-2021-31-pdf-untruncated` ZIPs): `14,952` unique PDFs (`993`–`999`/ZIP; `0` overlap CIC `1,452` or baseline; `14,952` net new).
  - **Batch deduplication totals (`summary.json`):** `43,854` unique batch SHA-256s; `42,402` net new unique vs `1,452` CIC SHA-256s; **`22,586` net new unique raw PDFs vs full `21,414`-file baseline**.
  - **Skipped sources recorded:** `cic_pdfmal_2022` (`tabular_only_no_raw_pdfs_published`), plus existing `zenodo_3464032_clean_9000` (`683,344,001` B) and `zenodo_3464032_malware_2011` (`129,118,746` B) preserved on `Lab`.

### 3. Snapshot & Documentation Sync
- **Snapshot:** User captured clean baseline VMware snapshot (`snapshot_count: 1`, `Remnux-disk1.vmdk` detached). Post-snapshot live checks on `Lab`: `malpdf-firewall status` = `phase2_locked` (`nat_up: false`), `lab status` = `host_only_ready: true`, `lab preflight` = `credentials: []`, `pending_jobs: 0`.
- **Remaining VMX item:** `Lab.vmx` does not yet set `ethernet0.startConnected = "FALSE"` on the `NAT` adapter, so Windows `lab_vmware.isolation()` currently reports `network_configuration: "unverified"` (`reason: "operator_isolation_review_required"`). Uncheck *Connect at power on* on the NAT adapter (or remove it when powered off) and refresh the baseline snapshot when convenient.
- **Governance & Docs Updated:** Added continuous status/progress/architecture sync policy to [AGENTS.md](../../AGENTS.md), [docs/agent_workflow_and_gates.md](../../docs/agent_workflow_and_gates.md), and [docs/agent_datasets_and_provenance.md](../../docs/agent_datasets_and_provenance.md); updated NIC/topology specs in [docs/agent_architecture_and_environments.md](../../docs/agent_architecture_and_environments.md), [docs/agent_security_and_safe_corpus.md](../../docs/agent_security_and_safe_corpus.md), [docs/lab_runner.md](../../docs/lab_runner.md), and [docs/README.md](../../docs/README.md).

## Verification

| Scope | Measured result |
| --- | --- |
| Windows `.venv-windows-dev` (`Python 3.11.16`) `scripts/lab/check_local.py` | `passed`: `409` AST files (`0` errors), `237/237` synthetic tests (`selftest_offline.py` + `selftest_workflow.py`), `dependency_checks`, `pip_check`, `diff_check`, and `repository_content_guard` passed |
| Windows `scripts/security/check_repo_content.py` | Passed against `HEAD` (`2486` tracked index files checked) |
| Windows `.venv-windows-dev` targeted pytest (`test_bulk_pdf_acquisition.py`, `test_cape_lab_design.py`, `test_lab_halt_reporting.py`) | `49 passed in 0.75s` |
| Windows `.venv-windows-dev` including `tests/test_cic_static_benchmark.py` (earlier run) | `114 passed, 10 failed in 6.42s` — all `10` failures in `test_cic_static_benchmark.py` (`TypeError`/`KeyError`/`worker_error` in Windows local worker profiling) |
| Remote REMnux `Lab` gateway (`.\lab.ps1 verify`, `.\lab.ps1 doctor`, `.\lab.ps1 test -Mode synthetic`) | `verified: true`, `status: "ready"`, `passed` (`409` syntax files, `6/6` synthetic cases; `job_id: 3eeb9f79f4bf222534fad89fbc47c13568afc5df59e81fea9de7ec53ef3dff60`) |
| Post-snapshot live `Lab` runtime (`malpdf-firewall status`, `lab status`, `lab preflight`) | `phase2_locked` (`host_only_if: "ens34"`, `nat_ifs: ["ens33"]`, `nat_up: false`), `host_only_ready: true`, `credentials: []`, `pending_jobs: 0` |
| Bulk acquisition `Lab` verification (`data/raw/bulk_20261116`) | `0` errors; `manifest.csv` = `52,049` lines (`52,048` PDFs); `pdfs/` = `43,854` unique files; `_work/` has `0` `.zip`/`.7z`/`.part`/`.pkl` |

## Remaining Operational Limits

- No new real-PDF feature extraction or model training was executed on `Lab` (`pending_jobs: 0`); classifier metrics remain N/A.
- `Lab.vmx` still lacks `ethernet0.startConnected = "FALSE"` (`lab_vmware.isolation()` reports `network_configuration: "unverified"` despite `snapshot_count: 1`).
- Windows working tree has uncommitted infrastructure, acquisition, and documentation changes ready for review and commit.
