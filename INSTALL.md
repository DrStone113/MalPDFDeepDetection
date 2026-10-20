# Windows DEV and REMnux LAB workflow

Daily commands: `.\lab.ps1 status|prepare|test|report`; offline REMnux:
`lab status|run|report|menu`. Start with the [short LAB Runner guide](docs/lab_runner.md).

Run development from `C:\Project\MalPDFDeepDetection` on Windows. Read
[AGENTS.md](AGENTS.md) and the [operating and rollback guide](docs/windows_lab_workflow.md)
before using any LAB command.

## Windows checks

The dedicated `.venv-windows-dev` environment follows `pyproject.toml`; the older
`.venv` is preserved. Source packaging and security self-tests also work with
Python 3.11+ and the standard library alone.

```powershell
.venv-windows-dev/Scripts/python.exe scripts/lab/check_local.py --save
python scripts/security/check_repo_content.py --worktree
python -B scripts/lab/selftest.py
python scripts/lab/labctl.py --help
```

`check_local` checks the index and edited/untracked nonignored files, source AST,
synthetic security regressions, project metadata, dependency consistency and
reviewed imports. It never discovers datasets or opens corpus PDFs. CI uses
`--stdlib-only`, so its source checks do not assert ML dependency readiness.

The hook is stored in `.githooks/pre-commit`. Inspect it before opting in:

```powershell
git config --local core.hooksPath .githooks
```

The repository guard preserves unchanged baseline identities for the two
historical Parquet outputs and four nonempty legacy `.gitkeep` files. New
placeholders must be empty. Reviewed figure PNGs must have the expected header.
Other PDFs, datasets, archives, private keys, unsupported binary content,
symlinks and submodules remain rejected. The guard is a content policy, not a
malware scanner or a complete secret scanner.

## Prepare and inspect

```powershell
python scripts/lab/labctl.py prepare
python scripts/lab/labctl.py status
python scripts/lab/labctl.py audit-check
```

Default `prepare` requires a clean committed checkout. For an explicit existing
commit, `prepare --commit FULL_40_HEX_SHA` checks that immutable Git tree and
excludes every working change. It does not approve the commit for deployment.
Packages and manifests are written under `%TEMP%/malpdf-lab-packages`, with
SHA-256 checksums and no overwrite of differing existing packages.

`status` and `audit-check` require authorized read-only inspection and an already
verified host key. They use only the approved audit identity and fixed endpoint.
They never accept a new host key automatically. `audit-check` probes status,
nonallowlisted `id`, and an empty shell request; forwarding and server privilege
checks remain separate operator checks.

## Permission boundaries

Commit/push, source upload, bootstrap installation, SSHD updates, LAB test
execution, and report retrieval require the applicable explicit approvals.
`labctl.py deploy` remains operator-only in a supervised terminal, with a full
commit confirmation and a separate administrator password. Codex must not call
it or provide its input under the current [AGENTS.md](AGENTS.md) rules.

The default deployed check parses Python AST only. The separately approved
synthetic check runs only the reviewed offline security self-tests with bounds;
it does not run project pytest or real samples. Real-PDF analysis is a separate,
manifested and isolated Level 3 workflow. See the operating guide for the exact
commands, sanitized report schema, approval batch and rollback procedure.

## LAB Runner

Giao diện vận hành ngắn: `.\lab.ps1 status|prepare|test|report` trên Windows;
`lab status|run|report|menu` tại console REMnux sau setup được duyệt.
Xem [hướng dẫn một lệnh](docs/lab_runner.md) cho cài một lần, mode Host-only và
mode ngắt toàn bộ mạng. Source implementation cần được cài/kiểm chứng trên LAB;
không tự thay quyền SSH, bật mạng hoặc chạy PDF thật khi cài.
