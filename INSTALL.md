# Security patch installation (Windows local workspace)

These files are a **proposal** to copy into `C:\Project\MalPDFDeepDetection`. Nothing has been applied to the Windows host, GitHub or REMnux.

1. Inspect/merge `AGENTS.md` and three new files into the repository paths shown in this bundle. If those paths already exist, compare before replacing.
2. From Windows PowerShell in the repository, run `python scripts/security/check_repo_content.py`. It checks **all staged/tracked indexed blobs**, so it may identify pre-existing files that need review, rather than silently passing. It intentionally rejects any tracked `.npy`, `.parquet`, `.safetensors` and many binary formats: those belong outside Git.
3. Once the script is reviewed and passing, opt in to the local Git hook with `git config --local core.hooksPath .githooks`. Git for Windows can execute the shell hook using its bundled shell; ensure `python` is available on PATH.
4. Review the workflow and branch ruleset before pushing. In GitHub, configure the `repository-content-guard` job as a required check for `main` (where supported) and disable force pushes / unauthorized bypasses.
5. Do not grant Codex unrestricted SSH access: the Git hook and CI cannot stop an agent from executing `ssh` or `scp`. Use restricted REMnux SSH credentials and appropriate firewall rules separately.

The gate does not guarantee that Python code, Git history, secrets, images or user-supplied content is safe. It checks current indexed content, not historical objects, untracked files, actual SSH operations, or off-repository data.
