# Agent Workflow and Execution Gates

This document defines the standard agent operating cycle, human gates, zero-argument operator execution trigger, and completion verification procedures for `MalPDFDeepDetection`.

## 1. Default Agent Workflow

The standard agent workflow proceeds through five sequential phases:

```
[Phase 1: Windows Baseline]
  ↳ Local source edits, static checks & synthetic tests
        │
[Phase 2: Autonomous LAB Staging via SSH]
  ↳ Deploy release tarball, update gateway/runner, stage job manifest
        │
[Phase 3: Strict Human Gate]
  ↳ Agent halts prior to running real malware extraction
        │
[Phase 4: Zero-Argument Trigger]
  ↳ Operator runs `lab run` in REMnux console
        │
[Phase 5: Autonomous Post-Run Analysis]
  ↳ Agent pulls sanitized metrics/diagnostics to Windows for refinement
```

### Phase 1: Local Windows Baseline
Inspect `git status`, local source, tests, and configurations. Implement code changes and run local synthetic unit tests exclusively in the Windows checkout.

### Phase 2: Autonomous LAB Preparation via SSH
Connect autonomously via SSH to REMnux (alias `remnux-lab` using `~/.ssh/id_ed25519_remnux`) to perform all setup, staging, and verification tasks without requiring per-step operator intervention:
- Deploy source updates, bootstrap packages, and snapshot tarballs from Windows to REMnux.
- Install, upgrade, and configure gateway policy and runner helpers (`setup_gateway.py --install`, `setup_runner.py --install`) via passwordless `sudo` over SSH.
- Verify runtime dependencies, virtual environment health, systemd services/timers, and parser toolchains.
- Generate, update, or maintain the safe structural test corpus (`data/safe_samples/`).
- Run synthetic tests, parser unit tests, and structural edge-case tests on REMnux.
- **Pre-stage and queue the active offline job:** Transfer the source archive and manifest, verify releases, and queue the job target under `/var/lib/malpdf/jobs/<job_id>` (`queued.json`).

### Phase 3: Strict Human Gate for Real / Suspicious PDFs
Whenever a task targets **real, unverified, or suspicious malware samples**, the agent must pause immediately before invoking the parser or extractor on those samples.
- The operator is NEVER asked to run installation scripts, copy files, transfer keys, or type complex commands. The agent handles 100% of preparation autonomously via SSH.
- Because the agent has already pre-staged and queued the active job on REMnux, the operator does not need to enter job IDs, file paths, or complex flags.

### Phase 4: Zero-Argument Operator Trigger
The operator executes the single pre-staged runner command inside the REMnux terminal:
- Inside REMnux terminal / console:
  ```bash
  lab run
  ```
  *(or `lab menu` for interactive TUI)*
- Note: Windows `.\lab.ps1` is strictly for staging and status checks (e.g., `.\lab.ps1 prepare` or `.\lab.ps1 status`); it never executes raw PDF analysis.

### Phase 5: Autonomous Post-Run Analysis
Following operator execution, the agent autonomously fetches sanitized diagnostics, stack traces, and feature schemas from REMnux, identifies any extractor failures, and refines the codebase on Windows.

---

## 2. Zero-Argument Operator Trigger Protocol

When an extraction run on **real or untrusted PDF samples** is prepared:
1. The agent stages all inputs, manifests, environment variables, and timeout wrappers on REMnux.
2. The agent arms the active job runner (`lab run` points directly to the prepared manifest).
3. The agent outputs a clear summary of what will be processed (sample count, parser targets, output destination).
4. The agent pauses and displays the single trigger command:

```bash
# Inside REMnux terminal / console:
lab run
```

5. The operator presses Enter to execute the command. The agent waits or resumes upon completion to analyze the sanitized results.

---

## 3. Completion and Handoff Checklist

Before concluding any development iteration or handoff:

1. **Verify Windows source state:** Review `git status`, verify changes meet the zero-comment convention, and ensure documentation in `docs/` is up to date.
2. **Run local safe tests:** Execute `pytest tests/` using synthetic fixtures on Windows.
3. **Execute autonomous LAB checks:** Deploy the changes to REMnux via SSH, run the safe synthetic/safe-corpus test suite, and verify extractor stability.
4. **Report status clearly:**
   - Summarize code changes and local verification results.
   - Summarize REMnux safe-corpus extraction outcomes and edge-case handling.
   - If real-sample evaluation is required, pre-load the active job manifest and inform the operator that they only need to run `lab run` in the REMnux console.
