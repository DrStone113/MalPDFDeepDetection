# AGENTS.md — MalPDFDeepDetection

Authoritative specification index and operational boundaries for AI agents and developers. Detailed guides are maintained in `docs/`.

## 1. Quick Reference & Policy Lookup

| Domain | Core Directive | Detailed Specification |
| --- | --- | --- |
| **Architecture & Environments** | Windows DEV (`C:\Project\MalPDFDeepDetection`) is source of truth with CUDA. REMnux LAB (`192.168.217.10`) is isolated untrusted analysis VM. Transport via VMnet1 Host-only SSH (`remnux-lab`). | [Architecture & Environments](docs/agent_architecture_and_environments.md) |
| **Agent Operating Cycle** | 5-phase workflow: Windows baseline → Autonomous SSH staging → Strict human gate → Zero-argument trigger (`lab run`) → Autonomous post-run analysis. | [Workflow & Execution Gates](docs/agent_workflow_and_gates.md) |
| **Human Gate & Triggers** | Agent autonomously stages manifest & queues jobs under `/var/lib/malpdf/jobs/<job_id>`. Operator executes only `lab run` in REMnux console for real malware runs. | [Workflow & Execution Gates](docs/agent_workflow_and_gates.md) |
| **Security & Malware Boundaries** | Windows DEV never receives or opens raw PDFs, payloads, or shellcode. Dynamic detonation is prohibited in standard LAB. Untrusted inputs are strictly segregated. | [Security & Safe Corpus](docs/agent_security_and_safe_corpus.md) |
| **Resilience & Safe Corpus** | Build edge-case PDFs via `scripts/lab/prepare_safe_corpus.py` under `data/safe_samples/`. Safe alerts only (`app.alert`), clean reference corpora (veraPDF, Govdocs1). | [Security & Safe Corpus](docs/agent_security_and_safe_corpus.md) |
| **Engineering Conventions** | Strict ZERO comments in Python code (`src/malpdf/`, `scripts/`, `tests/`). Document all bugs and anti-regression invariants in `docs/bugs/`. Clean tracking. | [Engineering & Resilience](docs/agent_engineering_and_resilience.md), [Bug Registry](docs/bugs/README.md) |
| **Extractor Contracts** | Parsers classify outcomes as `complete`, `partial`, or `failed`. Must catch corrupt xref, circular refs, and nested streams without worker crashes. | [Engineering & Resilience](docs/agent_engineering_and_resilience.md) |
| **Deserialization Security** | Strict ban on `pickle.load`, `joblib.load`, `dill`, and `numpy.load(allow_pickle=True)`. Use safe numpy loading, Parquet/Arrow, and Safetensors. | [Engineering & Resilience](docs/agent_engineering_and_resilience.md) |
| **Dataset Disciplines** | Protocol G deterministic split (seed `42`). Fit normalizers strictly on train split. Immutable run records in `reports/experiments/` with `locked_methodology.json`. | [Datasets & Provenance](docs/agent_datasets_and_provenance.md) |
| **Repository Guardrails** | Automated pre-commit hooks and CI guards (`scripts/security/check_repo_content.py`) block untracked/staged PDFs, archives, binaries, and secrets. | [Security & Safe Corpus](docs/agent_security_and_safe_corpus.md) |
| **Completion Checklist** | Verify zero comments in Python, pass local `pytest tests/`, run autonomous remote checks over SSH, provide structured summary before operator trigger. | [Workflow & Execution Gates](docs/agent_workflow_and_gates.md) |

## 2. Standing Autonomous SSH Authorizations

The agent connects to REMnux via `ssh remnux-lab` without human confirmation for:
- Environment and toolchain health checks (`git status`, `python3 --version`, disk, venv).
- Code deployment, bootstrapping, and gateway/runner setup (`setup_gateway.py`, `setup_runner.py`) using passwordless `sudo`.
- Generating safe structural samples (`data/safe_samples/`).
- Running synthetic and parser test suites on REMnux.
- Pre-staging and queueing offline jobs (`queued.json`).
- Fetching structured, non-executable artifacts (metrics JSON, sanitized traces, numeric matrices).

## 3. Strict Non-Negotiable Invariants

1. **Malware Isolation:** Never open, extract, or preview untrusted/raw PDFs or payloads on Windows DEV.
2. **Zero Python Comments:** Never write or leave comments in Python code across `src/malpdf/`, `scripts/`, or `tests/`. Intent must be expressed through naming, types, and external markdown documentation.
3. **Zero Operator Burden:** Never ask the operator to copy files, install packages, or enter complex arguments. The operator only triggers `lab run` in the REMnux console.
4. **No Unsafe Deserialization:** Never use `pickle`, `joblib`, `dill`, or `allow_pickle=True`.
5. **Editing Boundary:** All code editing occurs in the Windows repository; never edit tracked source directly on REMnux.