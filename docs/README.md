# Documentation index

Technical guides, workflow contracts, and development progress belong in `docs/`.
The [project README](../README.md) provides the overview and navigation.

| Start here | Contents |
| --- | --- |
| [LAB Runner: one-command operation](lab_runner.md) | Windows `lab.ps1`, offline menu, one-time setup and approval boundaries |
| [Restricted unattended LAB gateway](lab_gateway.md) | Separate runner key, pinned lexer profile, sandbox probes and one-time operator installation |
| [Development environment](development.md) | Python versions, installation, Codespaces, and handoff checks |
| [Windows DEV and REMnux LAB](windows_lab_workflow.md) | Source packages, restricted audit SSH, approvals, synthetic checks, sanitized reports and rollback |
| [Workspace layout](workspace_layout.md) | Directory ownership, generated notebooks, maintenance storage, and legacy path contracts |
| [Research workflows](workflows.md) | Cohort preparation, Markov caches, Vision, fusion/stacking, Protocol P/G, static inspection, and offline report parsing |
| [PDF extraction implementation](pdf_extraction.md) | Evidence/feature/coverage contracts, static profiles, plan progress and guarded offline CIC jobs |
| [Static VM extraction](extraction_vm.md) | Concurrent full-partition extraction, VM resource policy and active-worktree provenance |
| [Static plugin SDK](contributing_plugins.md) | Explicit source-pinned parser/decoder/feature contracts, bounded worker integration and synthetic verification |
| [Static event plans](trigger_plans.md) | Document/page/form/XFA/bookmark candidates from exported graph/raw IR, provenance, quotas and runtime uncertainty |
| [Offline LAB handoff](extraction_lab_handoff.md) | Private metadata/runbook package, clean-code gate and VMware-console transition for the locked static PDF job |
| [Research status](research_status.md) | Recorded extractor changes, Kaggle development studies, outcomes, and limitations |
| [Lubuntu migration](lubuntu_migration.md) | Private transfer verification and local environment restoration |

## Agent and Architecture Standards

| Specification | Contents |
| --- | --- |
| [Architecture and Environments](agent_architecture_and_environments.md) | Dual-environment topology (DEV/LAB), SSH config, permissions and data handoff |
| [Workflow and Execution Gates](agent_workflow_and_gates.md) | 5-phase agent workflow, zero-argument `lab run`, pre-staging and handoff checklist |
| [Security and Safe Corpus](agent_security_and_safe_corpus.md) | Untrusted inputs, live malware boundaries, safe synthetic corpora, host-only rules |
| [Engineering and Resilience](agent_engineering_and_resilience.md) | Strict zero comments in Python, bug documentation, extractor states, deserialization safety |
| [Datasets and Provenance](agent_datasets_and_provenance.md) | Protocol G partition manifest, leakage prevention, experiment runs and research log |
| [Bug Knowledge Base & Registry](bugs/README.md) | Deep-dive root cause analyses, anti-regression invariants, and bug catalog (BUG-001+) |

## Evidence and project rules

| Reference | Purpose |
| --- | --- |
| [AGENTS.md](../AGENTS.md) | Safety, partition discipline, provenance, and contribution requirements |
| [PDF extraction proposal](../plans/extract-pdf/plan.md) | Planned extractor design; separate from implemented functionality |
| [Full CIC cohort proposal](../plans/cic_full_cohort.md) | Draft 1 452-sample cohort design; not approved, changes no policy |
| [Research log](../reports/research_log.md) | Append-only register of experiments and maintenance |
| [Experiment reports](../reports/experiments/) | Immutable run evidence |
| [Existing analyses](../reports/analysis/) | Saved feature, pipeline, protocol, and containment analyses |
| [Thesis evidence index](../reports/thesis/thesis_evidence_index.md) | Methodology and result provenance |
| [Thesis limitations](../reports/thesis/limitations.md) | Boundaries on interpretation of saved results |
| [Vietnamese progress report](../reports/progress/progress_report_2026-10-11.html) | Offline presentation with links to saved evidence |

Existing analysis and experiment files remain at their recorded paths to preserve
provenance. Write new technical guidance and development updates in `docs/`;
keep per-run evidence in `reports/` and append maintenance records to the research log.

## Documentation maintenance

On 2026-10-15, the long-form README content was organized into the development,
workflow, and research-status guides above. Existing commands, results, caveats,
and the Vietnamese progress-report link were retained, with Markdown links made
relative to their new locations. This maintenance changes documentation only.
