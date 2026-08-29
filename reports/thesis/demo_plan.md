# Safe Thesis Demonstration Plan

Use only a benign synthetic PDF or a harmless, instructor-approved document created for the demonstration. Do not open, execute, render, upload, or submit suspicious PDFs.

1. Show the thesis evidence index and state the Protocol P / Protocol G distinction before showing metrics.
2. Run `malpdf inspect` on the approved benign file to demonstrate bounded static parsing and the 41-feature output; do not use a desktop previewer.
3. Explain the 38-feature compatibility gate. If the local deployment artifact has been built from the documented full-data procedure, run `malpdf scan` on that same benign file and present its score as a model prediction, not proof of safety or maliciousness.
4. Show the Protocol G XGBoost table and the TreeSHAP global bar plot, saying that contributions are descriptive rather than causal.
5. Show the architecture diagram and explicitly identify the dynamic/CAPE/hybrid nodes as future design-only components. Do not demonstrate a sandbox, submit a sample, or claim live dynamic analysis.

If the benign file fails parsing or the compatibility gate, report that fact rather than replacing feature values or selecting a more favourable result.
