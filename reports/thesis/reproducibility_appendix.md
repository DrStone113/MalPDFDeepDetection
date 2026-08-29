# Reproducibility Appendix

## Environment and data identity

The official project environment is Python 3.11. Historical run metadata records Python 3.11.0 with NumPy 2.4.6, pandas 2.3.3, scikit-learn 1.9, XGBoost 3.2, PyMuPDF 1.26.7, pypdf 5.9, and PyTorch 2.7.1+cu128 where the focused neural comparison used CUDA. The development hardware recorded for the project is Intel Core i5-14400F, NVIDIA GeForce RTX 5060 Ti 8 GB, and 16 GB RAM; environment reports remain the authority for any individual runtime comparison.

The local RIT dataset is `rit-pdfmal-2026.csv`, SHA-256 `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`. Data and fitted model binaries are intentionally ignored by Git. Checksums of metric sources used by this package are generated in [`tables/evidence_source_checksums.csv`](tables/evidence_source_checksums.csv).

## Exact provenance anchors

| Evidence | Generating code SHA | Result SHA / persistent artifact |
| --- | --- | --- |
| Protocol P seed-42 | `3e970ef2df0460fb4a51b10418c9af7564339419` | `ed50bd9e4e9cd0268c9e2359a89a1867dad68095` |
| Multi-seed P vs G | `2147d0a1e12162ac7092fe797260f0c12a5fe3d6` | result provenance in the official aggregate report |
| XGBoost CV10 | `e5cb9bce8eef7bc26ea189d80fdd597fbecc3b43` | result provenance in `reports/experiments/xgb_cv10/seed42/` |
| Static deployment artifact | `439f6f4…` | model manifest result `5e649bc…`; artifact SHA-256 `8aeba9…` |
| CAPE design documentation | `c654f7f0bc4c99ef25428443b75bc0554805d2ff` | design only; no sandbox artifact |

The feature-vector-disjoint Protocol G manifest is immutable and identifies 15,371 feature-equivalent groups. The deployment model uses all 24,337 rows only after evaluation, keeps 38 drop-three-constant features, and uses threshold 0.5. It is not the held-out Protocol G model.

## Rebuild the thesis evidence package

From a checkout containing the committed lightweight reports (but without requiring a dataset or model binary):

```powershell
.\.venv\Scripts\python.exe scripts\build_thesis_evidence.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

The builder reads reports only, verifies selected cross-artifact invariants, writes deterministic CSV tables, and does not fit a model or access a PDF. The dynamic interface is `dynamic-schema-v1` with 21 behavioral fields. The CAPE design records its cited source revision in its own design document; it deliberately contains no submission client or live-run command.
