# Protocol G Benchmark & High-Accuracy Evaluation on Full CIC Evasive-PDFMal2022 Corpus

## 1. Experimental Methodology & Invariants

- **Corpus**: Complete 1,452 samples from CIC Evasive-PDFMal2022 (800 malicious, 652 benign).
- **Partitioning**: Protocol G deterministic partition (seed 42):
  - Train: 870 samples (480 malware, 390 benign).
  - Validation: 291 samples (160 malware, 131 benign).
  - Test: 291 samples (160 malware, 131 benign).
- **Leakage Prevention**:
  - Preprocessing and missing-value strategies fitted strictly on the Train split.
  - Validation split used solely for model tuning and selection; Test split evaluated once on frozen estimators.
- **Feature Fusion Portfolio (40 Features)**:
  - 31 Canonical PDF structure metrics: `StartXref`, `XFA`, `Javascript`, `PageNo`, `OpenAction`, `Obj`, `MetadataSize`, `Stream`, `EmbeddedFile`, `XrefLength`, `PdfSize`, `Colors`, `AA`, `JS`, `Xref`, etc.
  - 9 MalPDF Evasion & Anomaly signals: `evasive_timeout_anomaly`, `flag_decompression_ratio_exceeded`, `is_truncated_stream`, `flag_spec_violation_flood`, `flag_excessive_object_graph`, `flag_ast_complexity_truncated`, `raw_entropy`, `raw_prefix_entropy`, `raw_suffix_entropy`.

---

## 2. Comprehensive Benchmark Results

### 2.1 Validation Split (Model Selection)

| Model Architecture | Features Used | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | Brier Loss |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost Fused** | 31 Canonical + 9 Evasion Signals | **0.9863** | **0.9875** | **0.9875** | **0.9874** | **0.9724** | **0.9994** | **0.0105** |
| **Random Forest Fused** | 31 Canonical + 9 Evasion Signals | 0.9828 | 0.9874 | 0.9812 | 0.9843 | 0.9653 | 0.9993 | 0.0144 |
| **Ensemble (Soft Voting)**| 50% XGBoost + 50% RF | **0.9863** | **0.9875** | **0.9875** | **0.9874** | **0.9724** | **0.9993** | **0.0118** |

### 2.2 Test Split (Frozen Evaluation on 291 Held-Out Samples)

| Model Architecture | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | Confusion Matrix (TN / FP / FN / TP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest Fused** | **0.9863 (98.63%)** | **0.9815** | **0.9938** | **0.9876** | **0.9723** | **0.9987** | TN: 128 \| FP: 3 \| FN: 1 \| **TP: 159** |
| **XGBoost Fused** | **0.9828 (98.28%)** | 0.9814 | 0.9875 | 0.9844 | 0.9653 | **0.9992** | TN: 128 \| FP: 3 \| FN: 2 \| **TP: 158** |
| **Ensemble (Soft Voting)**| **0.9828 (98.28%)** | 0.9814 | 0.9875 | 0.9844 | 0.9653 | **0.9990** | TN: 128 \| FP: 3 \| FN: 2 \| **TP: 158** |

---

## 3. Top Predictive Features (Feature Importance)

The decision tree and gradient boosting feature importances demonstrate that detection relies on a combination of structural revision topology and defensive evasion flags:

1. **`StartXref` (53.3%)**: Distinguishes incremental revisions and update streams. Benign files have multi-revision tables (`StartXref >= 2`), whereas packed malware samples present single/tampered tables (`StartXref <= 1`).
2. **`XFA` (8.6%)**: Rich XML form architecture predominantly observed in legitimate corporate documents.
3. **`Javascript` (6.9%)**: Active script count.
4. **`PageNo` (5.1%)**: Document pagination structure.
5. **`OpenAction` (4.0%)**: Automatic document execution triggers.
6. **`evasive_timeout_anomaly` & `raw_entropy`**: Captures payload compression and static analysis denial-of-service attempts.
