# Methodology Summary

## Data and terminology

The verified local RIT-PDFMal-2026 CSV has 24,337 rows, 41 predictive static features, and `Label` (0=benign, 1=malicious). It has 13,235 benign and 11,102 malicious rows. `Acroform`, `Colors`, and `BaseEncoding` are constant zero; `RichMedia` is near-constant. Values such as `contains_text=-1`, `pages=0`, and out-of-specification `pdf_ver` values remain source semantics, not imputed missing values.

The CSV has no original PDF hash column. Consequently, this project calls equality of all 41 predictor values an **identical 41-dimensional feature vector** or **feature-equivalent group**. It never calls these duplicate PDF files without file hashes.

## Evaluation protocols

| Protocol | Assignment | Purpose and interpretation boundary |
| --- | --- | --- |
| P — paper-aligned reproduction attempt | 75/25 stratified, row-level random split, seed 42 | Uses all 41 features and a drop-three-constant variant. Seed 42 and incomplete settings are project assumptions; it is not exact paper reproduction. |
| G — feature-vector-disjoint generalization | Deterministic 60/20/20 train/validation/test split, seed 42; duplicate groups stay together | Train 14,602 / validation 4,868 / test 4,867 rows; 8,600 / 3,386 / 3,385 groups. It establishes zero identical-vector overlap, not PDF identity, chronology, external validity, or real-world performance. |
| CV10 — paper-aligned XGBoost | `KFold(10, shuffle=True, random_state=42)` across all 24,337 rows | Separate from P/G; 20 fits across all-41 and drop-three variants. It is row-level and permits equal vectors in different folds. |

Every reported operational metric uses Label=1 as malicious-positive and is named `precision_malicious`, `recall_malicious`, or `f1_malicious`. Paper comparisons use separately named macro metrics due to the prior metric-semantics audit.

## Model and explanation procedure

The classical study freezes Logistic Regression, Random Forest, Decision Tree, Gaussian Naive Bayes, and XGBoost configuration objects before execution. No benchmark result is hyperparameter-tuned against a test set. The Logistic Regression scaler is fit to training rows only. Tree models and Gaussian NB receive the recorded semantic values without scaling, clipping, or imputation. Metrics use continuous scores for ROC-AUC and PR-AUC whenever the model supplies them.

The explanation study retrains the fixed G-drop3constant XGBoost model only on saved training rows, first checks that historical test metrics reproduce, then uses native XGBoost `pred_contribs=True` on the fixed test partition. It verifies margin/probability reconstruction. TreeSHAP ranking describes this model's contributions only.

## Implemented-versus-planned architecture

```mermaid
flowchart LR
    PDF[Untrusted PDF bytes] --> EX[Safe static extractor]
    EX --> GATE[38-feature compatibility gate]
    GATE --> STATIC[Static XGBoost detector\nprobability, threshold, local TreeSHAP]
    STATIC --> ROUTE[Static-to-dynamic routing policy]
    ROUTE -. future approved laboratory .-> CAPE[Isolated CAPEv2 laboratory]
    CAPE -. future sanitized report only .-> DYN[Dynamic schema / classifier]
    DYN -. future .-> HYBRID[Hybrid decision]

    classDef implemented fill:#d9ead3,stroke:#38761d,color:#000;
    classDef planned fill:#eeeeee,stroke:#666,stroke-dasharray: 5 5,color:#000;
    class PDF,EX,GATE,STATIC,ROUTE implemented;
    class CAPE,DYN,HYBRID planned;
```

Green nodes are implemented static/offline components. Gray dashed nodes are planned or design-only. Dynamic schema parsing is implemented for already-produced, harmless/sanitized reports, but live sandbox execution, a dynamic classifier, and hybrid evaluation are not implemented.
