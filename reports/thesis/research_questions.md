# Research Questions

The project addresses static, tabular malicious-PDF detection. It does not claim dynamic sandbox efficacy.

1. How accurately can five fixed classical models classify the verified RIT-PDFMal-2026 static feature table under a paper-aligned row-level split (Protocol P)?
2. How do those measurements change when identical 41-dimensional feature vectors are prevented from crossing partitions (Protocol G)?
3. Is the direction of the Protocol P–G difference stable across the five predeclared split seeds 42–46 when model randomness remains fixed?
4. How closely does the fixed XGBoost configuration follow the paper's reported Table 6 macro metrics under the separately defined row-level 10-fold CV attempt?
5. Which static features contribute most to the completed Protocol G XGBoost model according to native TreeSHAP, without treating those contributions as causal explanations?
6. On the fixed Protocol G split, how do two fixed tabular neural baselines compare with the historical XGBoost reference, subject to single-split and hardware-determinism limitations?

The completed work cannot answer external, temporal, file-identity-disjoint, live-sandbox, hybrid, or real-world deployment performance questions.
