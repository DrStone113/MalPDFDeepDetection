# Selective Static Ensemble and Dynamic Routing Analysis

## 1. Objective

Assess fixed XGBoost/FT-Transformer probability fusion and whether validation-locked uncertainty concentrates errors for hypothetical dynamic referral. No PDF, CAPE, dynamic feature, dynamic classifier, or hybrid model is used.

## 2. Base models

The established Protocol G `G-drop3constant` 38-feature XGBoost configuration and fixed FT-Transformer training procedure are reused. XGBoost is reproduced against the historical test record after the validation lock; FT configuration is checked unchanged and trained once with its existing validation-loss stopping procedure.

## 3. Calibration and validation lock

Validation was deterministically stratified into calibration-fit and selection halves. Candidates were none/Platt/isotonic calibration crossed with the declared base/equal/grid-weight fusion family. The locked candidate is `platt` + `weighted_probability_average` with XGBoost weight `0.6`, selected by validation MCC (`0.966984`), then malicious F1. TEST was not provided to the selector.

## 4. Test performance

| model | probability_source | accuracy | precision_malicious | recall_malicious | f1_malicious | f1_macro | roc_auc | pr_auc | mcc | brier | log_loss | ece |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| xgboost | raw established base | 0.976988 | 0.995301 | 0.954054 | 0.974241 | 0.976723 | 0.997079 | 0.997354 | 0.954161 | 0.018062 | 0.072320 | 0.019263 |
| ft_transformer | raw fixed-training base | 0.979453 | 0.990741 | 0.963964 | 0.977169 | 0.979246 | 0.996447 | 0.996691 | 0.958795 | 0.017260 | 0.067260 | 0.009803 |
| validation_selected_ensemble | platt calibration; weighted_probability_average; xgb_weight=0.6 | 0.979453 | 0.995327 | 0.959459 | 0.977064 | 0.979228 | 0.997576 | 0.997794 | 0.958997 | 0.014875 | 0.061508 | 0.019863 |

## 5. Error complementarity and disagreement

| subset | count | benign_count | malicious_count | xgb_correct | ft_correct | both_wrong | mean_xgb_probability | mean_ft_probability | xgb_false_positive | xgb_false_negative | ft_false_positive | ft_false_negative |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| model_disagreement | 110 | 20 | 90 | 49 | 61 | 0 | 0.366807 | 0.499879 | 5 | 56 | 15 | 34 |

## 6. Selective classification

At the predeclared 10% uncertainty-only referral budget, actual referral is `0.1001`, retained coverage `0.8999`, error capture `0.8800`, and false-negative capture `0.9000`. Referred rows are abstained/referred, not counted as corrected.

## 7. Dynamic-routing efficiency

Routing is a hypothetical recommendation only. Static prediction unavailability remains independently referral-capable in the production contract; there are no unavailable rows in this numerical table evaluation.

## 8. Recommended conceptual modes

- FAST: XGBoost-only static prediction; dynamic recommendation only for extraction failure/extreme reviewed policy.
- BALANCED: selected ensemble plus uncertainty/disagreement routing.
- MAX ACCURACY: selected ensemble plus a larger predeclared referral budget. None of these are production guarantees.

## 9. Threats to validity

One Protocol G split and one FT training run remain insufficient for a general ensemble claim. Calibration selection inherits the FT validation-loss training procedure; calibration fitting and candidate selection were separated within validation, but no external calibration set exists. Feature-vector-disjointness is not file identity, temporal, external, or real-world generalization. Dynamic benefits are not measured.

## 10. Future hybrid preparation

A future hybrid vector may contain static ensemble/XGBoost/FT probabilities, disagreement, uncertainty, and only genuinely observed dynamic-schema-v1 fields. This study fabricates none and trains no hybrid model.
