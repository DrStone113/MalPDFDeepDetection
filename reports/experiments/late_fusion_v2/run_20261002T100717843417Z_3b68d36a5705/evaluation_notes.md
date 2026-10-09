# Late fusion v2: Protocol G seed 42

Generating source: `3b68d36a570531058543170e2debc7d5805e6bb5` on local branch `codex/late-fusion-v2-20261002`; clean committed worktree at invocation. The main working tree was preserved. A fresh Python 3.11 environment passed all 290 tests and pip check before official evaluation.

Validation was divided by deterministic stratified groups into 1,056 meta-fit, 1,239 calibration-fit and 2,573 selection rows. Meta learners and Platt calibrators used separate fit roles; all choices used selection MCC, malicious F1, then declared order. No chosen model was refit on selection or full validation. The validation lock was saved before decoding/evaluating the test probability tables once.

Validation selected candidate 7: the Platt-calibrated XGBoost control, with XGB/FT weights 1/0. Logistic Regression stacking and other weighted averages were evaluated as validation candidates. Vision weights 0.1/0.25 are unavailable because there are no official aligned RIT Vision predictions; the CVE smoke model is ineligible.

| Model | F1 malicious | MCC | Brier | Log loss | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| xgboost | 0.974241 | 0.954161 | 0.018062 | 0.072320 | 0.019263 |
| ft_transformer | 0.977169 | 0.958795 | 0.017260 | 0.067260 | 0.009803 |
| late_fusion_v2 | 0.975195 | 0.955745 | 0.018817 | 0.079721 | 0.011498 |

FT-Transformer alone achieved higher test F1/MCC and lower Brier/log loss/ECE than the selected v2 model. These results do not establish a stacking gain; no candidate or hyperparameter was changed after test evaluation.

The fixed entropy budget referred 487/4,867 samples (10.0062%) and retained 4,380 (89.9938%). It caught 85/97 false negatives (87.6289%) and 91/108 errors (84.2593%) in the referral group. The retained cohort has 12 false negatives and 5 false positives; F1 malicious=0.995873, MCC=0.992215, Brier=0.004168, log loss=0.034879 and ECE=0.016135. Referrals are abstentions, never corrected predictions; zero samples were dynamically executed.

Label=1 is malicious. ECE uses 10 equal-width malicious-probability bins, with p=1 in the last bin. The historical test probability tables are reused; this is an evaluation on the existing Protocol G test cohort, not a new external or temporally independent cohort. Protocol G proves feature-vector group disjointness; the RIT table has no corresponding raw PDF index, so PDF-file identity and Vision alignment remain unverified.

Exact values are in `metrics.json`, `model_comparison.csv`, `routing_analysis.csv`, and `validation_lock.json`. Detailed roles/predictions stay under ignored `artifacts/late_fusion_v2/`.
