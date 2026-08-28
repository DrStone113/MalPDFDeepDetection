# Static XGBoost deployment detector v1

## Objective and scope

This is a reproducible static-only deployment/demo detector, not a new benchmark. It reads a local PDF as untrusted bytes through the bounded non-executing extractor, requires the 38-feature gate, and then returns an ML prediction plus a local TreeSHAP explanation.

## Deployment model versus benchmark evidence

The frozen XGBoost family/configuration was selected and evaluated separately by the committed Protocol G, multi-seed, and reproduction work. This detector fits all approved RIT rows only to create a final deployment artifact. It reports no full-data training accuracy and makes no new generalization claim.

## Training data and schema

- RIT-PDFMal-2026 SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Rows: 24337; Label=0 benign: 13235; Label=1 malicious: 11102.
- Schema: `rit-pdfmal-2026/G-drop3constant/38/v1` with 38 ordered features; only `Acroform`, `Colors`, and `BaseEncoding` are excluded as known constants.
- Semantic sentinel values are preserved. No imputation, clipping, normalization, encoding, or further feature selection occurs.

## Static compatibility and inference flow

`malpdf scan` performs bounded static extraction, then invokes `StaticInspectionResult.protocol_g_drop3constant_gate()`. Every required feature must be present, `IMPLEMENTED_VERIFIED_SEMANTICS`, numeric, and finite. Any blocker refuses inference; no partial vector is scored. The model receives the explicit saved feature order, never document-controlled ordering.

## Model, threshold, and integrity

- Model ID: `xgb-rit-full-drop3constant-v1`; random state: 42; threshold: 0.5. Probability >= threshold produces model verdict `MALICIOUS`; otherwise `BENIGN`.
- Configuration is the existing fixed Protocol G XGBoost factory configuration, reused without tuning. The deployment model is not itself called a Protocol G model.
- Loading requires the controlled local artifact, SHA-256 match, model type, saved feature count/order, feature schema, and manifest configuration identity. Artifacts and manifests are immutable by default.

## Local explanation

Native XGBoost `pred_contribs=True` produces feature contributions plus a separate bias. The scanner verifies contribution-sum plus bias against raw margin and sigmoid(margin) against malicious probability. If either check fails, prediction remains separately available but explanation is reported unavailable rather than shown incorrectly. Contributions are model associations, not causal reasons.

## Safety and limitations

No JavaScript, Launch action, attachment, URI, payload, viewer, external application, or network action is executed or followed. The model receives only numeric static features. It is trained on RIT static features; arbitrary real-world PDFs may differ in distribution. Exact record-level equality with the unavailable original RIT PDFs cannot be demonstrated. Static analysis cannot observe runtime behavior; malformed or encrypted files can yield incomplete extraction; a malicious probability is a model score rather than proof. No sandbox or dynamic analysis is included. Future routing can use the exposed probability and prediction-availability fields without defining an unvalidated uncertainty band.

## Provenance

- Deployment code commit: `439f6f4bbf9415b10807372f4b238dfc2845c8fe`.
- Artifact SHA-256: `8aeba9dd2a095ce26314b432fe48e227fa742be76085548140a32c88448fabf9`.
- Build command: `.\.venv\Scripts\python.exe scripts\build_deployment_model.py --execute`.
