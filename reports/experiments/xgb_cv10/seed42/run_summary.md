# XGBoost 10-fold cross-validation run

- Run ID: `seed42`.
- Benchmark-generating code commit: `e5cb9bce8eef7bc26ea189d80fdd597fbecc3b43`.
- Dataset SHA-256: `2f270ab31fbfe8821fd7f54608cb1aa694a0a8d0bbf2ca000942a68213ef8623`.
- Primary splitter: KFold(n_splits=10, shuffle=True, random_state=42); seed 42 is a project choice, not a paper seed.
- XGBoost model_random_state is fixed at 42 for every fold.
- Completed fold records: 20; failed records: 0.
- Both CV-all41 and CV-drop3constant are included. No tuning or cross-protocol split reuse is performed.
