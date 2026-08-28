"""Explicit classical-model factories for Protocol P and future Protocol G runs.

The paper names the five model families but does not provide hyperparameters.
Every setting below is therefore a documented project assumption, not a claim of
paper reproduction. No factory fits a model.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

MODEL_NAMES = (
    "logistic_regression",
    "random_forest",
    "decision_tree",
    "gaussian_naive_bayes",
    "xgboost",
)


def model_configurations(seed: int = 42) -> dict[str, dict[str, Any]]:
    """Return JSON-serializable, explicit project assumptions for all five models."""
    return {
        "logistic_regression": {
            "paper_model_name": "Logistic Regression (LR)",
            "preprocessing": {"name": "StandardScaler", "fit_scope": "training partition only", "paper_status": "Scaling is a project assumption; the paper does not specify it."},
            "parameters": {"C": 1.0, "class_weight": None, "fit_intercept": True, "l1_ratio": 0.0, "max_iter": 1000, "random_state": seed, "solver": "liblinear", "tol": 0.0001},
            "regularization_assumption": "L2 regularization, represented by l1_ratio=0.0 for scikit-learn 1.8+ compatibility. This is a project assumption; the paper does not specify it.",
        },
        "random_forest": {
            "paper_model_name": "Random Forest (RF)",
            "preprocessing": {"name": None, "fit_scope": None, "paper_status": "No scaling is used for this tree model."},
            "parameters": {"bootstrap": True, "class_weight": None, "criterion": "gini", "max_depth": None, "max_features": "sqrt", "min_samples_leaf": 1, "min_samples_split": 2, "n_estimators": 200, "n_jobs": 1, "random_state": seed},
        },
        "decision_tree": {
            "paper_model_name": "Decision Tree (DT)",
            "preprocessing": {"name": None, "fit_scope": None, "paper_status": "No scaling is used for this tree model."},
            "parameters": {"class_weight": None, "criterion": "gini", "max_depth": None, "max_features": None, "min_samples_leaf": 1, "min_samples_split": 2, "random_state": seed, "splitter": "best"},
        },
        "gaussian_naive_bayes": {
            "paper_model_name": "Gaussian Naive-Bayes (GNB)",
            "preprocessing": {"name": None, "fit_scope": None, "paper_status": "No scaling is added; the paper gives no documented reason for it."},
            "parameters": {"priors": None, "var_smoothing": 1e-9},
        },
        "xgboost": {
            "paper_model_name": "eXtreme Gradient Boost (XGB)",
            "preprocessing": {"name": None, "fit_scope": None, "paper_status": "No scaling is used for this tree model."},
            "parameters": {"base_score": 0.5, "booster": "gbtree", "colsample_bylevel": 1.0, "colsample_bynode": 1.0, "colsample_bytree": 1.0, "eval_metric": "logloss", "gamma": 0.0, "learning_rate": 0.1, "max_delta_step": 0.0, "max_depth": 6, "min_child_weight": 1.0, "missing": None, "n_estimators": 200, "n_jobs": 1, "objective": "binary:logistic", "random_state": seed, "reg_alpha": 0.0, "reg_lambda": 1.0, "scale_pos_weight": 1.0, "subsample": 1.0, "tree_method": "hist", "verbosity": 0},
        },
    }


def create_model(model_name: str, seed: int = 42) -> Any:
    """Create an unfitted estimator with no dependency on mutable library defaults."""
    configurations = model_configurations(seed)
    if model_name not in configurations:
        raise ValueError(f"Unknown model {model_name!r}; expected one of {MODEL_NAMES}")
    parameters = deepcopy(configurations[model_name]["parameters"])
    if model_name == "logistic_regression":
        return Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(**parameters)),
            ]
        )
    if model_name == "random_forest":
        return RandomForestClassifier(**parameters)
    if model_name == "decision_tree":
        return DecisionTreeClassifier(**parameters)
    if model_name == "gaussian_naive_bayes":
        return GaussianNB(**parameters)
    if model_name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as error:  # pragma: no cover - dependency declared in pyproject
            raise ImportError("XGBoost is required; install the project dependencies.") from error
        return XGBClassifier(**parameters)
    raise AssertionError("All known model names were handled")
