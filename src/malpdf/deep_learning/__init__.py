"""Small reproducible tabular neural baselines for approved research protocols."""

from malpdf.deep_learning.models import (
    FTTransformerBinaryClassifier,
    MLPBinaryClassifier,
    build_tabular_model,
    count_trainable_parameters,
)
from malpdf.deep_learning.training import (
    EarlyStopping,
    binary_predictions_from_probabilities,
    probabilities_from_logits,
    set_deep_learning_seed,
    train_with_validation,
)

__all__ = [
    "EarlyStopping",
    "FTTransformerBinaryClassifier",
    "MLPBinaryClassifier",
    "binary_predictions_from_probabilities",
    "build_tabular_model",
    "count_trainable_parameters",
    "probabilities_from_logits",
    "set_deep_learning_seed",
    "train_with_validation",
]
