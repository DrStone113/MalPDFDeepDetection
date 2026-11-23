from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

import numpy as np


VERSION = 'pdf-tabular-v3'
LEXICAL = tuple('lexical_' + name for name in (
    'AA', 'AcroForm', 'EmbeddedFile', 'Encrypt', 'JBIG2Decode', 'JS', 'JavaScript', 'Launch',
    'ObjStm', 'OpenAction', 'Resources', 'RichMedia', 'Root', 'URI', 'XFA', 'endobj',
    'endstream', 'obj', 'page_command', 'stream', 'trailer', 'xref', 'startxref',
))
RAW = ('raw_size_bytes', 'raw_entropy', 'raw_header_offset', 'raw_suffix_bytes',
       'raw_suffix_entropy', 'raw_escaped_name_candidates')
AST_SUMMARY = tuple('legacy_observed_ast_' + name for name in ('node_count', 'max_depth', 'loops', 'computed_members'))
AST_TYPE_PREFIX = 'legacy_observed_ast_type_'
AST_TYPES = tuple(AST_TYPE_PREFIX + name for name in (
    'CallExpression', 'Identifier', 'MemberExpression', 'Literal', 'BinaryExpression', 'NewExpression',
    'AssignmentExpression', 'FunctionExpression', 'FunctionDeclaration', 'WhileStatement', 'ForStatement',
))
AST_CALLS = tuple('legacy_observed_call_' + name for name in (
    'eval', 'unescape', 'String.fromCharCode', 'util.printf', 'Collab.collectEmailInfo', 'app.launchURL', 'atob', 'Function',
))
ACTIONS = tuple('legacy_v8_action_' + name for name in (
    'GoToE', 'GoToR', 'ImportData', 'JavaScript', 'Launch', 'SubmitForm', 'URI',
))
EMBEDDED = tuple('legacy_v8_embedded_' + name for name in ('elf', 'jpeg', 'other', 'pdf', 'pe', 'png', 'zip'))
OBSERVED = LEXICAL + RAW + AST_SUMMARY + AST_TYPES + AST_CALLS + ACTIONS + EMBEDDED
DERIVED = ('js_per_obj', 'stream_per_obj', 'obj_endobj_diff', 'stream_endstream_diff',
           'ast_call_ratio', 'ast_identifier_ratio', 'ast_computed_ratio')
FEATURES = OBSERVED + DERIVED


def project_features(fields):
    observed = {}
    for name in OBSERVED:
        entry = fields.get(name, {})
        value = entry.get('value')
        observed[name] = (value if entry.get('scope_complete') is True
                          and entry.get('status') in ('observed', 'absent_within_scope')
                          and type(value) in (int, float) and isfinite(value) else None)

    def ratio(numerators, denominator):
        counts = [observed[name] for name in numerators]
        total = observed[denominator]
        if total is None or total <= 0 or any(count is None for count in counts):
            return None
        return sum(counts) / total

    def difference(left, right):
        a, b = observed[left], observed[right]
        return a - b if a is not None and b is not None else None

    return [*observed.values(), ratio(('lexical_JS', 'lexical_JavaScript'), 'lexical_obj'),
            ratio(('lexical_stream',), 'lexical_obj'), difference('lexical_obj', 'lexical_endobj'),
            difference('lexical_stream', 'lexical_endstream'),
            ratio((AST_TYPE_PREFIX + 'CallExpression',), AST_SUMMARY[0]),
            ratio((AST_TYPE_PREFIX + 'Identifier',), AST_SUMMARY[0]),
            ratio((AST_SUMMARY[3],), AST_SUMMARY[0])]


def log_matrix(values):
    array = np.asarray(values, dtype=np.float64)
    if array.ndim != 2 or np.isinf(array).any():
        raise ValueError('invalid_numeric_matrix')
    return np.sign(array) * np.log1p(np.abs(array))


@dataclass(frozen=True)
class RobustTransform:
    center: np.ndarray
    scale: np.ndarray
    available: np.ndarray

    @classmethod
    def fit(cls, values, *, roles):
        train = log_matrix(values)
        if len(roles) != len(train) or not len(train) or set(roles) != {'train'}:
            raise ValueError('train_only_transform')
        available = (~np.isnan(train)).any(axis=0)
        center, scale = np.zeros(train.shape[1]), np.ones(train.shape[1])
        if available.any():
            low, median, high = np.nanpercentile(train[:, available], [25, 50, 75], axis=0)
            center[available] = median
            scale[available] = np.where(high > low, high - low, 1)
        return cls(center, scale, available)

    def transform(self, values):
        matrix = log_matrix(values)
        if matrix.shape[1] != len(self.center):
            raise ValueError('feature_count_mismatch')
        mask = np.isnan(matrix) | ~self.available
        scaled = (matrix - self.center) / self.scale
        return np.where(mask, 0.0, scaled).astype(np.float32), mask
