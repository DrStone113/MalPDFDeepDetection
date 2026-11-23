import numpy as np
import pytest

from malpdf.features.contract_v3 import FEATURES, RobustTransform, project_features
from malpdf.scanner.ingestion import _scan_scanner_raw_tokens
from malpdf.static.raw_scan import scan_raw_pdf_tokens


def test_pdf_name_is_case_sensitive_and_historical_counter_remains_reproducible():
    data = b'/AcroForm /AcroFormExtra /Acroform /AcroForms\n/AcroForm/Other'
    lab = scan_raw_pdf_tokens(data, include_acroform=True)
    scanner = _scan_scanner_raw_tokens(data)
    assert lab['AcroForm'] == scanner['AcroForm'] == 2
    assert lab['Acroform'] == scanner['Acroform'] == 1


def test_projection_keeps_unsupported_fields_missing_and_derives_only_from_observed_values():
    actual = {'status': 'observed', 'scope_complete': True}
    raw = {
        'lexical_obj': {**actual, 'value': 2},
        'lexical_JS': {**actual, 'value': 1},
        'lexical_JavaScript': {**actual, 'value': 3},
        'lexical_Acroform': {**actual, 'value': 9},
        'lexical_endobj': {'status': 'partial', 'scope_complete': False, 'value': 1},
        'lexical_stream': {**actual, 'value': 0},
    }
    projected = dict(zip(FEATURES, project_features(raw), strict=True))
    assert projected['lexical_AcroForm'] is None
    assert projected['js_per_obj'] == 2
    assert projected['stream_per_obj'] == 0
    assert projected['obj_endobj_diff'] is None
    assert 'raw_prefix_entropy' not in projected
    assert 'byte_image_file_persisted_ratio' not in projected


def test_robust_transform_fits_train_only_and_distinguishes_zero_from_missing():
    train = [[0, None], [3, None], [15, None]]
    transformer = RobustTransform.fit(train, roles=['train'] * 3)
    values, missing = transformer.transform([[3, 1000], [0, None], [None, None]])
    np.testing.assert_allclose(values[0], [0, 0])
    np.testing.assert_array_equal(missing[:, 0], [False, False, True])
    np.testing.assert_array_equal(missing[:, 1], [True, True, True])
    with pytest.raises(ValueError, match='train_only'):
        RobustTransform.fit(train, roles=['train', 'val_select', 'train'])
