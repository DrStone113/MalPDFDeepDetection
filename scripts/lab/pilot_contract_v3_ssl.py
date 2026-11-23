from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import subprocess

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve
import torch
from torch import nn
from torch.nn import functional as F

from malpdf.evaluation.binary import evaluate_binary_predictions
from malpdf.features.contract_v3 import DERIVED, FEATURES, LEXICAL, RAW, VERSION, RobustTransform
from scripts.lab.build_clean_splits import digest, write_json
from scripts.lab.export_contract_v3 import TABLE_SHA256


SEED = 42
BATCH = 256
SUPERVISED_EPOCHS = 12
SSL_EPOCHS = 8
MASK_RATE = 0.25


def read_inputs(table, labels, split):
    with gzip.open(table, 'rt', encoding='ascii') as fields:
        header = json.loads(next(fields))
        if header != {'contract': VERSION, 'features': list(FEATURES), 'table_sha256': TABLE_SHA256}:
            raise ValueError('unexpected_feature_projection')
        vectors = {}
        for item in map(json.loads, fields):
            if isinstance(item, dict):
                if item['row_count'] != len(vectors) or fields.read(1):
                    raise ValueError('truncated_or_extra_projection_rows')
                break
            sha, vector = item
            if sha in vectors or len(vector) != len(FEATURES):
                raise ValueError('invalid_feature_projection_row')
            vectors[sha] = vector
        else:
            raise ValueError('missing_projection_trailer')
    with labels.open(encoding='ascii') as annotated, split.open(encoding='ascii') as assigned:
        next(annotated)
        if json.loads(next(assigned))['label_view_sha256'] != digest(labels):
            raise ValueError('split_label_view_mismatch')
        rows = []
        for label, membership in zip(map(json.loads, annotated), map(json.loads, assigned), strict=True):
            sha, role = membership['sha256'], membership['role']
            if sha != label['sha256']:
                raise ValueError('split_identity_mismatch')
            vector = vectors.pop(sha)
            if role in ('train', 'val_select') and any(value is not None for value in vector):
                rows.append((role, label['label'], label['status'], vector))
        if vectors:
            raise ValueError('feature_projection_membership_mismatch')
    return rows


def batches(count, seed):
    rng = np.random.default_rng(seed)
    permutation = rng.permutation(count)
    return (permutation[start:start + BATCH] for start in range(0, count, BATCH))


def fit_arm(train, mask, fit, labels, validation, *, pretrain, device):
    torch.manual_seed(SEED)
    dim = train.shape[1]
    encoder = nn.Sequential(nn.Linear(dim * 2, 128), nn.LayerNorm(128), nn.GELU(),
                            nn.Linear(128, 64), nn.GELU()).to(device)
    scorer = nn.Linear(64, 1).to(device)
    reconstruction = []
    if pretrain:
        decoder = nn.Linear(64, dim).to(device)
        optimizer = torch.optim.AdamW([*encoder.parameters(), *decoder.parameters()], lr=0.001)
        for epoch in range(SSL_EPOCHS):
            total_sq, total_targets = 0.0, 0
            for batch in batches(len(train), SEED + epoch):
                clean = train[batch]
                missing = mask[batch]
                hidden = (torch.rand_like(clean) < MASK_RATE) & ~missing
                if not hidden.any():
                    continue
                unavailable = missing | hidden
                corrupt = clean.masked_fill(unavailable, 0.0)
                outputs = decoder(encoder(torch.cat((corrupt, unavailable), dim=1)))
                loss = F.mse_loss(outputs[hidden], clean[hidden])
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                targets = int(hidden.sum().item())
                total_targets += targets
                total_sq += loss.item() * targets
            reconstruction.append(total_sq / total_targets)

    inputs = torch.cat((train, mask), dim=1)[fit]
    optimizer = torch.optim.AdamW([*encoder.parameters(), *scorer.parameters()], lr=0.001)
    label_weights = torch.bincount(labels.long()).reciprocal()
    label_weights /= label_weights.mean()
    for epoch in range(SUPERVISED_EPOCHS):
        for batch in batches(len(labels), SEED + 1000 + epoch):
            batch_labels = labels[batch]
            loss = F.binary_cross_entropy_with_logits(scorer(encoder(inputs[batch])).flatten(), batch_labels,
                                                       weight=label_weights[batch_labels.long()])
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
    with torch.inference_mode():
        scores = scorer(encoder(validation)).flatten().sigmoid().cpu().numpy()
    return scores, reconstruction


def diagnose(labels, scores, statuses):
    false_rate, true_rate, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    eligible = np.flatnonzero(false_rate <= 0.01)
    best = eligible[true_rate[eligible].argmax()]
    threshold = thresholds[best]
    decision = scores >= threshold
    slices = {'all': np.ones(len(labels), dtype=bool),
              'bounded_complete': statuses == 'bounded_complete',
              'degraded_or_unsupported': statuses != 'bounded_complete'}
    metrics = {}
    for name, view in slices.items():
        item = evaluate_binary_predictions(labels[view], decision[view], scores[view])
        (tn, fp), (fn, tp) = item['confusion_matrix']
        metrics[name] = {**item, 'n': tn + fp + fn + tp, 'fpr': fp / (fp + tn) if fp + tn else None}
    return {'diagnostic_threshold': float(threshold) if np.isfinite(threshold) else None, 'metrics': metrics}


def main():
    parser = argparse.ArgumentParser(description='Compare matched tabular models with and without masked pretraining')
    for name in ('table', 'labels', 'split', 'run-directory'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    rows = read_inputs(args.table, args.labels, args.split)
    training = [(y, vector) for role, y, _, vector in rows if role == 'train']
    validation = [(y, status, vector) for role, y, status, vector in rows if role == 'val_select']
    values = [value for _, value in training]
    transformer = RobustTransform.fit(values, roles=['train'] * len(values))
    train, mask = transformer.transform(values)
    valid, valid_mask = transformer.transform([value for _, _, value in validation])
    fit = [index for index, (label, _) in enumerate(training) if label is not None]
    target = np.array([training[index][0] for index in fit], dtype=np.float32)
    valid_labels = np.array([label for label, _, _ in validation], dtype=np.int64)
    status = np.array([value for _, value, _ in validation])
    torch.set_num_threads(4)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    args.run_directory.mkdir(parents=True, exist_ok=False)
    write_json(args.run_directory / 'locked_methodology.json', {
        'started_utc': datetime.now(timezone.utc).isoformat(), 'seed': SEED, 'batch': BATCH,
        'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'input_sha256': {path.name: digest(path) for path in (args.table, args.labels, args.split, Path(__file__))},
        'feature_order': FEATURES, 'ssl_epochs': SSL_EPOCHS, 'mask_rate': MASK_RATE,
        'supervised_epochs': SUPERVISED_EPOCHS, 'optimizer': 'AdamW lr=0.001',
        'threshold_selection_and_scoring': 'Val_Select only, in-sample operating point diagnostic',
        'shortcut_controls': ['status_only', 'observability_only', 'raw_lexical_only'],
        'device': torch.cuda.get_device_name(device) if device.type == 'cuda' else 'cpu',
    })
    tensors = [torch.from_numpy(array).to(device) for array in (
        train, mask, target, np.concatenate((valid, valid_mask), axis=1))]
    arms = {}
    for name, pretrain in (('supervised', False), ('masked_pretraining', True)):
        scores, reconstruction = fit_arm(tensors[0], tensors[1], fit, tensors[2], tensors[3],
                                         pretrain=pretrain, device=device)
        arms[name] = {**diagnose(valid_labels, scores, status), 'training_reconstruction_mse': reconstruction}
    controls = {'status_only': diagnose(valid_labels, (status != 'bounded_complete').astype(float), status)}
    availability_model = LogisticRegression(class_weight='balanced', random_state=SEED)
    availability_model.fit(mask[fit], target)
    controls['observability_only'] = diagnose(valid_labels, availability_model.predict_proba(valid_mask)[:, 1], status)
    raw = [FEATURES.index(name) for name in (*LEXICAL, *RAW, *DERIVED[:4])]
    raw_validation = torch.from_numpy(np.concatenate((valid[:, raw], valid_mask[:, raw]), axis=1)).to(device)
    scores, _ = fit_arm(tensors[0][:, raw], tensors[1][:, raw], fit, tensors[2], raw_validation,
                        pretrain=False, device=device)
    controls['raw_lexical_only'] = diagnose(valid_labels, scores, status)
    result = {'training_labeled': len(fit), 'training_unlabeled': len(train) - len(fit),
              'validation': len(validation), 'features': len(FEATURES),
              'feature_coverage': dict(zip(FEATURES, (~mask).sum(axis=0).tolist())), 'arms': arms, 'controls': controls}
    write_json(args.run_directory / 'metrics.json', result)


if __name__ == '__main__':
    main()
