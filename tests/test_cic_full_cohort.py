import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts/lab'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import lab_jobs
import lab_runner
from malpdf.experiments.cic_static_benchmark import select_corpus


class TestCicFullCohort(unittest.TestCase):
    def test_policy_pdf_static_cic_full(self):
        p = lab_jobs.policy('pdf-static-cic-full')
        self.assertEqual(p['samples'], 1452)
        self.assertEqual(p['workers'], 5)
        self.assertEqual(p['wall_seconds'], 7200)
        self.assertEqual(p['output_bytes'], 2 * 1024**3)
        self.assertIn('pdf-static-cic-full', lab_jobs.PDF_KINDS)
        self.assertIn('pdf-static-cic-full', lab_jobs.KINDS)

    def test_cic_full_contract(self):
        contract = lab_runner.cic_full_contract()
        self.assertEqual(contract['cohort'], 'cic-full-1452')
        self.assertEqual(contract['samples'], 1452)
        self.assertEqual(contract['train'], 870)
        self.assertEqual(contract['validation'], 291)
        self.assertEqual(contract['test'], 291)
        self.assertEqual(contract['seed'], 42)
        self.assertIn('split_manifest', contract['manifests'])
        self.assertIn('source_manifest', contract['manifests'])
        self.assertIn('normalization_manifest', contract['manifests'])

    def test_select_corpus_synthetic_validation(self):
        manifest = []
        sources = []
        for i in range(1452):
            sha = f'{i:064x}'
            sid = f'cic_{i:04d}'
            split = 'train' if i < 870 else 'validation' if i < 1161 else 'test'
            label = '1' if i % 2 == 0 else '0'
            manifest.append({'sample_id': sid, 'duplicate_group_id': f'dup_{i}', 'split': split, 'Label': label, 'cohort': 'cic'})
            sources.append({'sample_id': sid, 'Label': label, 'pdf_relative_path': f'data/raw/cic_pdf/{sid}.pdf', 'pdf_sha256': sha, 'related_group_id': f'rel_{i}'})

        chosen = select_corpus(manifest, sources, seed=42)
        self.assertEqual(len(chosen), 1452)
        self.assertEqual(chosen[0]['sample_id'], 'cic_0000')

    def test_select_corpus_fail_closed_on_wrong_count(self):
        manifest = [{'sample_id': 'c_1', 'duplicate_group_id': 'd1', 'split': 'train', 'Label': '1', 'cohort': 'cic'}]
        sources = [{'sample_id': 'c_1', 'Label': '1', 'pdf_relative_path': 'data/raw/cic_pdf/c_1.pdf', 'pdf_sha256': 'a' * 64, 'related_group_id': 'r1'}]
        with self.assertRaises(ValueError):
            select_corpus(manifest, sources, seed=42)

    def test_select_corpus_rejects_cross_partition_leak(self):
        sha = 'a' * 64
        manifest = []
        sources = []
        for i in range(1452):
            sid = f'cic_{i:04d}'
            split = 'train' if i < 870 else 'test'
            label = '1'
            dup = 'cross_leak' if i in (0, 870) else f'dup_{i}'
            manifest.append({'sample_id': sid, 'duplicate_group_id': dup, 'split': split, 'Label': label, 'cohort': 'cic'})
            sources.append({'sample_id': sid, 'Label': label, 'pdf_relative_path': f'data/raw/cic_pdf/{sid}.pdf', 'pdf_sha256': sha, 'related_group_id': f'rel_{i}'})
        with self.assertRaises(ValueError):
            select_corpus(manifest, sources, seed=42)


    def test_selection_json_buffer_limit_anti_regression(self):
        import json
        manifest = []
        sources = []
        for i in range(1452):
            sha = f'{i:064x}'
            sid = f'cic_{i:04d}'
            split = 'train' if i < 870 else 'validation' if i < 1161 else 'test'
            label = '1' if i % 2 == 0 else '0'
            manifest.append({'sample_id': sid, 'duplicate_group_id': f'dup_{i}', 'split': split, 'Label': label, 'cohort': 'cic'})
            sources.append({'sample_id': sid, 'Label': label, 'pdf_relative_path': f'data/raw/cic_pdf/CIC-Evasive-PDFMal2022/Cohort/{sid}_{sha}.pdf', 'pdf_sha256': sha, 'related_group_id': f'rel_{i}_{sha}'})
        chosen = select_corpus(manifest, sources, seed=42)
        selection = {'job_id': '0' * 64, 'rows': chosen, 'selection_sha256': '1' * 64}
        encoded = json.dumps(selection).encode('utf-8')
        self.assertGreater(len(encoded), 512 * 1024)
        self.assertLess(len(encoded), 4 * 1024**2)


if __name__ == '__main__':
    unittest.main()
