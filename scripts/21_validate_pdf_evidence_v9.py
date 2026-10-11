"""Fresh Python 3.11 CPU checks; never access real PDFs or fit models."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from malpdf.provenance.research_runs import ResearchRun, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-environment', action='store_true')
    parser.add_argument('--environment-run', help='Reuse the fresh environment from a saved preparation invocation')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.version_info[:2] != (3, 11):
        raise ValueError('Local validation requires Python 3.11')
    method = {'protocol': 'V9 maintenance, synthetic/benign fixtures only', 'pdf_access': False,
              'test_access': False, 'model_fitting': False,
              'environment': 'fresh Python 3.11 virtual environment; CPU wheels; pyproject editable dev install',
              'purpose': 'prepare fresh runtime' if args.prepare_environment else 'mandatory source and regression seal'}
    with ResearchRun(root, 'cic_v9_validation', method) as run:
        temporary_root = root/'artifacts/tmp'
        temporary_root.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix='v9_', dir=temporary_root))
        if len(os.fsencode(temporary)) > 64:
            raise ValueError('Validation TMPDIR exceeds multiprocessing socket budget')
        environment = {**os.environ, 'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1',
                       'MKL_NUM_THREADS': '1', 'MPLBACKEND': 'Agg', 'TMPDIR': str(temporary)}
        checks = {}

        def check(name, command, timeout=1200, env=None):
            path = run.artifacts/f'{name}.txt'
            run.progress('check_started', check=name)
            with path.open('x') as output:
                result = subprocess.run(list(map(str, command)), cwd=root, env=env or environment,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
            content = path.read_text()
            checks[name] = {'exit_code': result.returncode, 'output_tail': content[-8000:],
                            'full_output_path': str(path.relative_to(root))}
            write_json(run.report/f'{name}.json', checks[name])
            run.progress('check_finished', check=name, exit_code=result.returncode)
            if result.returncode:
                raise RuntimeError(f'{name} failed; inspect saved private output')
            return content

        if args.environment_run:
            if not re.fullmatch(r'run_[A-Za-z0-9_-]{1,100}', args.environment_run):
                raise ValueError('Unsafe environment run identity')
            prior = root/'reports/experiments/cic_v9_validation'/args.environment_run
            manifest = json.loads((prior/'environment_prepared.json').read_text())
            venv = root/manifest['venv_path']
            if (not venv.is_relative_to(root/'artifacts/cic_v9_validation')
                    or manifest['pyproject_sha256'] != hashlib.sha256((root/'pyproject.toml').read_bytes()).hexdigest()
                    or any(p.is_symlink() for p in venv.parents)):
                raise ValueError('Fresh environment preparation mismatch')
            run.state['fresh_environment_preparation'] = args.environment_run
        else:
            constraints = run.artifacts/'constraints.txt'
            constraints.write_text('\n'.join(sorted({f"{d.metadata['Name']}=={d.version}"
                for d in importlib.metadata.distributions()
                if d.metadata['Name'].lower() not in {'malpdf','pypdf'}})) + '\npypdf==6.18.1\n')
            venv = run.artifacts/'venv'
            check('create_venv', [sys.executable, '-m', 'venv', venv])
            # Wheels are transient: keep them off the almost-full project disk.
            # The fresh installed environment and test TMPDIR stay on disk.
            install_env = {**environment, 'TMPDIR': '/tmp'}
            check('install', [venv/'bin/python', '-m', 'pip', 'install', '--no-cache-dir',
                '--extra-index-url', 'https://download.pytorch.org/whl/cpu', '-c', constraints, '-e', '.[dev]'],
                env=install_env)
            manifest = {'venv_path': str(venv.relative_to(root)), 'python_major_minor': '3.11',
                        'pyproject_sha256': hashlib.sha256((root/'pyproject.toml').read_bytes()).hexdigest()}
            write_json(run.report/'environment_prepared.json', manifest)
        python = venv/'bin/python'
        check('python_version', [python, '--version'])
        check('pip_check_before', [python, '-m', 'pip', 'check'])
        runtime = json.loads(check('effective_environment', [python, '-c',
            "import importlib.metadata as m,json,platform,torch; print(json.dumps({'python':platform.python_version(),"
            "'packages':{n:m.version(n) for n in ['numpy','scipy','pandas','scikit-learn','pypdf','PyMuPDF','esprima','joblib','torch','torchvision']},"
            "'cuda':torch.version.cuda,'cuda_available':torch.cuda.is_available()}))"]))
        if runtime['cuda'] is not None or runtime['cuda_available'] or runtime['packages']['pypdf'] != '6.18.1':
            raise ValueError('Fresh runtime must use CPU PyTorch and pinned pypdf')
        if args.prepare_environment:
            run.state.update(status='completed', environment_only=True,
                             notes='Fresh Python3.11 CPU environment installed from pyproject; no tests, PDF access or model evaluation.')
        else:
            from malpdf.experiments.cic_v9 import v9_source_fingerprint
            before = v9_source_fingerprint(root)
            output = check('pytest', [python, '-m', 'pytest', 'tests/', '-q'])
            check('pip_check', [python, '-m', 'pip', 'check'])
            check('diff_check', ['git','diff','--check'])
            check('status', ['git','status','--short'])
            check('ignore_check', ['git','check-ignore','data/raw/guard.pdf','artifacts/guard.json','guard.pdf','guard.npy'])
            after = v9_source_fingerprint(root)
            if before != after:
                raise ValueError('Source or effective backend changed during validation')
            write_json(run.report/'source_integrity.json', {'before': before, 'after': after, 'status':'passed'})
            clean = run.state['code_worktree']['status'] == 'clean'
            passed = re.search(r'(\d+) passed', output)
            warnings = re.search(r'(\d+) warnings', output)
            evidence = {'status':'passed', 'fingerprint':before,
                'checks':{'pytest':0,'pip_check':0,'diff_check':0,'source_integrity':0,'ignore_check':0},
                'python_major_minor':'3.11','cpu_only':True,'clean_generating_code':clean,
                'fresh_environment_path':str(venv.relative_to(root)),
                'runtime':runtime, 'tests_passed':int(passed.group(1)) if passed else None,
                'warnings':int(warnings.group(1)) if warnings else 0}
            write_json(run.report/'validation_evidence.json', evidence)
            run.state.update(status='completed', tests_passed=evidence['tests_passed'], warnings=evidence['warnings'],
                release_status='requires_three_file_offline_integration_and_one_final_attempt',
                notes='Full dataset-free tests, dependency, source, diff and ignore checks passed in fresh CPU environment. '
                      'Warnings retained. No real PDF access or model fitting; technical code checks do not establish V9 LAB acceptance.')
    print(json.dumps({key:run.state[key] for key in ('run_id','status','report_path')}, indent=2))


if __name__ == '__main__':
    main()
