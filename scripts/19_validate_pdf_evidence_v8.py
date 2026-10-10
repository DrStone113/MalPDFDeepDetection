"""Fresh Python 3.11 CPU installation and dataset-free v8 maintenance checks."""

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
    root = Path(__file__).resolve().parents[1]
    method = {'protocol': 'v8 maintenance, synthetic/benign fixtures only', 'pdf_access': False,
              'test_access': False, 'environment': 'fresh Python 3.11 venv; CPU wheels; pyproject editable dev install',
              'constraints': 'effective starting package versions pinned for repeatable local checks',
              'benchmark': 'not invoked; final CIC acceptance pending isolated console LAB'}
    with ResearchRun(root, 'cic_v8_validation', method) as run:
        if sys.version_info[:2] != (3, 11):
            raise ValueError('Local validation requires Python 3.11')
        constraints = run.artifacts / 'constraints.txt'
        constraints.write_text('\n'.join(sorted({
            f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()
            if d.metadata['Name'].lower() != 'malpdf'})) + '\n')
        venv = run.artifacts / 'venv'
        python = venv / 'bin/python'
        # DataLoader file-descriptor sharing uses Unix sockets below TMPDIR.
        # Keep that path short as well as on disk, outside RAM-backed /tmp.
        temporary_root = root / 'artifacts/tmp'
        temporary_root.mkdir(exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix='v8_', dir=temporary_root))
        if len(os.fsencode(temporary)) > 64:
            raise ValueError('Validation TMPDIR too long for multiprocessing Unix sockets')
        run.state['temporary_path'] = str(temporary.relative_to(root))
        environment = {**os.environ, 'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1',
                       'MKL_NUM_THREADS': '1', 'MPLBACKEND': 'Agg', 'TMPDIR': str(temporary)}
        checks = {}

        def check(name, command, timeout=900):
            path = run.artifacts / f'{name}.txt'
            run.progress('check_started', check=name)
            with path.open('x') as output:
                result = subprocess.run(list(map(str,command)), cwd=root, env=environment,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
            content = path.read_text()
            checks[name] = {'exit_code': result.returncode, 'output_tail': content[-8000:],
                            'full_output_path': str(path.relative_to(root))}
            write_json(run.report / f'{name}.json', checks[name])
            run.progress('check_finished', check=name, exit_code=result.returncode)
            if result.returncode:
                raise RuntimeError(f'{name} failed; saved output: {path.relative_to(root)}')
            return content

        check('create_venv', [sys.executable,'-m','venv',venv])
        check('install', [python,'-m','pip','install','--extra-index-url',
                         'https://download.pytorch.org/whl/cpu','-c',constraints,'-e','.[dev]'])
        check('python_version',[python,'--version'])
        check('pip_check_before',[python,'-m','pip','check'])
        output = check('pytest',[python,'-m','pytest','tests/','-q'])
        check('pip_check',[python,'-m','pip','check'])
        check('diff_check',['git','diff','--check'])
        check('status',['git','status','--short'])
        check('ignore_check',['git','check-ignore','data/raw/guard.pdf','artifacts/guard.json','guard.pdf','guard.npy'])
        check('effective_environment',[python,'-c',
            "import importlib.metadata as m,json,platform,torch; print(json.dumps({'python':platform.python_version(),"
            "'packages':{n:m.version(n) for n in ['numpy','pandas','scikit-learn','pypdf','PyMuPDF','esprima','torch','torchvision']},"
            "'cuda':torch.version.cuda,'cuda_available':torch.cuda.is_available()}))"])
        passed = re.search(r'(\d+) passed',output)
        warnings = re.search(r'(\d+) warnings',output)
        run.state.update(status='completed',tests_passed=int(passed.group(1)) if passed else None,
                         warnings=int(warnings.group(1)) if warnings else 0,
                         checks=list(checks), release_status='pending_offline_benchmark')
        run.state['notes'] = ('Fresh CPU install, full dataset-free suite, pip/diff/status/ignore checks saved. '
                              'No CIC PDFs opened; v8 release and accuracy improvement unverified. '
                              'Temporary install/test files use the ignored on-disk run directory, '
                              'avoiding RAM-backed /tmp pressure; parser budgets and assertions remain intact.')
        (run.report/'validation_report.md').write_text(
            f"# V8 code validation\n\n{run.state['tests_passed']} tests passed; {run.state['warnings']} warnings. "
            'See pytest.json for warning details and effective_environment.json for the fresh runtime. '
            'All mandatory maintenance commands passed. This is code validation with synthetic/benign fixtures; '
            'the final same64 CIC offline measurement and release acceptance remain pending.\n')
    print(json.dumps({key:run.state[key] for key in ('run_id','status','report_path')},indent=2))


if __name__ == '__main__':
    main()
