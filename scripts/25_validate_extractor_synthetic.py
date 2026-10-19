"""Compare inert, generated scalar probes; never accept or discover PDF paths."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time


def fixture(value):
    data, offsets = b'%PDF-1.7\n', []
    for number, body in enumerate((b'<< /Type /Catalog /Pages 2 0 R /Probe ' + value + b' >>',
                                   b'<< /Type /Pages /Count 0 /Kids [] >>'), 1):
        offsets.append(len(data))
        data += f'{number} 0 obj\n'.encode() + body + b'\nendobj\n'
    offset = len(data)
    data += b'xref\n0 3\n0000000000 65535 f \n'
    data += b''.join(f'{position:010d} 00000 n \n'.encode() for position in offsets)
    return data + b'trailer\n<< /Root 1 0 R /Size 3 >>\nstartxref\n' + str(offset).encode() + b'\n%%EOF\n'


def cases():
    for number in (-(2**63), -(2**53) - 1, -(2**31) - 1, -1, 0, 1, 2**31, 2**53 + 1, 2**63 - 1):
        yield 'integer', str(number).encode(), number
    for number in ('0.0', '1.5', '-0.125', '123456.5', '0.1', '0.12345679'):
        yield 'real', number.encode(), Decimal(number)
    for encoded, expected in ((b'true', True), (b'false', False), (b'null', None)):
        yield 'literal', encoded, expected
    for encoded, expected in ((b'/Probe', '/Probe'), (b'/A#20B', '/A B'), (b'/N#C3#A9', '/N\u00e9')):
        yield 'name', encoded, expected
    for number, generation in ((3, 0), (3, 7), (99, 11)):
        yield 'reference', f'{number} {generation} R'.encode(), (number, generation)
    rng = random.Random(42)
    values = [b'', bytes(range(256)), b'\xfe\xff\x00A\x03\xa9', b'\xff\xfeA\x00\xa9\x03']
    values.extend(rng.randbytes(size) for size in (1, 2, 3, 8, 16, 32, 64, 128, 256, 512))
    for value in values:
        yield 'string', b'<' + value.hex().encode() + b'>', value
        yield 'string', b'(' + b''.join(f'\\{byte:03o}'.encode() for byte in value) + b')', value


def matches(value, kind, expected):
    from pypdf.generic import BooleanObject, IndirectObject, NameObject, NullObject, NumberObject
    if kind == 'integer':
        return type(value) is NumberObject and int(value) == expected
    if kind == 'real':
        return Decimal(str(value)) == expected
    if kind == 'literal':
        return isinstance(value, NullObject) if expected is None else isinstance(value, BooleanObject) and value.value is expected
    if kind == 'name':
        return isinstance(value, NameObject) and str(value) == expected
    if kind == 'reference':
        return isinstance(value, IndirectObject) and (value.idnum, value.generation) == expected
    return getattr(value, 'original_bytes', None) == expected


def worker():
    import pikepdf
    import pymupdf
    from pypdf.generic import IndirectObject
    from malpdf.extraction.mupdf_adapter import MuPDFReader
    from malpdf.extraction.parser_views import _RawBudget
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.recovery import MuPDFObjectReader
    observations, manifest, durations = [], [], {'native_inventory': [], 'legacy_v8_recovery': []}
    limits = CodeInspectionLimits()
    for index, (kind, encoded, expected) in enumerate(cases()):
        data = fixture(encoded)
        if len(data) > 4096:
            raise ValueError('Synthetic fixture exceeds the reviewed size bound')
        manifest.append({'case': index, 'kind': kind, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)})
        for backend, factory in [('native_inventory', MuPDFReader), ('legacy_v8_recovery', MuPDFObjectReader)]:
            started, adapter = time.perf_counter(), None
            try:
                adapter = factory(data, limits)
                if backend == 'native_inventory':
                    value, complete, reasons = adapter.object({'number': 1}, _RawBudget(4096))
                    passed = complete and not reasons
                else:
                    value = adapter.get_object(IndirectObject(1, 0, adapter))
                    passed = True
                passed = bool(passed and matches(value.raw_get('/Probe'), kind, expected))
                reason = None if passed else 'scalar_or_completeness_mismatch'
            except Exception as error:
                passed, reason = False, type(error).__name__
            finally:
                if adapter is not None:
                    adapter.close()
            durations[backend].append((time.perf_counter() - started) * 1000)
            observations.append({'case': index, 'backend': backend, 'passed': passed, 'reason': reason})
    summary = {}
    for backend, times in durations.items():
        selected = [item for item in observations if item['backend'] == backend]
        summary[backend] = {'passed': sum(item['passed'] for item in selected), 'total': len(selected),
            'median_ms': statistics.median(times), 'max_ms': max(times)}
    return {'schema_version': 1, 'scope': 'generated scalar fidelity; not corpus detection or containment',
        'seed': 42, 'pdf_paths_accepted': False, 'real_pdf_processing': 'not_run',
        'max_fixture_bytes': 4096, 'native_decoded_stream_calls': False,
        'python': platform.python_version(), 'system': platform.system(),
        'native_libraries': {'MuPDF': pymupdf.VersionFitz, 'QPDF': pikepdf.__libqpdf_version__},
        'packages': {name: importlib.metadata.version(name) for name in ('pypdf', 'PyMuPDF', 'pikepdf')},
        'manifest': manifest, 'observations': observations, 'summary': summary}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--save', action='store_true', help='Write a fresh diagnostic under ignored artifacts/tmp/maintenance/extract_pdf')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(), allow_nan=False))
        return 0
    result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--worker'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=True)
    report = json.loads(result.stdout)
    root = Path(__file__).resolve().parents[1]
    report.update(generated_utc=datetime.now(timezone.utc).isoformat(), wall_timeout_seconds=60,
        windows_os_memory_containment='not_implemented',
        commit=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
        dirty=bool(subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'])))
    sources = ('scripts/25_validate_extractor_synthetic.py', 'src/malpdf/extraction/mupdf_adapter.py',
        'src/malpdf/extraction/parser_views.py', 'src/malpdf/extraction/qpdf_adapter.py',
        'src/malpdf/extraction/raw_syntax.py', 'src/malpdf/static/recovery.py')
    report['source_sha256'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources}
    if args.save:
        parent = root / 'artifacts/tmp/maintenance/extract_pdf/synthetic_scalar'
        if parent.resolve() != parent.absolute() or any(path.is_symlink() for path in (parent, *parent.parents)):
            raise ValueError('Diagnostic output must not follow symbolic links')
        subprocess.run(['git', '-C', str(root), 'check-ignore', '-q', '--', str(parent / 'guard.json')], check=True)
        destination = parent / ('run_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        destination.mkdir(parents=True, exist_ok=False)
        with (destination / 'validation.json').open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2, allow_nan=False)
            handle.write('\n')
        print(json.dumps({'output_directory': str(destination), 'summary': report['summary']}))
    else:
        print(json.dumps(report, allow_nan=False))
    return 0 if all(item['passed'] for item in report['observations']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
