"""Standard-library bootstrap for a sealed numeric Kaggle bundle."""

import inspect
import json
from pathlib import Path
import re


def save_generated_notebook(root, study, run_id, filename, notebook):
    """Write a local per-run notebook under notebooks/generated, refusing overwrite."""
    if (not re.fullmatch(r"[a-z0-9_]+", study)
            or not re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", run_id)
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.ipynb", filename)):
        raise ValueError("Unsafe generated notebook destination")
    output = Path(root).absolute() / "notebooks/generated" / study / run_id / filename
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("Generated notebook destination contains a symbolic link")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(notebook, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return output


def find_kaggle_bundle(input_root, expected_metadata_sha256):
    """Find an expanded bundle or ZIP by its pinned metadata, never its slug."""
    import hashlib
    import os
    from pathlib import Path
    import zipfile

    if len(expected_metadata_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_metadata_sha256):
        raise ValueError("Use the generated notebook with its pinned metadata checksum")
    root = Path(input_root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"INPUT_ROOT directory does not exist or is unsafe: {root}. "
                         "Finish dataset creation, then Add Input in this notebook; try Path('/kaggle/input').")
    boundary = root.resolve()
    expanded, archives, observed = [], [], []
    count = 0
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = sorted(f for f in folders if not (Path(directory) / f).is_symlink())
        count += len(folders) + len(files)
        if count > 200000:
            raise ValueError("Too many input entries; set INPUT_ROOT to this dataset's directory")
        for name in sorted(files):
            if name != "bundle_metadata.json" and Path(name).suffix.lower() != ".zip":
                continue
            path = Path(directory) / name
            if path.is_symlink() or not path.resolve().is_relative_to(boundary) or not path.is_file():
                raise ValueError("Unsafe bundle candidate path")
            if len(observed) < 10:
                observed.append(str(path.relative_to(root)))
            if name == "bundle_metadata.json":
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError("Bundle metadata exceeds its cap")
                with path.open("rb") as handle:
                    content = handle.read(1024 * 1024 + 1)
                if hashlib.sha256(content).hexdigest() == expected_metadata_sha256:
                    expanded.append(path.parent)
                continue
            if path.stat().st_size > 7 * 1024**3:
                continue
            try:
                with zipfile.ZipFile(path) as archive:
                    members = archive.infolist()
                    if len(members) > 22000 or sum(m.file_size for m in members) > 7 * 1024**3:
                        continue
                    metadata = [m for m in members if m.filename == "bundle_metadata.json"]
                    if len(metadata) != 1:
                        continue
                    member = metadata[0]
                    if (member.file_size > 1024 * 1024 or member.flag_bits & 1
                            or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            or (member.external_attr >> 16 & 0o170000) == 0o120000):
                        continue
                    with archive.open(member) as handle:
                        content = handle.read(1024 * 1024 + 1)
                    if hashlib.sha256(content).hexdigest() == expected_metadata_sha256:
                        archives.append(path)
            except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError):
                continue
    # Some mounts contain both the original ZIP and its expanded contents.
    matches = expanded if expanded else archives
    if len(matches) > 1:
        raise ValueError("Ambiguous matching bundles; set INPUT_ROOT to one dataset directory. "
                         f"Matches: {[str(p) for p in matches[:10]]}")
    if not matches:
        mounted = sorted(p.name for p in root.iterdir())[:10]
        raise ValueError(f"No bundle matches the pinned Codespace export under {root}. "
                         f"Attached entries: {mounted}; metadata/ZIP candidates: {observed}. "
                         "Wait for dataset creation, then Add Input: nguyenkhang294/malpdf-markov-cache. "
                         "Use the generated notebook for that export; keep its checksum unchanged.")
    return (matches[0], None) if expanded else (None, matches[0])


def prepare_kaggle_code(bundle_root, metadata, overrides):
    """Copy verified base code into a new directory with pinned source updates."""
    import hashlib
    from pathlib import Path, PurePosixPath
    import tempfile

    if not overrides:
        return Path(bundle_root) / 'code/src'
    allowed = {'code/src/malpdf/experiments/kaggle_vision_runner.py',
               'code/src/malpdf/deep_learning/training.py'}
    if set(overrides) != allowed or not allowed.issubset(metadata['file_sha256']):
        raise ValueError('Unexpected optimized code overlay')
    for item in overrides.values():
        content = item['source'].encode('utf-8')
        if len(content) > 1024 * 1024 or hashlib.sha256(content).hexdigest() != item['sha256']:
            raise ValueError('Optimized source checksum mismatch')
    destination = Path(tempfile.mkdtemp(prefix='malpdf_gpu_code_'))
    for name, digest in metadata['file_sha256'].items():
        if not name.startswith('code/src/'):
            continue
        member = PurePosixPath(name)
        source = Path(bundle_root).joinpath(*member.parts)
        if (member.is_absolute() or '..' in member.parts or '\\' in name or member.suffix != '.py'
                or source.is_symlink() or not source.resolve().is_relative_to(Path(bundle_root).resolve())):
            raise ValueError('Unsafe sealed code path')
        with source.open('rb') as handle:
            content = handle.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024 or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError('Base source checksum mismatch')
        if name in overrides:
            content = overrides[name]['source'].encode('utf-8')
        target = destination.joinpath(*member.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(content)
    return destination / 'code/src'


def writable_numeric_bundle(bundle_root, metadata):
    """Copy sealed delta members into a writable directory, even for expanded mounts."""
    import csv
    import hashlib
    from pathlib import Path, PurePosixPath
    import tempfile

    root = Path(bundle_root)
    manifest = root / 'manifest.csv'
    if manifest.is_symlink() or manifest.stat().st_size > 16 * 1024**2:
        raise ValueError('Unsafe delta manifest')
    content = manifest.read_bytes()
    if hashlib.sha256(content).hexdigest() != metadata['file_sha256']['manifest.csv']:
        raise ValueError('Delta manifest changed')
    rows = list(csv.DictReader(content.decode().splitlines()))
    paths = {'bundle_metadata.json', *metadata['file_sha256']}
    matrices = {}
    for row in rows:
        name = row['cache_relative_path']
        source = root / name
        if source.exists():
            paths.add(name)
            matrices[name] = row['npy_sha256']
    destination = Path(tempfile.mkdtemp(prefix='malpdf_v4_writable_'))
    for name in sorted(paths):
        relative = PurePosixPath(name)
        source = root / name
        cap = 16 * 1024**2 if relative.suffix == '.csv' else 1024**2
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name
                or source.is_symlink() or not source.resolve().is_relative_to(root.resolve())
                or source.stat().st_size > cap):
            raise ValueError('Unsafe writable bundle member')
        with source.open('rb') as stream:
            content = stream.read(cap + 1)
        digest = matrices.get(name, metadata['file_sha256'].get(name))
        if len(content) > cap or digest and hashlib.sha256(content).hexdigest() != digest:
            raise ValueError('Writable bundle checksum differs')
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(content)
    return destination


def attach_existing_numeric_bundle(bundle_root, input_root, metadata):
    """Restore opaque source matrices from a separately pinned existing numeric input."""
    import csv
    import hashlib
    from pathlib import Path
    import re
    import zipfile

    def checked_csv(name):
        path = Path(bundle_root) / name
        if path.is_symlink() or path.stat().st_size > 16 * 1024**2:
            raise ValueError('Unsafe reuse manifest')
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != metadata['file_sha256'][name]:
            raise ValueError('Reuse manifest checksum differs')
        return list(csv.DictReader(content.decode().splitlines()))
    rows = {r['sample_id']: r for r in checked_csv('manifest.csv')}
    reuse = checked_csv('source_matrix_reuse.csv')
    if (len({r['sample_id'] for r in reuse}) != len(reuse)
            or any(set(r) != {'sample_id', 'legacy_sample_id'} for r in reuse)):
        raise ValueError('Duplicate or invalid reuse identities')
    source_root, archive_path = find_kaggle_bundle(input_root, metadata['source_bundle_metadata_sha256'])
    source = None
    if archive_path is not None:
        h = hashlib.sha256()
        with archive_path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024**2), b''): h.update(block)
        if h.hexdigest() != metadata['source_bundle_archive_sha256']:
            raise ValueError('Existing numeric archive checksum differs')
        source = zipfile.ZipFile(archive_path)
    try:
        for item in reuse:
            sid, old = item['sample_id'], item['legacy_sample_id']
            if any(not re.fullmatch(r'sample_[0-9]{6}', v) for v in (sid, old)) or sid not in rows:
                raise ValueError('Unsafe matrix reuse identity')
            relative = 'markov_cache/' + sid + '.npy'
            if rows[sid]['cache_relative_path'] != relative:
                raise ValueError('Unsafe target cache path')
            old_path = 'markov_cache/' + old + '.npy'
            if source is not None:
                info = source.getinfo(old_path)
                if (info.file_size > 1024**2 or info.flag_bits & 1
                        or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or (info.external_attr >> 16 & 0o170000) == 0o120000):
                    raise ValueError('Unsafe existing numeric matrix')
                content = source.read(info)
            else:
                path = source_root / old_path
                if path.is_symlink() or not path.resolve().is_relative_to(source_root.resolve()) or path.stat().st_size > 1024**2:
                    raise ValueError('Unsafe existing matrix path')
                content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != rows[sid]['npy_sha256']:
                raise ValueError('Reused numeric matrix checksum differs')
            target = Path(bundle_root) / relative
            if target.parent.is_symlink(): raise ValueError('Unsafe cache destination')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as out: out.write(content)
    finally:
        if source is not None: source.close()
    return len(reuse)


def render_kaggle_notebook(template: Path, metadata_sha256: str, *, overrides=None, code_provenance=None) -> dict:
    """Embed the standalone bootstrap and out-of-band checksum in a notebook."""
    if len(metadata_sha256) != 64 or any(c not in "0123456789abcdef" for c in metadata_sha256):
        raise ValueError("Invalid metadata SHA-256")
    notebook = json.loads(template.read_text(encoding="utf-8"))
    for cell in notebook["cells"]:
        source = "".join(cell["source"])
        begin, end = "# BEGIN BUNDLE DISCOVERY\n", "# END BUNDLE DISCOVERY\n"
        if begin in source:
            prefix, rest = source.split(begin, 1)
            _, suffix = rest.split(end, 1)
            source = prefix + begin + inspect.getsource(find_kaggle_bundle) + '\n' + inspect.getsource(prepare_kaggle_code) + end + suffix
        source = source.replace('CODE_OVERRIDES = {}', 'CODE_OVERRIDES = ' + repr(overrides or {}))
        source = source.replace('TRAINING_CODE_PROVENANCE = None', 'TRAINING_CODE_PROVENANCE = ' + repr(code_provenance))
        cell["source"] = source.replace("SET_FROM_EXPORT_REPORT", metadata_sha256).splitlines(keepends=True)
        if cell["cell_type"] == "code":
            cell["execution_count"], cell["outputs"] = None, []
    return notebook
