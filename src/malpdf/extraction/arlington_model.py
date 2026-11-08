"""Checksum-locked local Arlington TSV reference data; never fetch at runtime."""

import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess

from malpdf.static.safety import read_bounded_bytes

SOURCE = 'https://github.com/pdf-association/arlington-pdf-model'
HEADER = ('Key','Type','SinceVersion','DeprecatedIn','Required','IndirectReference',
          'Inheritable','DefaultValue','PossibleValues','SpecialCase','Link','Note')


class ModelUnavailable(ValueError):
    """Missing, changed or malformed model; no fixture/runtime HEAD fallback."""


@dataclass(frozen=True)
class Catalog:
    tables: dict
    provenance: dict


def _read(root, path, cap):
    try:
        return read_bounded_bytes(root/path,boundary=root,max_bytes=cap)
    except (OSError,ValueError) as error:
        raise ModelUnavailable('arlington_file_unavailable') from error


def _relative(value):
    if not isinstance(value,str) or not value or Path(value).is_absolute() or '..' in Path(value).parts:
        raise ModelUnavailable('arlington_unsafe_path')
    return value


def _git(directory, *args):
    result=subprocess.run(['git','--no-optional-locks','-C',str(directory),*args],
                          capture_output=True,timeout=10,check=False)
    if result.returncode or len(result.stdout)>1024**2:
        raise ModelUnavailable('arlington_git_identity_unavailable')
    return result.stdout


def _snapshot(root, snapshot, tsv):
    snapshot,tsv=_relative(snapshot),_relative(tsv)
    directory=root/snapshot
    if not (root/tsv).is_relative_to(directory) or (root/tsv)==directory:
        raise ModelUnavailable('arlington_tsv_outside_snapshot')

    if any(path.is_symlink() for path in (root/tsv,*(root/tsv).parents)):
        raise ModelUnavailable('arlington_snapshot_symlink')
    paths=sorted((root/tsv).glob('*.tsv'))
    if not 0<len(paths)<=2048:
        raise ModelUnavailable('arlington_tsv_set_unavailable')
    return directory,paths


def _tree(directory,commit,tsv):
    tree={}
    raw=_git(directory,'ls-tree','-r','-z',commit,'--',tsv,'LICENSE','NOTICE.txt')
    for line in raw.split(b'\0'):
        if line:
            meta,name=line.split(b'\t',1)
            mode,kind,blob=meta.split()
            if mode!=b'100644' or kind!=b'blob':
                raise ModelUnavailable('arlington_nonregular_git_source')
            tree[name.decode()]=blob.decode()
    return tree


def seal_model(root, *, commit, snapshot='third_party/arlington-pdf-model',
               tsv='third_party/arlington-pdf-model/tsv/latest', lock='configs/arlington.lock.json'):
    """Seal an explicitly acquired exact Git tree. Refuse replacing a lock."""
    root=Path(root).absolute()
    if not re.fullmatch('[a-f0-9]{40}',commit):
        raise ModelUnavailable('arlington_full_commit_required')
    directory,paths=_snapshot(root,snapshot,tsv)
    if _git(directory,'rev-parse','HEAD').decode().strip()!=commit:
        raise ModelUnavailable('arlington_commit_mismatch')
    names=[str(path.relative_to(directory)).replace('\\', '/') for path in paths]+['LICENSE','NOTICE.txt']
    tree=_tree(directory,commit,str((root/tsv).relative_to(directory)).replace('\\', '/'))
    if set(tree)!=set(names):
        raise ModelUnavailable('arlington_git_file_set_mismatch')
    files={}
    total=0
    for name in names:
        relative=str((directory/name).relative_to(root)).replace('\\', '/')
        data=_read(root,relative,1024**2)
        total+=len(data)
        if total>16*1024**2:
            raise ModelUnavailable('arlington_model_byte_limit')
        blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if blob!=tree[name]:
            raise ModelUnavailable('arlington_git_blob_mismatch')
        files[relative]={'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data),'git_blob_sha1':blob}
    value={'schema_version':'arlington-lock-v1','source':SOURCE,'commit':commit,
           'snapshot':snapshot,'tsv_directory':tsv,'files':files}
    destination=root/_relative(lock)
    if any(path.is_symlink() for path in (destination,*destination.parents)):
        raise ModelUnavailable('arlington_lock_symlink')
    catalog=_load(root,value)
    with destination.open('x',encoding='utf-8') as handle:
        json.dump(value,handle,indent=2,sort_keys=True,allow_nan=False)
        handle.write('\n')
    return catalog


def _load(root, value):
    try:
        if (set(value)!={'schema_version','source','commit','snapshot','tsv_directory','files'}
                or value['schema_version']!='arlington-lock-v1' or value['source']!=SOURCE
                or not re.fullmatch('[a-f0-9]{40}',value['commit'])):
            raise ModelUnavailable('arlington_invalid_lock')
        directory,paths=_snapshot(root,value['snapshot'],value['tsv_directory'])
        if _git(directory,'rev-parse','HEAD').decode().strip()!=value['commit']:
            raise ModelUnavailable('arlington_commit_mismatch')
        expected={str(path.relative_to(root)).replace('\\', '/') for path in paths}
        expected.update(str((directory/name).relative_to(root)).replace('\\', '/') for name in ('LICENSE','NOTICE.txt'))
        if set(value['files'])!=expected:
            raise ModelUnavailable('arlington_file_set_mismatch')
        tree=_tree(directory,value['commit'],str((root/value['tsv_directory']).relative_to(directory)).replace('\\', '/'))
        if {str((directory/name).relative_to(root)).replace('\\', '/') for name in tree}!=expected:
            raise ModelUnavailable('arlington_git_file_set_mismatch')
        tables={}; total=0; row_count=0
        for relative,spec in sorted(value['files'].items()):
            data=_read(root,_relative(relative),1024**2)
            total+=len(data)
            if (set(spec)!={'sha256','size_bytes','git_blob_sha1'} or type(spec['size_bytes']) is not int
                    or total>16*1024**2 or spec['size_bytes']!=len(data) or spec['sha256']!=hashlib.sha256(data).hexdigest()):
                raise ModelUnavailable('arlington_checksum_mismatch')
            name=str((root/relative).relative_to(directory)).replace('\\', '/')
            blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if spec['git_blob_sha1']!=blob or tree[name]!=blob:
                raise ModelUnavailable('arlington_git_blob_mismatch')
            if not relative.endswith('.tsv'):
                continue
            table=Path(relative).stem
            reader=csv.reader(io.StringIO(data.decode('utf-8')),delimiter='\t',quoting=csv.QUOTE_NONE)
            if tuple(next(reader,()))!=HEADER:
                raise ModelUnavailable('arlington_tsv_header_mismatch')
            rows=[]
            for line,cells in enumerate(reader,2):


                missing_note=len(cells)==len(HEADER)-1
                if missing_note:
                    cells=cells+['']
                if len(cells)!=len(HEADER) or any(len(cell)>16384 for cell in cells):
                    raise ModelUnavailable('arlington_tsv_row_invalid')
                row_count+=1
                if row_count>100000:
                    raise ModelUnavailable('arlington_row_limit')
                row=dict(zip(HEADER,cells))
                row.update(line=line,source_sha256=spec['sha256'])
                if missing_note:
                    row['loader_notes']=('omitted_optional_note_cell',)
                rows.append(row)
            if table in tables or len({row['Key'] for row in rows})!=len(rows):
                raise ModelUnavailable('arlington_duplicate_table_or_key')
            tables[table]=tuple(rows)
        provenance={key:value[key] for key in ('source','commit','snapshot','tsv_directory')}
        provenance.update(status='available',tsv_count=len(tables),row_count=row_count,
            verified_bytes=total,files=value['files'],
            lock_content_sha256=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        return Catalog(tables,provenance)
    except (OSError,UnicodeError,KeyError,TypeError,csv.Error,subprocess.SubprocessError) as error:
        raise ModelUnavailable('arlington_model_unavailable') from error


def load_model(root, lock='configs/arlington.lock.json'):
    root=Path(root).absolute()
    try:
        value=json.loads(_read(root,_relative(lock),2*1024**2))
    except (ValueError,TypeError) as error:
        raise ModelUnavailable('arlington_lock_unavailable') from error
    return _load(root,value)
