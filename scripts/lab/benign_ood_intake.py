from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import http.client
import io
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit


URLS = {
    'irs': r'https://www\.irs\.gov/pub/irs-pdf/[a-z0-9-]+\.pdf',
    'usco': r'https://www\.copyright\.gov/circs/circ[0-9a-zA-Z]+\.pdf',
    'rfc': r'https://www\.rfc-editor\.org/rfc/rfc[0-9]+\.pdf',
    'arxiv': r'https://arxiv\.org/pdf/(?:[0-9]{4}\.[0-9]{4,5}(?:v[0-9]+)?|math/[0-9]{7})',
    'court': r'https://www\.supremecourt\.gov/opinions/[0-9]{2}pdf/[A-Za-z0-9_-]+\.pdf',
    'fr': r'https://www\.govinfo\.gov/content/pkg/FR-[0-9]{4}-[0-9]{2}-[0-9]{2}/pdf/[0-9]{4}-[0-9]{5}\.pdf',
    'nasa': r'https://ntrs\.nasa\.gov/api/citations/[0-9]+/downloads/[A-Za-z0-9_.-]+\.pdf',
    'nist': r'https://nvlpubs\.nist\.gov/nistpubs/[A-Za-z0-9_./-]+\.pdf',
    'verapdf': r'https://raw\.githubusercontent\.com/veraPDF/veraPDF-corpus/staging/[A-Za-z0-9_.%/-]+\.pdf',
    'pdfjs': r'https://raw\.githubusercontent\.com/mozilla/pdf\.js/master/test/pdfs/[A-Za-z0-9_.%/-]+\.pdf',
}
OCTET_STREAM_ALLOWED_SOURCES = frozenset({'verapdf', 'pdfjs'})
MAX_DOC = 12 * 1024**2
MAX_TOTAL = 160 * 1024**2
MAX_REQUESTS = 150
HASH = re.compile(r'[a-f0-9]{64}')


def candidate_rows(value):
    rows = value['documents']
    if value['schema_version'] != 1 or not 1 <= len(rows) <= MAX_REQUESTS:
        raise ValueError('invalid_candidate_set')
    seen = set()
    for row in rows:
        source, identity, url = row['source'], row['id'], row['url']
        if (source not in URLS or not re.fullmatch(source + r'-[0-9]{3}', identity)
                or not re.fullmatch(URLS[source], url) or row['status'] != 200
                or identity in seen):
            raise ValueError('invalid_candidate_record')
        seen.add(identity)
    return rows


def download(row, root):
    url = urlsplit(row['url'])
    conn = http.client.HTTPSConnection(url.hostname, context=ssl.create_default_context(), timeout=30)
    try:
        conn.request('GET', url.path, headers={'User-Agent': 'MalPDF research (publisher controls)'})
        response = conn.getresponse()
        kind = (response.getheader('Content-Type') or '').split(';')[0].strip().lower()
        allowed_kinds = {'application/pdf', 'application/octet-stream'} if row['source'] in OCTET_STREAM_ALLOWED_SOURCES else {'application/pdf'}
        if response.status != 200 or kind not in allowed_kinds:
            return {'id': row['id'], 'error': 'unexpected_http_response', 'http_status': response.status}
        payload = response.read(MAX_DOC + 1)
        fixed = row.get('etag')
        modified = row.get('last_modified')
        if ((fixed and fixed != response.getheader('ETag'))
                or (modified and modified != response.getheader('Last-Modified'))):
            return {'id': row['id'], 'error': 'publisher_version_changed'}
        if (not 50 <= len(payload) <= MAX_DOC or not payload.startswith(b'%PDF-')
                or row.get('length') and int(row['length']) != len(payload)):
            return {'id': row['id'], 'error': 'unexpected_pdf_bytes'}
        (root / (row['id'] + '.pdf')).write_bytes(payload)
        return {'id': row['id'], 'bytes': len(payload), 'sha256': sha256(payload).hexdigest()}
    except (OSError, http.client.HTTPException):
        return {'id': row['id'], 'error': 'network_read_failed'}
    finally:
        conn.close()


def fetch(request):
    candidates = request['candidates']
    rows = candidate_rows(candidates)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        cert = root / 'receiver.pem'
        cert.write_text(request['receiver_pem'], encoding='ascii')
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(lambda row: download(row, root), rows))
        acquired = [row for row in results if 'sha256' in row]
        if not acquired or sum(row['bytes'] for row in acquired) > MAX_TOTAL:
            raise ValueError('acquisition_byte_budget')
        bundle = root / 'source.tar'
        with tarfile.open(bundle, 'w', format=tarfile.USTAR_FORMAT) as archive:
            manifest = json.dumps({'candidate_sha256': request['candidate_sha256'], 'results': results},
                                  separators=(',', ':')).encode('ascii')
            member = tarfile.TarInfo('acquisition.json')
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
            for row in acquired:
                name = row['id'] + '.pdf'
                archive.add(root / name, arcname=name, recursive=False)
        subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
                        '-in', str(bundle), str(cert)], check=True, timeout=90, stdout=sys.stdout.buffer)


def receive(bundle, candidates_path, cert, key, out):
    source = candidates_path.read_bytes()
    candidates = {row['id']: row for row in candidate_rows(json.loads(source))}
    if bundle.stat().st_size > MAX_TOTAL + 1024**2:
        raise ValueError('invalid_ciphertext_size')
    with tempfile.TemporaryDirectory(dir=out.parent) as directory:
        stage = Path(directory)
        clear = stage / 'bound.tar'
        subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in', str(bundle),
                        '-recip', str(cert), '-inkey', str(key), '-out', str(clear)], check=True, timeout=90)
        payload = stage / 'payload'
        payload.mkdir(mode=0o700)
        with tarfile.open(clear, mode='r:') as archive:
            members = archive.getmembers()
            if not members or members[0].name != 'acquisition.json' or not all(m.isreg() for m in members):
                raise ValueError('invalid_acquisition_members')
            if members[0].size > 128 * 1024:
                raise ValueError('invalid_acquisition_manifest')
            manifest = json.load(archive.extractfile(members[0]))
            if manifest['candidate_sha256'] != sha256(source).hexdigest():
                raise ValueError('acquisition_candidate_digest_mismatch')
            results = manifest['results']
            if len(results) != len(candidates) or {row['id'] for row in results} != set(candidates):
                raise ValueError('acquisition_identity_mismatch')
            acquired = [row for row in results if 'sha256' in row]
            if sum(row['bytes'] for row in acquired) > MAX_TOTAL:
                raise ValueError('acquisition_byte_budget')
            for row, member in zip(acquired, members[1:], strict=True):
                expected_filename = row['id'] + '.pdf'
                if (member.name != expected_filename or member.size != row['bytes']
                        or not 50 <= member.size <= MAX_DOC or not HASH.fullmatch(row['sha256'])):
                    raise ValueError('unexpected_acquisition_file')
                contents = archive.extractfile(member).read(MAX_DOC + 1)
                if sha256(contents).hexdigest() != row['sha256'] or not contents.startswith(b'%PDF-'):
                    raise ValueError('acquisition_byte_digest_mismatch')
                (payload / expected_filename).write_bytes(contents)
            result = {'candidate_sha256': manifest['candidate_sha256'],
                      'entries': [{**row, 'source': candidates[row['id']]['source'], 'url': candidates[row['id']]['url']}
                                  for row in acquired], 'failed': [r for r in results if 'error' in r]}
            (payload / 'acquisition.json').write_text(json.dumps(result, indent=2) + '\n', encoding='ascii')
        if out.exists():
            raise FileExistsError(out)
        payload.rename(out)
    return result


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action', required=True)
    subparsers.add_parser('fetch')
    intake = subparsers.add_parser('receive')
    for flag in ('bundle', 'candidates', 'cert', 'key', 'out'):
        intake.add_argument('--' + flag, type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(json.load(sys.stdin))
    else:
        print(json.dumps(receive(args.bundle, args.candidates, args.cert, args.key, args.out), separators=(',', ':')))


if __name__ == '__main__':
    main()
