"""Operator-console source bootstrap copy; never an unattended gateway fallback."""

import os
from pathlib import Path
import subprocess
import sys

import gateway_client as client
import gateway_contract as contract
from lab_contract import REV_RE, parse_json, text_failure, validate_public_key

REMOTE_PARENT = '/home/remnux/malpdf-gateway-bootstrap'


class CopyFailure(ValueError):
    def __init__(self, phase, reason, code=None):
        super().__init__(reason)
        self.phase = phase
        self.code = code


def operator_command(arguments, environment, phase):
    try:
        subprocess.run(arguments, cwd=client.ctl.REPO, env=environment, check=True, timeout=180)
    except subprocess.CalledProcessError as error:
        raise CopyFailure(phase, 'command_failed', error.returncode) from None
    except subprocess.TimeoutExpired:
        raise CopyFailure(phase, 'command_timeout') from None
    except OSError:
        raise CopyFailure(phase, 'client_unavailable') from None


def verified_files(value, *, offline=False):
    if offline:
        from offline_prepare import verified_files as offline_files
        return offline_files(value)
    identity = value['manifest_id']
    if not isinstance(identity, str) or not contract.HEX.fullmatch(identity):
        raise ValueError('bootstrap_rejected')
    folder = client.jobs.trusted_path(Path(value['bootstrap']))
    if folder != client.ctl.OUT / 'gateway-bootstrap' / identity:
        raise ValueError('bootstrap_rejected')
    raw = client.jobs.side.bounded_read(client.jobs.trusted_path(folder / 'manifest.json'), 16384)
    metadata = parse_json(raw)
    if not isinstance(metadata, dict) or set(metadata) != {'api', 'base_commit', 'source_kind', 'files'}:
        raise ValueError('bootstrap_rejected')
    if type(metadata['api']) is not int or metadata['api'] != 1 or metadata['source_kind'] != 'reviewed_worktree_bootstrap':
        raise ValueError('bootstrap_rejected')
    if not isinstance(metadata['base_commit'], str) or not REV_RE.fullmatch(metadata['base_commit']) or contract.sha(contract.encoded(metadata)) != identity:
        raise ValueError('bootstrap_rejected')
    expected = {*client.server.HELPERS, 'setup_gateway.py', 'setup_gateway.sh', 'id_ed25519_malpdf_runner.pub'}
    items = metadata['files']
    if not isinstance(items, list) or len(items) != len(expected) or any(not isinstance(item, dict) or set(item) != {'path', 'size', 'sha256'} for item in items):
        raise ValueError('bootstrap_rejected')
    if any(not isinstance(item['path'], str) for item in items) or {item['path'] for item in items} != expected or {path.name for path in folder.iterdir()} != expected | {'manifest.json'}:
        raise ValueError('bootstrap_rejected')
    for item in items:
        if type(item['size']) is not int or not 0 < item['size'] <= 2 * 1024**2:
            raise ValueError('bootstrap_rejected')
        payload = client.jobs.side.bounded_read(client.jobs.trusted_path(folder / item['path']), 2 * 1024**2)
        if len(payload) != item['size'] or contract.sha(payload) != item['sha256']:
            raise ValueError('bootstrap_rejected')
        if item['path'].endswith('.pub'):
            validate_public_key(payload)
        elif text_failure(payload, 'scripts/lab/' + item['path']):
            raise ValueError('bootstrap_rejected')
    return [folder / name for name in sorted(expected | {'manifest.json'})]


def create_directory(identity, *, offline=False):
    if not isinstance(identity, str) or not contract.HEX.fullmatch(identity):
        raise ValueError('bootstrap_rejected')
    parent = '/home/remnux/malpdf-offline-bootstrap' if offline else REMOTE_PARENT
    return '\n'.join([
        'set -eu', 'umask 077', 'test "$(id -un)" = remnux', 'test "$(id -u)" -ne 0',
        'test -d /home/remnux', 'test ! -L /home/remnux',
        'test "$(stat -c %u /home/remnux)" = "$(id -u)"',
        f'if [ ! -e {parent} ] && [ ! -L {parent} ]; then mkdir -m 700 {parent}; fi',
        f'test -d {parent}', f'test ! -L {parent}',
        f'test "$(stat -c %u {parent})" = "$(id -u)"',
        f'test "$(stat -c %a {parent})" = 700',
        f'mkdir -m 700 {parent}/{identity}',
    ])


def transfer(*, offline=False):
    if sys.platform != 'win32' or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('operator_terminal_required')
    ssh = Path(client.ctl.SSH)
    scp = ssh.with_name('scp.exe')
    if not ssh.is_file() or not scp.is_file():
        raise ValueError('windows_openssh_required')
    if offline:
        from offline_prepare import bootstrap
        value = bootstrap()
    else:
        value = client.setup()
    files = verified_files(value, offline=offline)
    remote = ('/home/remnux/malpdf-offline-bootstrap' if offline else REMOTE_PARENT) + '/' + value['manifest_id']
    print('Operator-only copy to ' + client.ctl.ADMIN)
    print('Manifest: ' + value['manifest_id'])
    print('Source: ' + value['bootstrap'])
    print('Destination: ' + remote)
    print(str(len(files)) + ' source/manifest/public-key files; existing destination is refused. No installer is executed.')
    print('Authentication uses the Linux remnux account password, with one attempt per connection.')
    print('OpenSSH may request your REMnux password twice in this terminal.')
    if input('Copy this installer? [y/N]: ').strip().lower() != 'y':
        raise ValueError('copy_cancelled')
    files = verified_files(value, offline=offline)
    environment = os.environ.copy()
    for name in ('SSH_ASKPASS', 'DISPLAY'):
        environment.pop(name, None)
    environment['SSH_ASKPASS_REQUIRE'] = 'never'
    command = create_directory(value['manifest_id'], offline=offline)
    operator_command([str(ssh), *client.ctl.ADMIN_SECURITY, client.ctl.ADMIN, command], environment, 'directory_preparation')
    verified_files(value, offline=offline)
    operator_command([str(scp), *client.ctl.SCP_SECURITY, *map(str, files), client.ctl.ADMIN + ':' + remote + '/'], environment, 'file_copy')
    print('COPIED: ' + remote)
    print('At the REMnux console, open that folder in a terminal and run:')
    print('sudo sh setup_runner.sh --check' if offline else 'sudo sh setup_gateway.sh --check')
    print('sudo sh setup_runner.sh --install' if offline else 'sudo sh setup_gateway.sh --install --allow-synthetic')
    return 0


def main(*, offline=False):
    try:
        return transfer(offline=offline)
    except CopyFailure as error:
        suffix = '' if error.code is None else ' (exit ' + str(error.code) + ')'
        print('COPY NOT COMPLETE [' + error.phase + '/' + str(error) + ']' + suffix)
        if error.phase == 'directory_preparation':
            print('Source file copy was not attempted. The remote directory state is not assumed.')
        else:
            print('File copy did not complete. Preserve the destination for operator review.')
        print('If OpenSSH reported Permission denied, verify the remnux account password and SSH authentication policy at the VM console.')
        print('No automatic retry, credential fallback or remote cleanup is attempted. See docs/lab_gateway.md.')
        return 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, ValueError) else 'copy_failed'
        print('COPY NOT COMPLETE: ' + reason)
        print('Use a separate operator PowerShell terminal. Preserve any partial remote directory; no retry or cleanup is automatic.')
        return 2


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    raise SystemExit(main(offline=args.offline))
