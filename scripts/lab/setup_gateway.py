"""Operator-only installation and real negative probes; never called over the audit key."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
LIB = Path('/usr/local/libexec/malpdf')
BASE = Path('/var/lib/malpdf-gateway')
ETC = Path('/etc/malpdf')
DROPIN = Path('/etc/ssh/sshd_config.d/00-malpdf-runner.conf')
UNIT_DIR = Path('/etc/systemd/system')
HELPERS = ('gateway_contract.py', 'gateway_harness.py', 'lab_gateway.py', 'lab_contract.py',
           'lab_side.py', 'lab_jobs.py', 'lab_guard.py', 'lab_runner.py', 'lab_readonly.py', 'lab_diagnostics.py')
UNITS = ('malpdf-gateway.service', 'malpdf-gateway-probe.service', 'malpdf-gateway.timer')
FAILURE_HINTS = {
    'sudo_policy_invalid': 'Run sudo /usr/sbin/visudo -c at the REMnux console; review the reported file ownership, mode or syntax before retrying.',
    'operator_console_root_required': 'Use sudo from the Linux operator console.',
    'unsupported_python': 'The system Python must be >=3.11,<3.14; no interpreter is installed automatically.',
    'bootstrap_rejected': 'Review the exact 14 installer files and their manifest hashes.',
    'audit_account_missing': 'The separately reviewed read-only audit account must already exist.',
    'audit_group_missing': 'The read-only audit report group must already exist.',
    'audit_key_missing': 'The installed read-only audit authorized_keys file is missing.',
    'runner_key_must_be_separate': 'The runner public key must differ from the audit key.',
    'sshd_include_required': 'Review the expected SSHD drop-in Include at the operator console.',
    'symlinked_destination': 'Review symlinked installer or destination paths; do not bypass the check.',
    'destination_permissions': 'Review root ownership and writable bits of the fixed installation paths.',
    'existing_account_requires_review': 'Review the reserved runner/worker UID, home, shell and groups.',
    'existing_privilege_or_session': 'Review existing runner/worker privileges and sessions.',
    'runner_process_present': 'A malpdf-runner process exists. Review the active session/job at the console; nothing is killed automatically.',
    'worker_process_present': 'A malpdf-worker process exists. Review the active job at the console; nothing is killed automatically.',
    'runner_sudo_listing_allowed': 'The sudo listing for malpdf-runner succeeded. Review its sudo grants at the console; no permissions are changed automatically.',
    'worker_sudo_listing_allowed': 'The sudo listing for malpdf-worker succeeded. Review its sudo grants at the console; no permissions are changed automatically.',
    'account_process_check_failed': 'The fixed account process check could not establish that no process exists.',
    'account_sudo_check_failed': 'The fixed account sudo check returned an unexpected result; stop for operator review.',
    'systemd_required': 'The installer requires a booted systemd system.',
    'cgroup_v2_controllers_required': 'The worker requires cgroup v2 memory, pids and cpu controllers.',
    'required_file_missing': 'A required installer or system file/tool is missing; review prerequisites at the console.',
    'permission_denied': 'Review permissions at the operator console.',
    'command_failed': 'A system prerequisite or installation command failed; preserve backups and review at the console.',
    'command_timeout': 'A bounded system command timed out; preserve state and review at the console.',
    'sshd_config_invalid': 'Run sudo /usr/sbin/sshd -t at the console; the SSH service was not accepted.',
    'sshd_restore_failed': 'The SSHD candidate could not be safely restored. Preserve operator backups and review the fixed runner drop-in at the console.',
    'sshd_policy_mismatch': 'Review effective forced-command and forwarding settings for malpdf-runner; do not relax the policy.',
    'systemd_unit_invalid': 'Review systemd-analyze verify for the three gateway units; the probe has not been started by this step.',
    'systemd_reload_failed': 'Review the system manager at the console before retrying.',
    'containment_probe_failed': 'Read sudo systemctl status malpdf-gateway-probe.service --no-pager -l; preserve isolation and backups.',
    'forced_command_probe_failed': 'Review the fixed runner command refusals; do not enable shell or forwarding.',
    'ssh_reload_failed': 'Review SSH service status at the console; preserve backups.',
    'timer_enable_failed': 'Review the gateway timer status; the installation did not complete.',
    'runtime_layout_mismatch': 'Review the existing runtime layout; do not replace unexpected paths automatically.',
    'existing_worker_requires_review': 'Review existing worker processes before changing the installation.',
    'lock_type_mismatch': 'Review the expected regular gateway lock file; preserve existing state.',
    'validation_failed': 'Review installer prerequisites and operator backups at the console.',
}
COMMAND_FAILURES = {
    ('/usr/sbin/visudo', '-c'): 'sudo_policy_invalid',
    ('/usr/sbin/sshd', '-t'): 'sshd_config_invalid',
    ('/usr/sbin/sshd', '-T'): 'sshd_policy_mismatch',
    ('/usr/bin/systemd-analyze', 'verify'): 'systemd_unit_invalid',
    ('/usr/bin/systemctl', 'daemon-reload'): 'systemd_reload_failed',
    ('/usr/bin/systemctl', 'start'): 'containment_probe_failed',
    ('/usr/bin/systemctl', 'reload'): 'ssh_reload_failed',
    ('/usr/bin/systemctl', 'enable'): 'timer_enable_failed',
}


def failure_reason(error):
    if isinstance(error, subprocess.CalledProcessError):
        command = tuple(error.cmd[:2]) if isinstance(error.cmd, (list, tuple)) and all(isinstance(part, str) for part in error.cmd[:2]) else ()
        return COMMAND_FAILURES.get(command, 'command_failed')
    if isinstance(error, subprocess.TimeoutExpired):
        return 'command_timeout'
    if isinstance(error, FileNotFoundError):
        if error.filename == '/home/malpdf-audit/.ssh/authorized_keys':
            return 'audit_key_missing'
        return 'required_file_missing'
    if isinstance(error, PermissionError):
        return 'permission_denied'
    reason = str(error)
    return reason if isinstance(error, ValueError) and reason in FAILURE_HINTS else 'validation_failed'


def sshd_text():
    return '''Match User malpdf-runner
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PubkeyAcceptedAlgorithms ssh-ed25519
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile /var/lib/malpdf-gateway/runner-home/.ssh/authorized_keys
    AuthorizedKeysCommand none
    ForceCommand /usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_gateway.py
    DisableForwarding yes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
    PermitUserRC no
    MaxSessions 1
Match all
'''


def service(action):
    return '''[Unit]
Description=MalPDF restricted source-only gateway

[Service]
Type=oneshot
Slice=system.slice
User=malpdf-worker
Group=malpdf-worker
RootDirectory=/var/lib/malpdf-gateway/runtime
MountAPIVFS=yes
BindReadOnlyPaths=/usr
BindReadOnlyPaths=/etc/malpdf/gateway.json:/gateway.json /etc/malpdf/gateway-verified.json:/verified.json
BindReadOnlyPaths=/var/lib/malpdf-gateway/uploads:/source /var/lib/malpdf-gateway/requests:/requests
BindReadOnlyPaths=/sys/fs/cgroup/system.slice/%n:/limits
BindPaths=/var/lib/malpdf-gateway/reports:/reports /var/lib/malpdf-gateway/worker:/worker
WorkingDirectory=/tmp
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
PrivateIPC=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=~@mount @privileged @debug @raw-io @reboot @swap @network-io:EPERM
ReadWritePaths=/tmp /reports /worker
UMask=0027
MemoryMax=512M
MemorySwapMax=0
TasksMax=32
CPUQuota=50%
LimitAS=536870912
LimitCPU=60
LimitFSIZE=1048576
LimitNOFILE=64
LimitNPROC=32
LimitCORE=0
TimeoutStartSec=90
TimeoutStopSec=5
KillMode=control-group
StandardOutput=null
StandardError=null
ExecStart=/usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_gateway.py ''' + action + '\n'


def timer():
    return '''[Unit]
Description=Poll only prevalidated MalPDF job requests

[Timer]
OnBootSec=5
OnUnitInactiveSec=2
AccuracySec=1
Unit=malpdf-gateway.service

[Install]
WantedBy=timers.target
'''


def run(args, *, check=True, timeout=30, env=None):
    return subprocess.run(args, check=check, timeout=timeout, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def safe(path):
    if path.resolve() != path.absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('symlinked_destination')
    return path


def replace_sshd(payload, mode=0o644, gid=0):
    safe(DROPIN)
    descriptor, name = tempfile.mkstemp(prefix='.malpdf-runner-', dir=DROPIN.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, gid)
        temporary.chmod(mode)
        os.replace(temporary, DROPIN)
    finally:
        temporary.unlink(missing_ok=True)


def sshd_required():
    return ['forcecommand /usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_gateway.py',
            'disableforwarding yes', 'passwordauthentication no', 'kbdinteractiveauthentication no',
            'authenticationmethods publickey', 'authorizedkeysfile /var/lib/malpdf-gateway/runner-home/.ssh/authorized_keys',
            'authorizedkeyscommand none', 'permittty no', 'permituserrc no', 'permituserenvironment no',
            'allowagentforwarding no', 'allowtcpforwarding no', 'allowstreamlocalforwarding no',
            'x11forwarding no', 'permittunnel no', 'maxsessions 1']


def require_sshd_candidate(candidate):
    safe(DROPIN)
    if not DROPIN.is_file() or DROPIN.stat().st_size != len(candidate) or DROPIN.read_bytes() != candidate:
        raise ValueError('sshd_restore_failed')


def restore_sshd(backup, previous, candidate):
    try:
        require_sshd_candidate(candidate)
        write(backup / 'sshd.rejected', candidate, 0o600)
        if previous is None:
            DROPIN.unlink()
        else:
            replace_sshd(*previous)
    except BaseException:
        raise ValueError('sshd_restore_failed') from None


def validate_sshd(checkpoint=None):
    run(['/usr/sbin/sshd', '-t'])
    if checkpoint is not None:
        checkpoint('sshd_policy')
    effective = run(['/usr/sbin/sshd', '-T', '-C', 'user=malpdf-runner,addr=192.168.217.1,host=192.168.217.1,laddr=192.168.217.10,lport=22']).stdout.decode().splitlines()
    if not set(sshd_required()).issubset(effective):
        raise ValueError('sshd_policy_mismatch')


def activate_sshd(backup, previous, candidate):
    require_sshd_candidate(candidate)
    try:
        validate_sshd()
        require_sshd_candidate(candidate)
        run(['/usr/bin/systemctl', 'reload', 'ssh'])
    except BaseException:
        restore_sshd(backup, previous, candidate)
        raise


def configure_sshd(backup, checkpoint):
    safe(DROPIN)
    previous = None
    if DROPIN.exists():
        metadata = DROPIN.stat()
        if not DROPIN.is_file() or metadata.st_uid != 0 or metadata.st_mode & 0o022 or metadata.st_size > 16384:
            raise ValueError('destination_permissions')
        previous = (DROPIN.read_bytes(), stat.S_IMODE(metadata.st_mode), metadata.st_gid)
        write(backup / 'sshd.previous', previous[0], 0o600)
    candidate = sshd_text().encode()
    checkpoint('sshd_syntax')
    replace_sshd(candidate)
    try:
        validate_sshd(checkpoint)
    except BaseException:
        restore_sshd(backup, previous, candidate)
        raise
    return previous, candidate


def check_account(name, account):
    specifications = {'malpdf-runner': (BASE / 'runner-home', '/bin/sh'),
                      'malpdf-worker': (BASE / 'worker-home', '/usr/sbin/nologin')}
    if name not in specifications:
        raise ValueError('existing_account_requires_review')
    home, shell = specifications[name]
    if account.pw_uid < 1000 or account.pw_dir != str(home) or account.pw_shell != shell or set(run(['/usr/bin/id', '-nG', name]).stdout.decode().split()) != {name}:
        raise ValueError('existing_account_requires_review')
    process = run(['/usr/bin/pgrep', '-u', name], check=False).returncode
    if process == 0:
        raise ValueError('runner_process_present' if name == 'malpdf-runner' else 'worker_process_present')
    if process != 1:
        raise ValueError('account_process_check_failed')
    privileges = run(['/usr/bin/sudo', '-n', '-l', '-U', name], check=False,
                     env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    if privileges.returncode not in (0, 1) or not isinstance(privileges.stdout, bytes) or not isinstance(privileges.stderr, bytes) or len(privileges.stdout) > 16384 or privileges.stderr:
        raise ValueError('account_sudo_check_failed')
    subject = rb'User ' + re.escape(name.encode('ascii'))
    hostname = rb'[A-Za-z0-9][A-Za-z0-9._-]{0,252}'
    denial = subject + rb' is not allowed to run sudo on ' + hostname + rb'\.\n?'
    if re.fullmatch(denial, privileges.stdout):
        return
    listing = rb'(?m)^' + subject + rb' may run the following commands on ' + hostname + rb':\n'
    if privileges.returncode == 0 and re.search(listing, privileges.stdout):
        raise ValueError('runner_sudo_listing_allowed' if name == 'malpdf-runner' else 'worker_sudo_listing_allowed')
    raise ValueError('account_sudo_check_failed')


def configure_accounts():
    import pwd
    for name, home, shell in [('malpdf-runner', BASE / 'runner-home', '/bin/sh'), ('malpdf-worker', BASE / 'worker-home', '/usr/sbin/nologin')]:
        try:
            pwd.getpwnam(name)
        except KeyError:
            run(['/usr/sbin/useradd', '--no-create-home', '--user-group', '--home-dir', str(home), '--shell', shell, name])
        run(['/usr/sbin/usermod', '--lock', name])
        check_account(name, pwd.getpwnam(name))
        directory(home)
    return pwd.getpwnam('malpdf-runner'), pwd.getpwnam('malpdf-worker')


def preflight():
    if sys.platform != 'linux' or os.getuid() != 0:
        raise ValueError('operator_console_root_required')
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        raise ValueError('unsupported_python')
    import grp
    import pwd
    raw = (SOURCE / 'manifest.json').read_bytes()
    if len(raw) > 32768:
        raise ValueError('bootstrap_rejected')
    metadata = json.loads(raw)
    expected = {*HELPERS, 'setup_gateway.py', 'setup_gateway.sh', 'id_ed25519_malpdf_runner.pub'}
    if set(metadata) != {'api', 'base_commit', 'source_kind', 'files'} or type(metadata['api']) is not int or metadata['api'] != 1 or metadata['source_kind'] != 'reviewed_worktree_bootstrap' or not re.fullmatch('[0-9a-f]{40}', metadata['base_commit']):
        raise ValueError('bootstrap_rejected')
    if len(metadata['files']) != len(expected) or {item['path'] for item in metadata['files']} != expected or {path.name for path in SOURCE.iterdir()} != expected | {'manifest.json'}:
        raise ValueError('bootstrap_rejected')
    for item in metadata['files']:
        path = safe(SOURCE / item['path'])
        if set(item) != {'path', 'size', 'sha256'} or not path.is_file() or not 0 < item['size'] <= 2 * 1024**2:
            raise ValueError('bootstrap_rejected')
        payload = path.read_bytes()
        if len(payload) != item['size'] or hashlib.sha256(payload).hexdigest() != item['sha256']:
            raise ValueError('bootstrap_rejected')
    sys.path.insert(0, str(SOURCE))
    from lab_contract import parse_json, validate_public_key
    parse_json(raw)
    key = validate_public_key((SOURCE / 'id_ed25519_malpdf_runner.pub').read_bytes())
    audit_keys = Path('/home/malpdf-audit/.ssh/authorized_keys').read_text()
    if key.split()[1] in audit_keys:
        raise ValueError('runner_key_must_be_separate')
    try:
        pwd.getpwnam('malpdf-audit')
    except KeyError:
        raise ValueError('audit_account_missing') from None
    try:
        grp.getgrnam('malpdf-report-readers')
    except KeyError:
        raise ValueError('audit_group_missing') from None
    if not re.search(r'^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf\s*$', Path('/etc/ssh/sshd_config').read_text(), re.M):
        raise ValueError('sshd_include_required')
    run(['/usr/sbin/visudo', '-c'])
    run(['/usr/sbin/sshd', '-t'])
    for name, home, shell in [('malpdf-runner', str(BASE / 'runner-home'), '/bin/sh'), ('malpdf-worker', str(BASE / 'worker-home'), '/usr/sbin/nologin')]:
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            continue
        check_account(name, account)
    for path in [LIB, ETC, BASE, BASE / 'runtime', DROPIN, *(LIB / name for name in HELPERS), *(UNIT_DIR / name for name in UNITS), ETC / 'gateway.json', ETC / 'gateway-verified.json', ETC / 'gateway-installation.json']:
        safe(path)
        if path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise ValueError('destination_permissions')
    for name in ('uploads', 'requests', 'queued', 'reports', 'worker', 'submit.lock', 'runner-home', 'runner-home/.ssh', 'runner-home/.ssh/authorized_keys', 'worker-home'):
        safe(BASE / name)
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('systemd_required')
    if not {'memory', 'pids', 'cpu'}.issubset(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()):
        raise ValueError('cgroup_v2_controllers_required')
    print('PASS: exact bootstrap hashes, distinct public key, fixed destinations and account/SSHD prerequisites; no changes.')
    return metadata, key


def write(path, payload, mode=0o644):
    safe(path)
    path.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
    os.chown(path, 0, 0)
    path.chmod(mode)


def directory(path, uid=0, gid=0, mode=0o755):
    safe(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    path.chmod(mode)


def record_installation(backup, phase, status, policy_sha256=None, reason=None):
    from lab_diagnostics import stamp, validate_installation
    value = validate_installation({'api': 1, 'status': status, 'phase': phase, 'reason': reason,
                                   'policy_sha256': policy_sha256, 'generated_utc': stamp()})
    payload = json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'
    write(ETC / 'gateway-installation.json', payload)
    write(backup / 'installation.json', payload, 0o600)


def configure_gateway(key, allow_synthetic):
    import grp
    directory(LIB)
    runner, worker = configure_accounts()
    readers = grp.getgrnam('malpdf-report-readers').gr_gid
    directory(BASE / 'uploads', runner.pw_uid, worker.pw_gid, 0o2750)
    directory(BASE / 'requests', runner.pw_uid, worker.pw_gid, 0o2750)
    directory(BASE / 'queued', runner.pw_uid, readers, 0o2750)
    directory(BASE / 'reports', worker.pw_uid, readers, 0o2750)
    directory(BASE / 'worker', worker.pw_uid, worker.pw_gid, 0o700)
    lock = safe(BASE / 'submit.lock')
    if not lock.exists():
        lock.touch(mode=0o600)
    if not lock.is_file():
        raise ValueError('lock_type_mismatch')
    os.chown(lock, runner.pw_uid, runner.pw_gid)
    lock.chmod(0o600)
    directory(BASE / 'runner-home/.ssh')
    for name in HELPERS:
        write(LIB / name, (SOURCE / name).read_bytes())
    public = ' '.join(key.split()[:2]) + ' malpdf-runner-gateway'
    write(BASE / 'runner-home/.ssh/authorized_keys', 'restrict,from="192.168.217.1",command="/usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_gateway.py" ' + public + '\n')
    root = BASE / 'runtime'
    directory(root)
    for name in ('usr', 'tmp', 'proc', 'dev', 'sys', 'run', 'source', 'requests', 'reports', 'worker', 'limits'):
        directory(root / name, mode=0o1777 if name == 'tmp' else 0o755)
    for name, destination in [('lib', 'usr/lib'), ('lib64', 'usr/lib64'), ('bin', 'usr/bin'), ('sbin', 'usr/sbin')]:
        path = root / name
        if path.is_symlink():
            if os.readlink(path) != destination:
                raise ValueError('runtime_layout_mismatch')
        elif path.exists():
            raise ValueError('runtime_layout_mismatch')
        else:
            path.symlink_to(destination)
    for name in ('gateway.json', 'verified.json'):
        write(root / name, '{}\n')
    units = {UNITS[0]: service('worker'), UNITS[1]: service('probe'), UNITS[2]: timer()}
    for name, payload in units.items():
        write(UNIT_DIR / name, payload)
    policy = {name: hashlib.sha256((LIB / name).read_bytes()).hexdigest() for name in HELPERS}
    from gateway_contract import encoded, sha
    cfg = {'api': 1, 'runner_uid': runner.pw_uid, 'worker_uid': worker.pw_uid, 'policy': policy,
           'policy_sha256': sha(encoded(policy)), 'profiles': ['syntax', 'synthetic'] if allow_synthetic else ['syntax'],
           'units': {name: sha(payload.encode()) for name, payload in units.items()}, 'sshd_sha256': sha(sshd_text().encode())}
    write(ETC / 'gateway.json', encoded(cfg) + b'\n')
    write(ETC / 'gateway-verified.json', '{}\n')
    return cfg


def install(key, allow_synthetic):
    from gateway_contract import encoded
    backup = Path(tempfile.mkdtemp(prefix='malpdf-gateway-setup-', dir='/var/tmp'))
    backup.chmod(0o700)
    targets = [*(LIB / name for name in HELPERS), *(UNIT_DIR / name for name in UNITS), DROPIN, ETC / 'gateway.json', ETC / 'gateway-verified.json', ETC / 'gateway-installation.json', BASE / 'runner-home/.ssh/authorized_keys']
    for index, path in enumerate(targets):
        if path.exists():
            shutil.copy2(path, backup / (str(index) + '-' + path.name))
    (backup / 'targets.json').write_text(json.dumps([str(path) for path in targets]))
    cfg = None
    phase = 'configuration'
    def checkpoint(name):
        nonlocal phase
        phase = name
        record_installation(backup, name, 'running', cfg['policy_sha256'] if cfg else None)
    try:
        directory(BASE)
        directory(ETC)
        checkpoint('configuration')
        write(ETC / 'gateway-verified.json', '{}\n')
        if (UNIT_DIR / 'malpdf-gateway.timer').exists():
            run(['/usr/bin/systemctl', 'stop', 'malpdf-gateway.timer'])
            process = run(['/usr/bin/pgrep', '-u', 'malpdf-worker'], check=False).returncode
            if process not in (0, 1):
                raise ValueError('account_process_check_failed')
            if process == 0:
                raise ValueError('existing_worker_requires_review')
        cfg = configure_gateway(key, allow_synthetic)
        previous_sshd, candidate_sshd = configure_sshd(backup, checkpoint)
        phase = 'unit_validation'
        checkpoint(phase)
        run(['/usr/bin/systemd-analyze', 'verify', *(str(UNIT_DIR / name) for name in UNITS)])
        phase = 'manager_reload'
        checkpoint(phase)
        run(['/usr/bin/systemctl', 'daemon-reload'])
        phase = 'containment'
        checkpoint(phase)
        run(['/usr/bin/systemctl', 'start', 'malpdf-gateway-probe.service'], timeout=100)
        from lab_contract import parse_json
        proof_path = BASE / 'reports/probe.json'
        if proof_path.is_symlink() or proof_path.stat().st_size > 4096:
            raise ValueError('containment_probe_failed')
        proof = parse_json(proof_path.read_bytes())
        expected = {'api': 1, 'policy_sha256': cfg['policy_sha256'], 'checks': {'nonroot': True, 'network_denied': True, 'source_readonly': True, 'host_data_hidden': True, 'resource_limits': True}}
        if proof != expected:
            raise ValueError('containment_probe_failed')
        phase = 'command_refusals'
        checkpoint(phase)
        for original in ('id', '', 'sftp', 'submit-pdf ' + 'a' * 64, 'submit-syntax ../escape'):
            result = run(['/usr/sbin/runuser', '-u', 'malpdf-runner', '--', '/usr/bin/env', '-i', 'SSH_ORIGINAL_COMMAND=' + original,
                '/usr/bin/python3', '-Es', '-B', str(LIB / 'lab_gateway.py')], check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('forced_command_probe_failed')
        approved = {'api': 1, 'verified': True, 'policy_sha256': cfg['policy_sha256'], 'profiles': cfg['profiles'], 'units': cfg['units'], 'sshd_sha256': cfg['sshd_sha256']}
        write(ETC / 'gateway-verified.json', encoded(approved) + b'\n')
        phase = 'ssh_reload'
        checkpoint(phase)
        activate_sshd(backup, previous_sshd, candidate_sshd)
        phase = 'timer_enable'
        checkpoint(phase)
        run(['/usr/bin/systemctl', 'enable', '--now', 'malpdf-gateway.timer'])
        record_installation(backup, 'complete', 'passed', cfg['policy_sha256'])
    except BaseException as error:
        try:
            write(ETC / 'gateway-verified.json', '{}\n')
        except (OSError, ValueError):
            print('Verification invalidation could not be saved; operator recovery is required.')
        try:
            record_installation(backup, phase, 'failed', cfg['policy_sha256'] if cfg else None, failure_reason(error))
        except (OSError, ValueError):
            print('Installation diagnostic checkpoint could not be saved; preserve the operator backup.')
        print('NOT READY: installation/probe failed. Timer not accepted; review console and backups: ' + str(backup))
        raise
    print('Installed restricted gateway. Operator backups: ' + str(backup))
    print('Windows must still verify live shell, subsystem, PDF/argument and forwarding refusals before submitting source.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('--check', '--install'), nargs='?', default='--check')
    parser.add_argument('--allow-synthetic', action='store_true')
    values = list(sys.argv[1:] if argv is None else argv)
    action = values.pop(0) if values and values[0] in ('--check', '--install') else '--check'
    args = parser.parse_args(values)
    stage = 'preflight'
    try:
        _, key = preflight()
        if action == '--install':
            stage = 'installation'
            install(key, args.allow_synthetic)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        reason = failure_reason(error)
        print('NOT READY [' + stage + '/' + reason + ']: ' + FAILURE_HINTS[reason])
        print('No automatic networking, sudo policy or dependency changes are attempted.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
