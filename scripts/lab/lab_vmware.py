"""Read only fixed VMware metadata without guest execution or credentials."""

import ipaddress
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

VMRUNS = (Path('C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe'),
          Path('C:/Program Files/VMware/VMware Workstation/vmrun.exe'))
VMX = Path('C:/VirtualMachine/Remnux.vmx')
EXPECTED_IP = '192.168.217.10'


def query(binary, action):
    commands = {'list': ['list'], 'tools': ['checkToolsState', str(VMX)],
                'address': ['getGuestIPAddress', str(VMX)], 'snapshots': ['listSnapshots', str(VMX)]}
    if action not in commands:
        raise ValueError('vmware_action_rejected')
    try:
        result = subprocess.run([str(binary), '-T', 'ws', *commands[action]],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, check=False)
        if result.returncode or len(result.stdout) > 4096:
            return None
        return result.stdout.decode('utf-8', 'strict').strip('\r\n')
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def collect():
    result = {'vm_running': None, 'tools': 'unknown', 'guest_ipv4': None,
              'expected_ipv4': EXPECTED_IP, 'address_matches': None,
              'reason': 'vmware_metadata_unavailable'}
    if sys.platform != 'win32':
        return result
    binary = next((path for path in VMRUNS if path.is_file()), None)
    if binary is None:
        return result
    listing = query(binary, 'list')
    lines = listing.splitlines() if listing is not None else []
    header = re.fullmatch(r'Total running VMs: ([0-9]{1,2})', lines[0]) if lines else None
    if not header or len(lines) != int(header[1]) + 1:
        return result
    result['vm_running'] = any(line.replace('\\', '/').casefold() == VMX.as_posix().casefold() for line in lines[1:])
    if not result['vm_running']:
        result['reason'] = 'vm_not_running'
        return result
    tools = query(binary, 'tools')
    result['tools'] = tools if tools in ('running', 'installed', 'not_installed') else 'unknown'
    result['reason'] = 'guest_ip_unavailable'
    if tools != 'running':
        return result
    address = query(binary, 'address')
    try:
        parsed = ipaddress.IPv4Address(address) if address is not None else None
    except ipaddress.AddressValueError:
        return result
    if parsed is None or parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved:
        return result
    result['guest_ipv4'] = str(parsed)
    result['address_matches'] = str(parsed) == EXPECTED_IP
    result['reason'] = None if result['address_matches'] else 'guest_ip_mismatch'
    return result


def configuration_isolation(raw):
    if not isinstance(raw, bytes) or len(raw) > 1048576:
        raise ValueError('vmware_configuration_invalid')
    fields = {}
    for line in raw.decode('utf-8-sig', 'strict').splitlines():
        key, separator, value = line.partition('=')
        key = key.strip().casefold()
        relevant = re.fullmatch(r'ethernet[0-9]{1,2}\.(present|connectiontype|vnet|startconnected)', key) or re.fullmatch(r'sharedfolder[0-9]{1,3}\.(present|enabled)', key) or key in {'isolation.tools.copy.disable', 'isolation.tools.paste.disable', 'isolation.tools.dnd.disable', 'isolation.tools.hgfs.disable', 'sharedfolder.maxnum'}
        if not relevant:
            continue
        value = value.strip()
        if not separator or key in fields or len(value) > 128 or not re.fullmatch(r'"[^"\r\n]*"', value):
            raise ValueError('vmware_configuration_invalid')
        fields[key] = value[1:-1].casefold()
    def disabled(name):
        return {'true': 'disabled', 'false': 'enabled'}.get(fields.get(name), 'unverified')
    clipboard = [disabled('isolation.tools.' + name + '.disable') for name in ('copy', 'paste')]
    adapters = [key.removesuffix('.present') for key, value in fields.items() if key.startswith('ethernet') and key.endswith('.present') and value == 'true']
    invalid_adapter = any(value not in ('true', 'false') for key, value in fields.items() if key.startswith('ethernet') and key.endswith('.present'))
    network = 'host_only' if len(adapters) == 1 and not invalid_adapter and fields.get(adapters[0] + '.connectiontype') == 'hostonly' and fields.get(adapters[0] + '.vnet', 'vmnet1') == 'vmnet1' else 'unverified'
    shares = disabled('isolation.tools.hgfs.disable')
    if any(value != 'false' for key, value in fields.items() if key.startswith('sharedfolder') and key.endswith(('.present', '.enabled'))):
        shares = 'enabled'
    return {'vmx_sha256': hashlib.sha256(raw).hexdigest(), 'configured_adapter_count': len(adapters),
        'network_configuration': network, 'copy_paste': 'disabled' if clipboard == ['disabled', 'disabled'] else 'enabled' if 'enabled' in clipboard else 'unverified',
        'drag_drop': disabled('isolation.tools.dnd.disable'), 'shared_folders': shares}


def isolation():
    value = {'api': 1, 'configuration': None, 'snapshot_count': None, 'vm_running': None,
             'runtime_nics_disconnected': None, 'guest_controls_verified': False, 'ready_for_real_pdf': False,
             'reason': 'vmware_isolation_unverified'}
    if sys.platform != 'win32':
        return value
    try:
        if VMX.resolve() != VMX.absolute() or any(path.is_symlink() for path in (VMX, *VMX.parents)):
            return value
        with VMX.open('rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return value
            value['configuration'] = configuration_isolation(stream.read(1048577))
    except (OSError, ValueError, UnicodeError):
        return value
    binary = next((path for path in VMRUNS if path.is_file()), None)
    if binary is not None:
        listing = query(binary, 'list')
        lines = listing.splitlines() if listing is not None else []
        header = re.fullmatch(r'Total running VMs: ([0-9]{1,2})', lines[0]) if lines else None
        if header and len(lines) == int(header[1]) + 1:
            value['vm_running'] = any(line.replace('\\', '/').casefold() == VMX.as_posix().casefold() for line in lines[1:])
        snapshots = query(binary, 'snapshots')
        lines = snapshots.splitlines() if snapshots is not None else []
        header = re.fullmatch(r'Total snapshots: ([0-9]{1,3})', lines[0]) if lines else None
        if header and len(lines) == int(header[1]) + 1:
            value['snapshot_count'] = int(header[1])
    value['reason'] = 'operator_isolation_review_required'
    return value
