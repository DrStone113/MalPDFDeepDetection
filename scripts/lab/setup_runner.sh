#!/bin/sh
set -eu

ACTION=${1:---check}
case "$ACTION" in
  --check|--install) ;;
  --help) echo 'sudo sh setup_runner.sh --check|--install'; exit 0 ;;
  *) echo 'Use --check or --install' >&2; exit 2 ;;
esac
SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ "$(id -u)" -ne 0 ] || [ "$(uname -s)" != Linux ]; then
  echo 'Run once from the REMnux console as the operator using sudo.' >&2
  exit 2
fi
/usr/bin/python3 -Es -B - "$SOURCE_DIR" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sys
sys.excepthook=lambda *unused: sys.stderr.write('Setup preflight failed: review bootstrap checksums, remnux account, data root and destination permissions. No changes applied.\n')
source=Path(sys.argv[1])
meta=json.loads((source/'manifest.json').read_text())
expected={'lab_contract.py','lab_readonly.py','lab_side.py','setup_readonly.sh','lab_jobs.py','lab_runner.py','setup_runner.sh','check_local.py','lab_guard.py','id_ed25519_malpdf_audit.pub'}
assert type(meta['schema_version']) is int and meta['schema_version']==1 and re.fullmatch('[0-9a-f]{40}',meta['commit'])
assert len(meta['files'])==len(expected)
assert {item['path'] for item in meta['files']}==expected
assert {path.name for path in source.iterdir()}==expected|{'manifest.json'}
for item in meta['files']:
    path=source/item['path']
    assert path.is_file() and not path.is_symlink()
    payload=path.read_bytes()
    assert len(payload)==item['size'] and hashlib.sha256(payload).hexdigest()==item['sha256']
sys.path.insert(0,str(source))
from lab_contract import parse_json,validate_public_key
parse_json((source/'manifest.json').read_bytes())
validate_public_key((source/'id_ed25519_malpdf_audit.pub').read_bytes())
account=pwd.getpwnam('remnux')
assert account.pw_uid>=1000
data=Path('/home/remnux/MalPDFDeepDetection')
assert data.is_dir() and data.resolve()==data
for name in ('/usr/local/libexec/malpdf','/usr/local/bin/lab','/etc/malpdf','/etc/malpdf/runner.json','/var/lib/malpdf/jobs','/home/remnux/malpdf-inbox','/home/remnux/malpdf-releases','/usr/share/applications/malpdf-lab.desktop','/home/remnux/Desktop/MalPDF LAB Runner.desktop'):
    path=Path(name)
    assert path.resolve()==path.absolute() and not path.is_symlink()
    if path.exists() and str(path).startswith(('/usr/','/etc/')):
        assert path.stat().st_uid==0 and not path.stat().st_mode & 0o022
print('PASS: bootstrap identity, fixed destinations and remnux account; no changes yet.')
PY
if [ "$ACTION" = --check ]; then exit 0; fi
BACKUP_DIR=$(mktemp -d /var/tmp/malpdf-runner-setup.XXXXXX)
chmod 0700 "$BACKUP_DIR"
install -d -o root -g root -m 0755 /usr/local/libexec/malpdf /etc/malpdf
for NAME in lab_contract.py lab_readonly.py lab_side.py lab_jobs.py lab_runner.py check_local.py lab_guard.py; do
  if [ -f "/usr/local/libexec/malpdf/$NAME" ]; then cp -p "/usr/local/libexec/malpdf/$NAME" "$BACKUP_DIR/$NAME"; fi
  install -o root -g root -m 0644 "$SOURCE_DIR/$NAME" "/usr/local/libexec/malpdf/$NAME"
done
for TARGET in /usr/local/bin/lab /etc/malpdf/runner.json /usr/share/applications/malpdf-lab.desktop; do
  if [ -f "$TARGET" ]; then cp -p "$TARGET" "$BACKUP_DIR/$(basename "$TARGET")"; fi
done
cat > /usr/local/bin/lab <<'SH'
#!/bin/sh
exec /usr/bin/python3 -Es -B /usr/local/libexec/malpdf/lab_runner.py "$@"
SH
chmod 0755 /usr/local/bin/lab
/usr/bin/python3 -Es -B - <<'PY'
import json
from pathlib import Path
import pwd
root=Path('/home/remnux/MalPDFDeepDetection')
python=root/'.venv/bin/python'
if not python.is_file():python=Path('/usr/bin/python3')
config={'schema_version':1,'data_root':str(root),'python':str(python),'uid':pwd.getpwnam('remnux').pw_uid}
Path('/etc/malpdf/runner.json').write_text(json.dumps(config,sort_keys=True)+'\n')
PY
chmod 0644 /etc/malpdf/runner.json
install -d -o remnux -g remnux -m 0700 /var/lib/malpdf/jobs
install -d -o remnux -g remnux -m 0750 /home/remnux/malpdf-inbox /home/remnux/malpdf-releases
cat > /usr/share/applications/malpdf-lab.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=MalPDF LAB Runner
Comment=Run approved local jobs; never reconnect networking
Exec=/usr/local/bin/lab menu
Terminal=true
Icon=utilities-terminal
Categories=Development;
DESKTOP
chmod 0644 /usr/share/applications/malpdf-lab.desktop
if [ -d /home/remnux/Desktop ] && [ ! -e '/home/remnux/Desktop/MalPDF LAB Runner.desktop' ]; then
  install -o remnux -g remnux -m 0755 /usr/share/applications/malpdf-lab.desktop '/home/remnux/Desktop/MalPDF LAB Runner.desktop'
fi
sh "$SOURCE_DIR/setup_readonly.sh" "$SOURCE_DIR/id_ed25519_malpdf_audit.pub" "$SOURCE_DIR"
echo "Runner installed. Backups: $BACKUP_DIR"
echo 'No dependencies, NICs, routes, firewalls, datasets or current releases were changed.'
