#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 2 ]; then
  echo 'Operator only, from the REMnux console: sudo sh setup_readonly.sh PUBLIC_KEY BOOTSTRAP_DIR' >&2
  exit 1
fi
KEY_FILE=$1
SOURCE_DIR=$2
for CHECKED_PATH in /usr/local/libexec/malpdf /home/malpdf-audit /home/malpdf-audit/.ssh /home/malpdf-audit/.ssh/authorized_keys /var/lib/malpdf /var/lib/malpdf/reports /var/lib/malpdf/reports/approved; do
  if [ -L "$CHECKED_PATH" ]; then
    echo 'Refusing a symlinked audit installation path' >&2
    exit 1
  fi
done
if [ ! -x /usr/bin/sudo ] || [ ! -x /usr/sbin/visudo ] || ! /usr/sbin/visudo -c >/dev/null; then
  echo 'Cannot verify sudo policy; no changes applied' >&2
  exit 1
fi
for NAME in lab_readonly.py lab_side.py lab_contract.py; do
  if [ ! -f "$SOURCE_DIR/$NAME" ] || [ -L "$SOURCE_DIR/$NAME" ] || [ -L "/usr/local/libexec/malpdf/$NAME" ]; then
    echo 'Missing or symlinked reviewed bootstrap source' >&2
    exit 1
  fi
done
KEY=$(/usr/bin/python3 -Es - "$KEY_FILE" "$SOURCE_DIR" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[2])
from lab_contract import validate_public_key
path = Path(sys.argv[1])
if path.is_symlink() or path.stat().st_size > 1024:
    raise SystemExit("Invalid public key file")
print(validate_public_key(path.read_bytes()))
PY
)
if id malpdf-audit >/dev/null 2>&1; then
  if [ "$(getent passwd malpdf-audit | cut -d: -f6)" != /home/malpdf-audit ] || [ "$(id -u malpdf-audit)" -lt 1000 ]; then
    echo 'Unexpected existing audit account; stop for operator review' >&2
    exit 1
  fi
  for GROUP in $(id -nG malpdf-audit); do
    case "$GROUP" in
      malpdf-audit|malpdf-report-readers) ;;
      *) echo 'Audit account has unexpected group privileges; stop for review' >&2; exit 1 ;;
    esac
  done
  if pgrep -u malpdf-audit >/dev/null; then
    echo 'Existing audit processes/sessions require console review before reconfiguration' >&2
    exit 1
  fi
  if /usr/bin/sudo -n -l -U malpdf-audit >/dev/null 2>&1; then
    echo 'Audit account has sudo grants; remove them through a separate approved change' >&2
    exit 1
  fi
fi
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf([[:space:]]|$)' /etc/ssh/sshd_config; then
  echo 'Expected Ubuntu SSHD Include missing; no automatic main-config edits' >&2
  exit 1
fi
BACKUP_DIR=$(mktemp -d /var/tmp/malpdf-audit-setup.XXXXXX)
chmod 0700 "$BACKUP_DIR"
DROPIN=/etc/ssh/sshd_config.d/00-malpdf-audit.conf
if [ -L "$DROPIN" ]; then
  echo 'Refusing symlinked SSHD drop-in' >&2
  exit 1
fi
if [ -e "$DROPIN" ]; then
  cp -p "$DROPIN" "$BACKUP_DIR/sshd.previous"
fi
for NAME in lab_readonly.py lab_side.py lab_contract.py; do
  if [ -f "/usr/local/libexec/malpdf/$NAME" ]; then
    cp -p "/usr/local/libexec/malpdf/$NAME" "$BACKUP_DIR/$NAME"
  fi
done
if [ -f /home/malpdf-audit/.ssh/authorized_keys ]; then
  cp -p /home/malpdf-audit/.ssh/authorized_keys "$BACKUP_DIR/authorized_keys.previous"
fi
if ! getent group malpdf-report-readers >/dev/null; then
  groupadd --system malpdf-report-readers
fi
if ! id malpdf-audit >/dev/null 2>&1; then
  useradd --create-home --user-group --shell /bin/sh --comment 'MalPDF report-only SSH' malpdf-audit
fi
usermod --lock --shell /bin/sh --append --groups malpdf-report-readers malpdf-audit
install -d -o root -g root -m 0755 /usr/local/libexec/malpdf
for NAME in lab_readonly.py lab_side.py lab_contract.py; do
  install -o root -g root -m 0644 "$SOURCE_DIR/$NAME" "/usr/local/libexec/malpdf/$NAME"
done
install -d -o root -g root -m 0755 /var/lib/malpdf /var/lib/malpdf/reports
install -d -o remnux -g malpdf-report-readers -m 2750 /var/lib/malpdf/reports/approved
install -d -o root -g root -m 0755 /home/malpdf-audit /home/malpdf-audit/.ssh
printf '%s\n' "restrict,from=\"192.168.217.1\",command=\"/usr/bin/python3 -Es /usr/local/libexec/malpdf/lab_readonly.py\" $KEY" > /home/malpdf-audit/.ssh/authorized_keys
chown root:root /home/malpdf-audit/.ssh/authorized_keys
chmod 0644 /home/malpdf-audit/.ssh/authorized_keys

restore_dropin() {
  if [ -f "$BACKUP_DIR/sshd.previous" ]; then
    cp -p "$BACKUP_DIR/sshd.previous" "$DROPIN"
  else
    rm -f "$DROPIN"
  fi
  echo "SSHD drop-in restored. Account/helper changes require console review; backups: $BACKUP_DIR" >&2
}
trap 'restore_dropin' EXIT
trap 'exit 1' HUP INT TERM
cat > "$DROPIN" <<'CONF'
Match User malpdf-audit
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PubkeyAcceptedAlgorithms ssh-ed25519
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile /home/malpdf-audit/.ssh/authorized_keys
    AuthorizedKeysCommand none
    ForceCommand /usr/bin/python3 -Es /usr/local/libexec/malpdf/lab_readonly.py
    DisableForwarding yes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
    PermitUserRC no
Match all
CONF
chown root:root "$DROPIN"
chmod 0644 "$DROPIN"
if ! /usr/sbin/sshd -t; then
  restore_dropin
  exit 1
fi
if ! /usr/sbin/sshd -T -C user=malpdf-audit,addr=192.168.217.1,host=192.168.217.1,laddr=192.168.217.10,lport=22 > "$BACKUP_DIR/sshd.effective"; then
  restore_dropin
  exit 1
fi
for REQUIRED in \
  'authenticationmethods publickey' \
  'pubkeyauthentication yes' \
  'pubkeyacceptedalgorithms ssh-ed25519' \
  'passwordauthentication no' \
  'kbdinteractiveauthentication no' \
  'authorizedkeysfile /home/malpdf-audit/.ssh/authorized_keys' \
  'authorizedkeyscommand none' \
  'forcecommand /usr/bin/python3 -Es /usr/local/libexec/malpdf/lab_readonly.py' \
  'disableforwarding yes' \
  'allowtcpforwarding no' \
  'allowstreamlocalforwarding no' \
  'allowagentforwarding no' \
  'x11forwarding no' \
  'permittunnel no' \
  'permittty no' \
  'permituserrc no' \
  'permituserenvironment no'; do
  if ! grep -Fxq "$REQUIRED" "$BACKUP_DIR/sshd.effective"; then
    restore_dropin
    echo 'Effective audit SSHD settings differ; service was not reloaded' >&2
    exit 1
  fi
done
if ! systemctl reload ssh; then
  restore_dropin
  exit 1
fi
trap - EXIT HUP INT TERM
echo "Audit account installed; SSHD checked and reloaded. Root-only backups: $BACKUP_DIR"
echo 'No network, firewall, dataset or Python-environment changes were made.'
echo 'Verify live refusal tests and sudo policy from the console before accepting this setup.'
