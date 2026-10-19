#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo 'Run with sudo locally in the REMnux VM console' >&2
  exit 1
fi
if [ "$#" -ne 2 ]; then
  echo 'Usage: sudo sh setup_readonly.sh /path/to/id_ed25519_malpdf_audit.pub /path/to/bootstrap-directory' >&2
  exit 1
fi
KEY_FILE=$1
SOURCE_DIR=$2
if [ ! -f "$KEY_FILE" ] || [ ! -f "$SOURCE_DIR/lab_readonly.py" ] || [ ! -f "$SOURCE_DIR/lab_side.py" ]; then
  echo 'Missing public key or LAB-side scripts' >&2
  exit 1
fi
KEY=$(cat "$KEY_FILE")
case "$KEY" in
  ssh-ed25519\ *) ;;
  *) echo 'Require an ed25519 SSH public key' >&2; exit 1 ;;
esac

if ! getent group malpdf-report-readers >/dev/null; then
  groupadd --system malpdf-report-readers
fi
if ! id malpdf-audit >/dev/null 2>&1; then
  useradd --create-home --shell /bin/sh --comment 'MalPDF report-only SSH' malpdf-audit
fi
usermod -aG malpdf-report-readers malpdf-audit

install -d -o root -g root -m 0755 /usr/local/libexec/malpdf
install -o root -g root -m 0755 "$SOURCE_DIR/lab_readonly.py" /usr/local/libexec/malpdf/lab_readonly.py
install -o root -g root -m 0755 "$SOURCE_DIR/lab_side.py" /usr/local/libexec/malpdf/lab_side.py
install -d -o root -g root -m 0755 /var/lib/malpdf
install -d -o root -g root -m 0755 /var/lib/malpdf/reports
install -d -o remnux -g malpdf-report-readers -m 2750 /var/lib/malpdf/reports/approved
chmod 2750 /var/lib/malpdf/reports/approved

HOME_DIR=/home/malpdf-audit
install -d -o root -g root -m 0755 "$HOME_DIR/.ssh"
printf '%s\n' "restrict,command=\"/usr/bin/python3 /usr/local/libexec/malpdf/lab_readonly.py\" $KEY" > "$HOME_DIR/.ssh/authorized_keys"
chown root:root "$HOME_DIR/.ssh/authorized_keys"
chmod 0644 "$HOME_DIR/.ssh/authorized_keys"
chown root:root "$HOME_DIR"
chmod 0755 "$HOME_DIR"

if id -nG malpdf-audit | grep -Eq '(^| )sudo( |$)'; then
  echo 'ERROR: audit account unexpectedly has sudo group access' >&2
  exit 1
fi

echo 'Reader installed with root-owned authorized_keys and forced command.'
echo 'This script intentionally DOES NOT alter system SSH/network configuration.'
echo 'Verify sshd allows key authentication and forbids password login for malpdf-audit.'
