#!/usr/bin/env bash
set -euo pipefail

: "${CTVLMS_LAB_REPO_URL:=http://172.28.77.5:8080}"
pubkey=/run/ctvlms-lab/id_ed25519.pub
[[ -s "$pubkey" ]] || { echo "Missing lab SSH public key" >&2; exit 1; }

for user in ctvlms-inventory ctvlms-patcher; do
  home="/home/$user"
  install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
  install -o "$user" -g "$user" -m 0600 "$pubkey" "$home/.ssh/authorized_keys"
done

# Make the remediation source deterministic: these disposable targets use only
# the internal lab repository after boot. The failure target intentionally points
# this URL at a closed local port.
rm -f /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/debian.sources
printf 'deb [trusted=yes] %s ./\n' "$CTVLMS_LAB_REPO_URL" > /etc/apt/sources.list.d/ctvlms-lab.list
rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial /run/sshd
ssh-keygen -A >/dev/null 2>&1
exec /usr/sbin/sshd -D -e
