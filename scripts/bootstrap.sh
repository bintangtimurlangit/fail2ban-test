#!/usr/bin/env bash
set -euo pipefail

# Bootstrap environment for Fail2Ban replay container.

if [[ $EUID -ne 0 ]]; then
  echo "[bootstrap] Please run as root (sudo ./bootstrap.sh)"
  exit 1
fi

APT_PACKAGES=(
  fail2ban
  rsyslog
  libfaketime
  faketime
  python3
  python3-venv
  python3-pip
  pv
)

echo "[bootstrap] Updating package index"
apt-get update -y

echo "[bootstrap] Installing packages: ${APT_PACKAGES[*]}"
apt-get install -y "${APT_PACKAGES[@]}"

VENVDIR=${VENVDIR:-/opt/f2b-replay}
if [[ ! -d "${VENVDIR}" ]]; then
  echo "[bootstrap] Creating virtualenv at ${VENVDIR}"
  python3 -m venv "${VENVDIR}"
fi

source "${VENVDIR}/bin/activate"
echo "[bootstrap] Installing Python deps"
pip install --upgrade pip
pip install pandas pyarrow
deactivate

ACTION_TARGET=/usr/local/bin/f2b_action_logger.py
if [[ ! -f "${ACTION_TARGET}" ]]; then
  echo "[bootstrap] Installing action_logger helper to ${ACTION_TARGET}"
  install -m 0755 "$(dirname "$0")/action_logger.py" "${ACTION_TARGET}"
else
  echo "[bootstrap] action_logger already present at ${ACTION_TARGET}"
fi

echo "[bootstrap] Verifying commands"
for cmd in fail2ban-client faketime logger python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[bootstrap] ERROR: $cmd not found in PATH"
    exit 1
  fi
done

echo "[bootstrap] Done. Remember to configure ssh-proxmox jail/filter."


