#!/usr/bin/env bash
set -euo pipefail

# Orchestrate a full Fail2Ban replay run inside the LXC container.
# Requires rsyslog and fail2ban installed plus faketime for service wrapping.

: "${DATA_ROOT:=/mnt/replay/fail2ban-test}"
: "${LOG_FILE:=${DATA_ROOT}/benchmark.log}"
: "${PARQUET_FILE:=${DATA_ROOT}/benchmark.parquet}"
: "${RESULTS_ROOT:=${DATA_ROOT}/results}"
: "${RUN_ID:=$(date +%Y%m%d-%H%M%S)}"
: "${JAIL_NAME:=ssh-proxmox}"
: "${FAKETIME_SPEC:=-0d}"
: "${REPLAY_SPEED:=600}"
: "${SLEEP_CAP:=0.1}"
: "${LOGGER_CMD:=logger --priority authpriv.info --tag replay}"

RESULTS_DIR="${RESULTS_ROOT}/${RUN_ID}"
mkdir -p "${RESULTS_DIR}"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[orchestrate] Missing required command: $cmd" >&2
    exit 1
  fi
}

require_cmd fail2ban-client
require_cmd faketime
require_cmd logger
require_cmd python3

echo "[orchestrate] run_id=${RUN_ID}"
echo "[orchestrate] data_root=${DATA_ROOT}"

echo "[orchestrate] stopping services"
systemctl stop fail2ban || true
systemctl stop rsyslog || true

echo "[orchestrate] flushing firewall chain"
if command -v iptables >/dev/null 2>&1; then
  iptables -F "f2b-${JAIL_NAME}" || true
fi

echo "[orchestrate] starting rsyslog under faketime"
faketime "${FAKETIME_SPEC}" systemctl start rsyslog

echo "[orchestrate] starting fail2ban under faketime"
faketime "${FAKETIME_SPEC}" systemctl start fail2ban

sleep 2
echo "[orchestrate] baseline jail status"
fail2ban-client status "${JAIL_NAME}" > "${RESULTS_DIR}/status_before.txt"

echo "[orchestrate] launching replay with faketime timestamp matching"
python3 "${DATA_ROOT}/scripts/replay.py" \
  --log-file "${LOG_FILE}" \
  --parquet "${PARQUET_FILE}" \
  --speed-factor "${REPLAY_SPEED}" \
  --sleep-cap "${SLEEP_CAP}" \
  --logger-cmd "${LOGGER_CMD}" \
  --status-interval 5000 \
  --use-faketime \
  2>&1 | tee "${RESULTS_DIR}/replay.log"

echo "[orchestrate] jail status after replay"
fail2ban-client status "${JAIL_NAME}" > "${RESULTS_DIR}/status_after.txt"

echo "[orchestrate] collecting metrics"
python3 "${DATA_ROOT}/scripts/collect_fail2ban.py" \
  --parquet "${PARQUET_FILE}" \
  --actions-log /var/log/f2b-actions.json \
  --fail2ban-log /var/log/fail2ban.log \
  --output "${RESULTS_DIR}/metrics.json" \
  --history "${RESULTS_ROOT}/history.json" \
  --run-id "${RUN_ID}"

echo "[orchestrate] archiving logs"
cp /var/log/fail2ban.log "${RESULTS_DIR}/fail2ban.log"
cp /var/log/f2b-actions.json "${RESULTS_DIR}/f2b-actions.json"

echo "[orchestrate] run complete -> ${RESULTS_DIR}"


