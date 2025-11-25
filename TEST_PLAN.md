## Fail2Ban Log-Replay Test Plan

### Goals
- Assess Fail2Ban’s detection quality on identical Proxmox SSH logs used in SSHGuard testing.
- Compare metrics (TPR, FPR, Detection Time, Blocking Duration, Overall Accuracy, Repeatability) directly with SSHGuard outcomes.
- Ensure repeatable automation for an LXC container dedicated to Fail2Ban.

### Assumptions & Dependencies
- Container OS: Debian/Ubuntu LXC with Fail2Ban ≥0.11, rsyslog, and libfaketime available.
- Jail configuration focuses on SSH (`sshd` jail) with custom filters mirroring Proxmox log format; jail actions log ban/unban events with timestamps and IP.
- `test_labeled.parquet` contains authoritative labels for each event; controller has Python + pandas/pyarrow to parse it.
- Log replay driver shared with SSHGuard plan to maintain parity; adjustments limited to Fail2Ban-specific service control and metrics taps.

### Test Topology
- LXC: `fail2ban-lab`
  - Services: rsyslog, Fail2Ban (`fail2ban-server`, `fail2ban-client`).
  - Shared volume: `/mnt/replay` -> `C:\Finals`.
  - Log artifacts captured from `/var/log/fail2ban.log` and jail-specific log files.

### Replay Workflow
1. **Prepare jail configs**  
   - Copy Proxmox-specific filter regex into `/etc/fail2ban/filter.d/ssh-proxmox.conf`.
   - Configure dedicated jail `ssh-proxmox` with adjustable `maxretry`, `findtime`, `bantime` to match production.
2. **Inject log lines**  
   - Run rsyslog + fail2ban-server within `libfaketime` wrapper.
   - Feed chronological log lines synced to `test_labeled.parquet` timestamps using the same replay controller as SSHGuard.
3. **Capture telemetry**  
   - Enable `fail2ban-server -x` debug logging to emit detailed ban decision traces.
   - Use `fail2ban-client status ssh-proxmox` snapshots to track ban list changes.

### Instrumentation & Telemetry
- Rsyslog template with high-resolution recv timestamps (UTC) for correlation.
- Fail2Ban log level set to DEBUG; ensure ban/unban messages include epoch/ISO time.
- Hook jail action scripts (`actionban`, `actionunban`) to append JSON entries to `/var/log/f2b-actions.json` for easier parsing.
- Controller polls `fail2ban-client status` after each ban/unban to determine block duration precisely.

### Metric Computation
- **TPR**: share same labeling pipeline as SSHGuard; true positives counted when Fail2Ban bans an IP labeled malicious.
- **FPR**: count benign-labeled IPs that enter ban list.
- **Detection Time**: time from first malicious log entry to ban event in Fail2Ban logs.
- **Blocking Duration**: difference between ban and unban timestamps; consider jail `bantime` as upper bound.
- **Overall Accuracy**: identical formula to SSHGuard for comparability.
- **Repeatability**: perform ≥3 identical replays; compute deviation per metric; compare run-to-run deltas with SSHGuard.

### Execution Steps
1. Snapshot container, install dependencies, configure shared mount.
2. Deploy scripts:
   - `replay.py` (shared) with option `--mode fail2ban` to adjust service control.
   - `collect_fail2ban.py` to parse logs, action JSON, and generate metrics vs. parquet.
   - `orchestrate.sh` to reset iptables, restart rsyslog/fail2ban, run replay, gather artifacts under `results/`.
3. Dry-run with 24h subset verifying filter accuracy (no missed patterns, acceptable FPR).
4. Execute month-long replay, store run artifacts.
5. Repeat entire process to measure repeatability and compare aggregated metrics with SSHGuard results.

### Validation & QC
- Confirm number of log lines ingested matches source.
- Manually inspect random benign events flagged as bans to verify false positives.
- Check filter regex coverage by diffing `fail2ban-regex` output against actual logs prior to replay.
- Maintain container snapshot metadata and script commit hash for reproducibility.

### Open Questions
- Exact column definitions + timezone in `test_labeled.parquet`.
- Desired `bantime`/`findtime` parameters to mirror production.
- Whether to test multiple jail parameter sets (e.g., tuned vs. default) for comparative analysis.



