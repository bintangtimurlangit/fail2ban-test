## Fail2Ban Replay Runbook

This runbook complements `TEST_PLAN.md` and documents the concrete steps,
scripts, and configuration snippets required to execute the log replay inside
the Fail2Ban LXC container.

### Directory Layout

```
fail2ban-test/
  benchmark.log           # replay source (copied from Proxmox)
  benchmark.parquet       # labeled IP/day summary (ground truth)
  scripts/
    replay.py             # streams benchmark.log into rsyslog
    collect_fail2ban.py   # computes metrics vs. parquet labels
    action_logger.py      # Fail2Ban action hook -> JSON lines
    orchestrate.sh        # end-to-end automation
  results/                # created after first run, contains artifacts
```

Mount the entire `fail2ban-test/` folder into the container at
`/mnt/replay/fail2ban-test` (read-only for data, read/write for `results/`).

### Dependencies / Bootstrap

1. Run the bootstrap helper once on a fresh container:

```bash
cd /mnt/replay/fail2ban-test/scripts
sudo ./bootstrap.sh
```

This installs apt packages (`fail2ban`, `rsyslog`, `libfaketime` + `faketime`, `python3-venv`, etc.),
creates `/opt/f2b-replay`, installs `pandas`/`pyarrow`, and copies
`action_logger.py` into `/usr/local/bin/f2b_action_logger.py`.

2. Configure the `ssh-proxmox` jail/filter as described below.

### Fail2Ban Hooking

1. Copy the JSON action helper:

```bash
cp /mnt/replay/fail2ban-test/scripts/action_logger.py /usr/local/bin/f2b_action_logger.py
chmod +x /usr/local/bin/f2b_action_logger.py
```

2. Extend the jail action (example inside `/etc/fail2ban/action.d/ssh-json.conf`):

```
[Definition]
actionban  = python3 /usr/local/bin/f2b_action_logger.py \
               --action ban --ip <ip> --jail <name> \
               --reason "<matches>" --log-file /var/log/f2b-actions.json
actionunban = python3 /usr/local/bin/f2b_action_logger.py \
               --action unban --ip <ip> --jail <name> \
               --reason "auto-unban" --log-file /var/log/f2b-actions.json
```

3. Reference the action from the `ssh-proxmox` jail:

```
[ssh-proxmox]
enabled   = true
filter    = ssh-proxmox
action    = %(action_mwl)s
           ssh-json
logpath   = /var/log/auth.log
findtime  = 600
bantime   = 3600
maxretry  = 5
```

### Running a Replay

1. Mount/share data:
   - Host: `fail2ban-test/` → Container: `/mnt/replay/fail2ban-test`.
2. Review `scripts/orchestrate.sh` variables (default speed factor is 600×, jail name, faketime spec).
3. Execute:

```bash
cd /mnt/replay/fail2ban-test/scripts
chmod +x orchestrate.sh
./orchestrate.sh
```

The script:
- Stops rsyslog/fail2ban, flushes jail firewall chain.
- Restarts both services under `faketime`.
- Runs `replay.py` to stream `benchmark.log`.
- Captures jail status before/after.
- Runs `collect_fail2ban.py` to compute metrics and update `results/history.json`.
- Copies Fail2Ban logs and action JSON into `results/<run_id>/`.

### Monitoring During Replay

- `tail -f /var/log/fail2ban.log`
- `tail -f /var/log/f2b-actions.json`
- `fail2ban-client status ssh-proxmox`
- `iptables -L f2b-ssh-proxmox -v -n`

### After the Run

`results/<run_id>/` contains:
- `replay.log` – emission progress.
- `status_before.txt` / `status_after.txt`.
- `fail2ban.log` / `f2b-actions.json` snapshots.
- `metrics.json` – computed KPIs plus repeatability stats.

Use `results/history.json` to compare multiple runs and derive the repeatability
deviation required by the metrics list.


