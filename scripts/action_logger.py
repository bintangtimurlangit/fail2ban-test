#!/usr/bin/env python3
"""
Fail2Ban action hook that appends JSON rows for ban/unban events.

Usage inside jail action file:
  actionban = python3 /mnt/replay/fail2ban-test/scripts/action_logger.py \
                --log-file /var/log/f2b-actions.json \
                --action ban --ip <ip> --jail <name> --reason "<matches>"
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record Fail2Ban action as JSON.")
    parser.add_argument("--log-file", default="/var/log/f2b-actions.json")
    parser.add_argument("--action", required=True, choices=["ban", "unban"])
    parser.add_argument("--ip", required=True)
    parser.add_argument("--jail", required=True)
    parser.add_argument("--reason", default="")
    parser.add_argument("--match-ts", default="")
    parser.add_argument("--log-line", default="")
    parser.add_argument("--extra", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "action": args.action,
        "ip": args.ip,
        "jail": args.jail,
        "reason": args.reason,
        "match_ts": args.match_ts,
        "log_line": args.log_line,
        "extra": args.extra,
    }
    path = Path(args.log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


if __name__ == "__main__":
    main()


