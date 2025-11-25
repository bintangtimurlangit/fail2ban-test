#!/usr/bin/env python3
"""
Replay benchmark.log entries into rsyslog for Fail2Ban testing.

The script streams a saved SSH log back into the container's logger command
while roughly respecting original inter-event timing. Use libfaketime for
rsyslog/fail2ban processes separately; this script only controls emission pace.
"""

from __future__ import annotations

import argparse
import itertools
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional

SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class LogLine:
    raw: str
    timestamp: datetime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay benchmark.log into rsyslog/Fail2Ban."
    )
    parser.add_argument(
        "--log-file",
        default="benchmark.log",
        help="Path to captured SSH log with syslog-style timestamps.",
    )
    parser.add_argument(
        "--parquet",
        default="benchmark.parquet",
        help="Path to benchmark parquet (used for default year derivation).",
    )
    parser.add_argument(
        "--start-year",
        type=int,
        default=None,
        help="Optional year hint. When omitted the first window_start year from "
        "the parquet file is used.",
    )
    parser.add_argument(
        "--speed-factor",
        type=float,
        default=600.0,
        help="Speed multiplier relative to real time. 600 means 10 minutes of logs per second.",
    )
    parser.add_argument(
        "--logger-cmd",
        default="logger --priority authpriv.info --tag replay",
        help="Command used to inject each line (default: logger). Parsed with shlex.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned emissions without calling logger.",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=None,
        help="Optional limit for smoke tests.",
    )
    parser.add_argument(
        "--filter-ip",
        default=None,
        help="Restrict replay to a specific source IP (string containment).",
    )
    parser.add_argument(
        "--sleep-cap",
        type=float,
        default=5.0,
        help="Maximum sleep per log delta (seconds) after speed factor applied.",
    )
    parser.add_argument(
        "--status-interval",
        type=int,
        default=1000,
        help="Print progress every N emitted lines.",
    )
    return parser.parse_args()


def derive_start_year(parquet_path: Path) -> Optional[int]:
    try:
        import pandas as pd  # type: ignore
    except ImportError:  # pragma: no cover
        return None

    if not parquet_path.exists():
        return None
    df = pd.read_parquet(parquet_path, columns=["window_start"])
    df = df.dropna(subset=["window_start"])
    if df.empty:
        return None
    try:
        sample = df.iloc[0]["window_start"]
        if isinstance(sample, str):
            # Example: 17/12/2024 00:00
            parsed = datetime.strptime(sample, "%d/%m/%Y %H:%M")
        else:
            parsed = pd.to_datetime(sample).to_pydatetime()
        return parsed.year
    except Exception:
        return None


def parse_syslog_timestamp(line: str, current_year: int, previous: Optional[datetime]) -> datetime:
    month = line[0:3]
    if month not in SYSLOG_MONTHS:
        raise ValueError(f"Cannot parse month from line: {line[:32]!r}")
    day = int(line[4:6])
    time_fragment = line[7:15]
    ts = datetime.strptime(time_fragment, "%H:%M:%S")
    candidate = datetime(current_year, SYSLOG_MONTHS[month], day, ts.hour, ts.minute, ts.second)
    if previous:
        if candidate < previous and SYSLOG_MONTHS[month] == 1 and previous.month == 12:
            candidate = candidate.replace(year=previous.year + 1)
        elif candidate.year < previous.year:
            candidate = candidate.replace(year=previous.year)
    return candidate


def read_log_lines(path: Path, start_year: int, ip_filter: Optional[str]) -> Iterator[LogLine]:
    previous_ts: Optional[datetime] = None
    year_hint = start_year
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            if ip_filter and ip_filter not in raw:
                continue
            timestamp = parse_syslog_timestamp(raw, year_hint, previous_ts)
            previous_ts = timestamp
            year_hint = timestamp.year
            yield LogLine(raw=raw.rstrip("\n"), timestamp=timestamp)


def emit_line(cmd: list[str], line: str, dry_run: bool) -> None:
    if dry_run:
        print(line)
        return
    subprocess.run(cmd, input=line + "\n", text=True, check=True)


def replay(lines: Iterable[LogLine], speed_factor: float, sleep_cap: float, status_interval: int, cmd: list[str], dry_run: bool, max_lines: Optional[int]) -> None:
    iterator = iter(lines)
    emitted = 0
    last_ts: Optional[datetime] = None
    start_wall = time.monotonic()
    for line in iterator:
        if last_ts is not None:
            delta = (line.timestamp - last_ts).total_seconds()
            if delta > 0:
                scaled = min(delta / speed_factor, sleep_cap)
                time.sleep(max(0.0, scaled))
        emit_line(cmd, line.raw, dry_run=dry_run)
        emitted += 1
        last_ts = line.timestamp
        if status_interval and emitted % status_interval == 0:
            elapsed = time.monotonic() - start_wall
            print(f"[replay] emitted={emitted} last_ts={last_ts} elapsed={elapsed:.1f}s", file=sys.stderr)
        if max_lines and emitted >= max_lines:
            break
    print(f"[replay] finished emitted={emitted}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    log_path = Path(args.log_file)
    parquet_path = Path(args.parquet)
    if not log_path.exists():
        print(f"log file not found: {log_path}", file=sys.stderr)
        return 1
    start_year = args.start_year or derive_start_year(parquet_path) or datetime.utcnow().year
    command = shlex.split(args.logger_cmd)
    lines = read_log_lines(log_path, start_year=start_year, ip_filter=args.filter_ip)
    replay(
        lines=lines,
        speed_factor=args.speed_factor,
        sleep_cap=args.sleep_cap,
        status_interval=args.status_interval,
        cmd=command,
        dry_run=args.dry_run,
        max_lines=args.max_lines,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())


