#!/usr/bin/env python3
"""
Aggregate Fail2Ban replay metrics using benchmark parquet ground truth.

Expected inputs:
  - benchmark.parquet: columns include src_ip, label, first_ts, last_ts, confidence.
  - /var/log/f2b-actions.json: JSON lines produced by action_logger.py hooks.
  - /var/log/fail2ban.log: optional for troubleshooting, not parsed yet.

Outputs metrics.json with TPR/FPR, detection/ban timing stats, accuracy, repeatability.
"""

from __future__ import annotations

import argparse
import json
import statistics
import itertools
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd  # type: ignore

DATETIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S",
)


def parse_dt(value: str) -> datetime:
    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized datetime format: {value}")


def normalize_label(label: str) -> str:
    label = (label or "").upper()
    if "ATTACK" in label:
        return "malicious"
    if "UNKNOWN" in label:
        return "unknown"
    return "benign"


@dataclass
class ActionEvent:
    timestamp: datetime
    ip: str
    action: str  # ban or unban
    jail: str
    reason: Optional[str]


def load_actions(path: Path) -> List[ActionEvent]:
    events: List[ActionEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            events.append(
                ActionEvent(
                    timestamp=parse_dt(payload.get("timestamp") or payload["ts"]),
                    ip=payload["ip"],
                    action=payload.get("action", "ban"),
                    jail=payload.get("jail", "ssh-proxmox"),
                    reason=payload.get("reason"),
                )
            )
    return events


def load_ground_truth(parquet_path: Path) -> pd.DataFrame:
    df = pd.read_parquet(parquet_path)
    required = {"src_ip", "label", "first_ts"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Parquet missing columns: {missing}")
    df = df.copy()
    df["label_norm"] = df["label"].apply(normalize_label)
    df["first_ts_parsed"] = df["first_ts"].apply(lambda x: parse_dt(x) if isinstance(x, str) else pd.to_datetime(x).to_pydatetime())
    return df


def compute_detection_times(actions: List[ActionEvent], truth: pd.DataFrame) -> Dict[str, float]:
    first_ban: Dict[str, datetime] = {}
    for event in actions:
        if event.action.lower() != "ban":
            continue
        first_ban.setdefault(event.ip, event.timestamp)
    detection_seconds: Dict[str, float] = {}
    for _, row in truth.iterrows():
        ip = row["src_ip"]
        if ip not in first_ban:
            continue
        detection_seconds[ip] = (first_ban[ip] - row["first_ts_parsed"]).total_seconds()
    return detection_seconds


def compute_block_durations(actions: List[ActionEvent]) -> Dict[str, List[float]]:
    bans: Dict[str, List[datetime]] = defaultdict(list)
    durations: Dict[str, List[float]] = defaultdict(list)
    for event in sorted(actions, key=lambda e: e.timestamp):
        if event.action.lower() == "ban":
            bans[event.ip].append(event.timestamp)
        elif event.action.lower() == "unban":
            if bans[event.ip]:
                start = bans[event.ip].pop(0)
                durations[event.ip].append((event.timestamp - start).total_seconds())
    return durations


def summarize(values: Iterable[float]) -> Dict[str, float]:
    data = list(values)
    if not data:
        return {"count": 0, "avg": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "count": len(data),
        "avg": sum(data) / len(data),
        "median": statistics.median(data),
        "min": min(data),
        "max": max(data),
    }


def compute_metrics(actions: List[ActionEvent], truth: pd.DataFrame) -> Dict[str, object]:
    malicious_ips = set(truth[truth["label_norm"] == "malicious"]["src_ip"])
    benign_ips = set(truth[truth["label_norm"] == "benign"]["src_ip"])
    unknown_ips = set(truth[truth["label_norm"] == "unknown"]["src_ip"])

    banned_ips = {event.ip for event in actions if event.action.lower() == "ban"}
    true_positive = len(banned_ips & malicious_ips)
    false_positive = len(banned_ips & benign_ips)
    false_negative = len(malicious_ips - banned_ips)
    true_negative = len(benign_ips) - false_positive

    tpr = true_positive / len(malicious_ips) if malicious_ips else 0.0
    fpr = false_positive / len(benign_ips) if benign_ips else 0.0
    accuracy = (true_positive + true_negative) / (len(malicious_ips) + len(benign_ips)) if (malicious_ips or benign_ips) else 0.0

    detection_times = compute_detection_times(actions, truth[truth["label_norm"] == "malicious"])
    block_durations = compute_block_durations(actions)

    return {
        "counts": {
            "malicious_ips": len(malicious_ips),
            "benign_ips": len(benign_ips),
            "unknown_ips": len(unknown_ips),
            "banned_ips": len(banned_ips),
        },
        "tpr": tpr,
        "fpr": fpr,
        "accuracy": accuracy,
        "detection_seconds": summarize(detection_times.values()),
        "blocking_seconds": summarize(itertools.chain.from_iterable(block_durations.values())),
        "detection_by_ip": detection_times,
        "blocking_by_ip": block_durations,
    }


def update_history(history_path: Path, run_entry: Dict[str, object]) -> Dict[str, object]:
    history: List[Dict[str, object]] = []
    if history_path.exists():
        history = json.loads(history_path.read_text(encoding="utf-8"))
    history.append(run_entry)
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    repeatability = {}
    if len(history) >= 2:
        detection_vals = [h["metrics"]["detection_seconds"]["avg"] for h in history if h["metrics"]["detection_seconds"]["count"]]
        accuracy_vals = [h["metrics"]["accuracy"] for h in history]
        if detection_vals:
            repeatability["detection_seconds_std"] = statistics.stdev(detection_vals)
        if accuracy_vals:
            repeatability["accuracy_std"] = statistics.stdev(accuracy_vals)
    return repeatability


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect Fail2Ban metrics from replay run.")
    parser.add_argument("--parquet", default="benchmark.parquet")
    parser.add_argument("--actions-log", default="/var/log/f2b-actions.json")
    parser.add_argument("--fail2ban-log", default="/var/log/fail2ban.log")
    parser.add_argument("--output", default="results/metrics.json")
    parser.add_argument("--history", default="results/history.json")
    parser.add_argument("--run-id", required=True, help="Identifier for this replay run.")
    parser.add_argument("--notes", default="", help="Optional annotation for the run.")
    return parser.parse_args()


def main() -> None:
    args = parse_cli()
    parquet_path = Path(args.parquet)
    actions_path = Path(args.actions_log)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    truth = load_ground_truth(parquet_path)
    actions = load_actions(actions_path)
    metrics = compute_metrics(actions, truth)
    run_entry = {
        "run_id": args.run_id,
        "notes": args.notes,
        "metrics": metrics,
    }
    repeatability = update_history(Path(args.history), run_entry)
    payload = {
        "run": run_entry,
        "repeatability": repeatability,
        "source": {
            "parquet": str(parquet_path),
            "actions": str(actions_path),
            "fail2ban_log": str(Path(args.fail2ban_log)),
        },
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Metrics written to {output_path}")


if __name__ == "__main__":
    main()


