#!/usr/bin/env python3
"""Packet metrics, quality checks and aggregation for independent experiments."""

from collections import Counter, defaultdict
import csv
import json
from statistics import median

PARAMS = (
    "scenario",
    "mode",
    "epoch_ms",
    "threshold",
    "ubf_size",
    "clients",
    "client_interval",
    "attackers",
    "attack_interval",
)
METRICS = (
    "attack_drop_pct",
    "legitimate_drop_pct",
    "clients_affected_pct",
    "attack_passed",
    "attack_passed_per_s",
    "first_drop_median_ms",
    "never_blocked_pct",
    "observed_attack_syn_per_s",
    "observed_gap_epoch_ratio",
    "observed_syn_interval_ms",
    "steady_attack_drop_pct",
)
COLORS = ["#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#333333"]


def pct(n, d):
    return 100 * n / d if d else None


def write_csv(path, rows, fields=None):
    if not rows and fields is None:
        return
    names = {
        "epoch_ms": "EPOCH_TIME_MS",
        "threshold": "SYN_COUNT_BLOCK_THRESHOLD",
        "ubf_size": "UBF_SIZE",
    }
    if fields is None:
        fields = [names.get(k, k) for k in rows[0]]
        rows = [{names.get(k, k): v for k, v in row.items()} for row in rows]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def analyze_run(directory):
    m = json.loads((directory / "run.json").read_text())
    m["ubf_size_assumed"] = "ubf_size" not in m
    m.setdefault("ubf_size", 2048)
    if m["status"] != "complete":
        raise ValueError(f"Incomplete run: {m['status']}")
    start, end = m["start_ns"], m["end_ns"]
    phases = m["phases"]
    a = phases.get("attack_launch_ns", phases["measure_start_ns"])
    b = phases["measure_end_ns"]
    duration = (b - a) / 1e9
    sources = {ip: kind for kind, ips in m["sources"].items() for ip in ips}
    counts, steady = Counter(), Counter()
    first, first_drop, last = {}, {}, {}
    origin_counts, origin_pass, ordinal = Counter(), Counter(), {}
    gaps = []
    clients_seen, clients_dropped = set(), set()
    unexpected = 0
    modes = set()
    with (directory / "packets.csv").open() as f:
        for r in csv.DictReader(f):
            t = int(r["timestamp_monotonic_ns"])
            if not start <= t < end:
                continue
            modes.add(r["mode"])
            if (
                r["ip_protocol"] != "6"
                or r["dst_ip"] != "203.0.113.2"
                or r["dst_port"] != "80"
                or not r["tcp_flags"]
                or int(r["tcp_flags"]) & 0x3F != 2
            ):
                continue
            ip, action = r["src_ip"], r["action"]
            kind = sources.get(ip)
            if kind is None:
                unexpected += 1
                continue
            if not a <= t < b:
                continue
            counts[kind, action] += 1
            if t >= phases["measure_start_ns"]:
                steady[kind, action] += 1
            if kind == "client":
                clients_seen.add(ip)
                if action == "DROP":
                    clients_dropped.add(ip)
            else:
                first.setdefault(ip, t)
                origin_counts[ip] += 1
                if action == "PASS":
                    origin_pass[ip] += 1
                if ip in last:
                    gaps.append((t - last[ip]) / 1e6 / m["epoch_ms"])
                last[ip] = t
                if action == "DROP" and ip not in first_drop:
                    first_drop[ip] = t
                    ordinal[ip] = origin_counts[ip]
    origin_rows = []
    times = []
    for ip in sorted(first):
        delay = (first_drop[ip] - first[ip]) / 1e6 if ip in first_drop else None
        if delay is not None:
            times.append(delay)
        origin_rows.append(
            dict(
                run=m["id"],
                source=ip,
                syns=origin_counts[ip],
                passed=origin_pass[ip],
                first_drop_ms=delay,
                first_drop_syn_number=ordinal.get(ip),
                never_blocked=ip not in first_drop,
            )
        )
    stats = list(csv.DictReader((directory / "stats.csv").open()))
    left = [r for r in stats if int(r["timestamp_monotonic_ns"]) <= start]
    right = [r for r in stats if int(r["timestamp_monotonic_ns"]) >= end]
    quality = []
    deltas = {k: None for k in ("passed", "dropped", "aborted", "events_lost")}
    if not left or not right:
        quality.append("missing_stats_coverage")
    else:
        for k in deltas:
            deltas[k] = int(right[0][k]) - int(left[-1][k])
        if any(v < 0 for v in deltas.values()):
            quality.append("counters_reset")
        if deltas["events_lost"]:
            quality.append("events_lost")
        if deltas["aborted"]:
            quality.append("packets_aborted")
    if modes != {m["mode"]}:
        quality.append("inconsistent_mode")
    if unexpected:
        quality.append("unknown_sources")
    if m["attackers"] and len(first) != m["attackers"]:
        quality.append("missing_attacker_sources")
    if m["clients"] and len(clients_seen) != m["clients"]:
        quality.append("missing_clients_in_window")
    total = lambda c, kind: sum(v for (k, action), v in c.items() if k == kind)
    attack_total, client_total = total(counts, "attack"), total(counts, "client")
    row = {k: m[k] for k in ("id", *PARAMS, "repetition")}
    row.update(
        quality=";".join(quality) or "ok",
        duration_s=duration,
        attack_syns=attack_total,
        legitimate_syns=client_total,
        attack_drop_pct=pct(counts["attack", "DROP"], attack_total),
        legitimate_drop_pct=pct(counts["client", "DROP"], client_total),
        clients_affected_pct=pct(len(clients_dropped), len(clients_seen)),
        attack_passed=counts["attack", "PASS"],
        attack_dropped=counts["attack", "DROP"],
        legitimate_passed=counts["client", "PASS"],
        legitimate_dropped=counts["client", "DROP"],
        attack_passed_per_s=counts["attack", "PASS"] / duration,
        first_drop_median_ms=median(times) if times else None,
        never_blocked_pct=pct(len(first) - len(first_drop), len(first)),
        observed_attack_syn_per_s=attack_total / duration if m["attackers"] else None,
        observed_gap_epoch_ratio=median(gaps) if gaps else None,
        observed_syn_interval_ms=median(gaps) * m["epoch_ms"] if gaps else None,
        steady_attack_drop_pct=pct(steady["attack", "DROP"], total(steady, "attack")),
        events_lost=deltas["events_lost"],
        aborted=deltas["aborted"],
    )
    return row, origin_rows, m


def aggregate(rows):
    groups = defaultdict(list)
    for row in rows:
        if row["quality"] == "ok":
            groups[tuple(row[k] for k in PARAMS)].append(row)
    result = []
    for key, group in groups.items():
        record = dict(zip(PARAMS, key))
        record["n"] = len(group)
        for metric in METRICS:
            values = [r[metric] for r in group if r[metric] is not None]
            record[metric] = median(values) if values else None
            record[metric + "_min"] = min(values) if values else None
            record[metric + "_max"] = max(values) if values else None
        result.append(record)
    return result
