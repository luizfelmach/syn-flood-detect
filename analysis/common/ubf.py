"""Map observed service SYN origins to UBF indices; not a snapshot of live counters."""

from collections import Counter, defaultdict
import csv
from ipaddress import IPv4Address
from statistics import mean

from .hashing import DEFAULT_HASH_ALGORITHM, HASH_FUNCTIONS
from .metrics import pct, write_csv
from .progress import report

CATEGORIES = ("client", "attack", "mixed")


def ubf_index(src_ip, dst_ip, dst_port, size, algorithm=DEFAULT_HASH_ALGORITHM):
    data = IPv4Address(src_ip).packed + IPv4Address(dst_ip).packed + dst_port.to_bytes(2, "big")
    value = HASH_FUNCTIONS[algorithm](data)
    return value % size if size else 0


def observed_sources(directory, metadata):
    """Use the same HTTP SYN predicate and observation window as analyze_run."""
    phases = metadata["phases"]
    start = max(metadata["start_ns"], phases.get("attack_launch_ns", phases["measure_start_ns"]))
    end = min(metadata["end_ns"], phases["measure_end_ns"])
    sources = {ip: kind for kind, ips in metadata["sources"].items() for ip in ips}
    observed = set()
    with (directory / "packets.csv").open() as stream:
        for packet in csv.DictReader(stream):
            if not start <= int(packet["timestamp_monotonic_ns"]) < end:
                continue
            if (
                packet["ip_protocol"] != "6"
                or packet["dst_ip"] != "203.0.113.2"
                or packet["dst_port"] != "80"
                or not packet["tcp_flags"]
                or int(packet["tcp_flags"]) & 0x3F != 2
            ):
                continue
            kind = sources.get(packet["src_ip"])
            if kind not in ("client", "attack"):
                raise ValueError(f"Unknown SYN source in {metadata['id']}: {packet['src_ip']}")
            observed.add((kind, packet["src_ip"]))
    return observed


def index_distribution(sources, size, algorithm=DEFAULT_HASH_ALGORITHM):
    buckets = defaultdict(lambda: {"client": set(), "attack": set()})
    for kind, source in sources:
        buckets[ubf_index(source, "203.0.113.2", 80, size, algorithm)][kind].add(source)
    indices = []
    for index in range(size):
        bucket = buckets[index]
        clients, attackers = sorted(bucket["client"]), sorted(bucket["attack"])
        category = ("mixed" if clients and attackers else "client" if clients
                    else "attack" if attackers else "empty")
        indices.append(dict(
            index=index, clients=len(clients), attackers=len(attackers),
            origins=len(clients) + len(attackers), category=category,
            client_sources=";".join(clients), attacker_sources=";".join(attackers),
        ))
    bins = Counter((entry["origins"], entry["category"]) for entry in indices)
    used = sum(entry["origins"] > 0 for entry in indices)
    metrics = dict(
        used=used, empty=size - used,
        shared=sum(entry["origins"] >= 2 for entry in indices),
        clients_with_attack_pct=pct(
            sum(entry["clients"] for entry in indices if entry["category"] == "mixed"),
            sum(entry["clients"] for entry in indices),
        ),
    )
    return indices, bins, metrics


def prepare_histogram(args, rows, runs, directory):
    """Recompute derived CSVs for fresh and cached collections identically."""
    by_id = {row["id"]: row for row in rows}
    records = []
    for run_dir, metadata in runs:
        quality = by_id[metadata["id"]]["quality"]
        sources = observed_sources(run_dir, metadata) if quality == "ok" else set()
        records.append(dict(
            run=metadata["id"], repetition=metadata["repetition"],
            ubf_size=metadata["ubf_size"], quality=quality, sources=sources,
            hash_algorithm=metadata.get("hash_algorithm", "fnv1a"),
        ))
    if len({record["hash_algorithm"] for record in records}) > 1:
        raise ValueError("Cannot combine different hash algorithms in one histogram")
    by_repetition = defaultdict(list)
    for record in records:
        if record["quality"] == "ok":
            by_repetition[record["repetition"]].append(record)
    for repetition, group in by_repetition.items():
        if any(record["sources"] != group[0]["sources"] for record in group[1:]):
            report(f"Repetition {repetition}: observed sources differ between UBF sizes; histogram points will be N/A")
            for record in group:
                record["quality"] = "inconsistent_sources_across_sizes"
    index_rows, histogram_rows = [], []
    for record in records:
        common = {key: record[key] for key in ("run", "repetition", "ubf_size", "hash_algorithm", "quality")}
        if record["quality"] != "ok":
            histogram_rows.append(dict(**common, origins_per_index=None, category=None, indices=None))
            continue
        indices, bins, metrics = index_distribution(record["sources"], record["ubf_size"], record["hash_algorithm"])
        record.update(bins=bins, **metrics)
        index_rows.extend(dict(**common, **entry) for entry in indices)
        # Include zero-valued bins so exported repetitions share the same interpretation.
        histogram_rows.append(dict(**common, origins_per_index=0, category="empty", indices=record["empty"]))
        for count in range(1, max((entry["origins"] for entry in indices), default=0) + 1):
            for category in CATEGORIES:
                histogram_rows.append(dict(
                    **common, origins_per_index=count, category=category,
                    indices=bins[count, category],
                ))
    if index_rows:
        write_csv(directory / "ubf_indices.csv", index_rows)
    else:
        write_csv(directory / "ubf_indices.csv", [], fields=[
            "run", "repetition", "UBF_SIZE", "hash_algorithm", "quality", "index", "clients", "attackers",
            "origins", "category", "client_sources", "attacker_sources",
        ])
    write_csv(directory / "ubf_histogram.csv", histogram_rows)
    return records


def aggregate_histogram(records, sizes):
    """Average per-run bucket counts, never pool sources across repetitions."""
    if len({r["hash_algorithm"] for r in records}) > 1:
        raise ValueError("Cannot aggregate different hash algorithms in one histogram")
    groups = []
    for size in sizes:
        valid = [r for r in records if r["ubf_size"] == size and r["quality"] == "ok"]
        group = dict(ubf_size=size, n=len(valid), bins={})
        if valid:
            keys = set().union(*(record["bins"].keys() for record in valid))
            group["bins"] = {key: mean(record["bins"][key] for record in valid) for key in keys}
            for metric in ("used", "empty", "shared", "clients_with_attack_pct"):
                values = [record[metric] for record in valid if record[metric] is not None]
                group[metric] = mean(values) if values else None
        groups.append(group)
    return groups
