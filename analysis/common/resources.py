"""Sample local Docker containers through host cgroup v2 counters.

memory.current includes page cache and charged kernel memory. cpu.stat measures
CPU charged to container tasks; it does not isolate XDP/interrupt processing.
See https://docs.kernel.org/admin-guide/cgroup-v2.html for counter semantics.
"""

from collections import defaultdict
from contextlib import contextmanager
import csv
import math
import os
from pathlib import Path
import threading
import time

from .collection import command


def container_cgroup(name):
    """Require a local Docker daemon and the host's unified cgroup hierarchy."""
    pid = int(command("docker", "inspect", "-f", "{{.State.Pid}}", name))
    if pid <= 0:
        raise RuntimeError(f"Container is not running: {name}")
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and not controllers:
            if relative == "/" or ".." in Path(relative).parts:
                break
            path = Path("/sys/fs/cgroup") / relative.lstrip("/")
            if (path / "memory.current").is_file() and (path / "cpu.stat").is_file():
                return path
    raise RuntimeError(
        f"Cannot read host cgroup v2 counters for {name}. "
        "Run on the Docker host with readable memory.current and cpu.stat."
    )


def cpu_capacity(path, root=Path("/sys/fs/cgroup")):
    """Effective logical CPUs, capped by this cgroup's and its ancestors' quotas."""
    capacity = float(os.cpu_count() or 1)
    cpuset = path / "cpuset.cpus.effective"
    if cpuset.exists():
        ranges = cpuset.read_text().strip().split(",")
        capacity = float(sum(int(part.split("-")[-1]) - int(part.split("-")[0]) + 1
                             for part in ranges if part))
    for ancestor in (path, *path.parents):
        if not ancestor.is_relative_to(root):
            break
        limit = ancestor / "cpu.max"
        if limit.exists():
            quota, period = limit.read_text().split()
            if quota != "max":
                capacity = min(capacity, int(quota) / int(period))
    if capacity <= 0:
        raise ValueError(f"No CPU capacity available: {path}")
    return capacity


def snapshot(node, path, capacity):
    memory = int((path / "memory.current").read_text())
    cpu = dict(line.split() for line in (path / "cpu.stat").read_text().splitlines())
    return dict(node=node, timestamp_monotonic_ns=time.monotonic_ns(),
                memory_bytes=memory, cpu_usage_usec=int(cpu["usage_usec"]), cpu_capacity=capacity)


@contextmanager
def sample_resources(prefix, directory, interval):
    """Bracket run_one, keeping raw samples even when collection fails."""
    paths = {node: container_cgroup(prefix + node) for node in ("server", "firewall")}
    capacities = {node: cpu_capacity(path) for node, path in paths.items()}
    stop = threading.Event()
    errors = []
    with (directory / "resources.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "node", "timestamp_monotonic_ns", "memory_bytes", "cpu_usage_usec", "cpu_capacity"
        ))
        writer.writeheader()

        def sample():
            for node, path in paths.items():
                writer.writerow(snapshot(node, path, capacities[node]))
            stream.flush()

        def monitor():
            try:
                while not stop.wait(interval):
                    sample()
            except Exception as error:
                errors.append(error)

        sample()
        thread = threading.Thread(target=monitor, name="resource-sampler", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join()
            if errors:
                raise RuntimeError(f"Resource sampling failed: {errors[0]}") from errors[0]
            sample()


def resource_bins(directory, metadata, rates, sample_interval):
    """Weight counter deltas and held memory values by overlap with each SYN bin."""
    samples = defaultdict(list)
    with (directory / "resources.csv").open() as stream:
        for row in csv.DictReader(stream):
            samples[row["node"]].append({
                key: int(row[key]) for key in (
                    "timestamp_monotonic_ns", "memory_bytes", "cpu_usage_usec"
                )
            } | {"cpu_capacity": float(row["cpu_capacity"])})
    start, end = metadata["start_ns"], metadata["end_ns"]
    result = [dict(run=metadata["id"], attackers=metadata["attackers"],
                   second=row["second"], attack_syn_per_s=row["attack_PASS"] + row["attack_DROP"])
              for row in rates]
    for node in ("server", "firewall"):
        series = samples[node]
        if len(series) < 2 or series[0]["timestamp_monotonic_ns"] > start or series[-1]["timestamp_monotonic_ns"] < end:
            raise ValueError(f"Missing resource coverage: {directory}/{node}")
        segments = []
        for left, right in zip(series, series[1:]):
            a, b = left["timestamp_monotonic_ns"], right["timestamp_monotonic_ns"]
            delta = right["cpu_usage_usec"] - left["cpu_usage_usec"]
            capacity = left["cpu_capacity"]
            if not math.isfinite(capacity) or capacity <= 0 or right["cpu_capacity"] != capacity:
                raise ValueError(f"Invalid or changing CPU capacity: {directory}/{node}")
            if b <= a or delta < 0 or left["memory_bytes"] < 0 or right["memory_bytes"] < 0:
                raise ValueError(f"Invalid resource counters: {directory}/{node}")
            if a < end and b > start:
                if b - a > max(3 * sample_interval, 1) * 1e9:
                    raise ValueError(f"Resource sampling gap: {directory}/{node}")
                segments.append((a, b, left["memory_bytes"] / 2**20, delta * 1e5 / (b - a) / capacity))
        for index, row in enumerate(result):
            a = start + round(row["second"] * 1e9)
            b = start + round(result[index + 1]["second"] * 1e9) if index + 1 < len(result) else end
            memory, cpu, covered = 0., 0., 0
            for left, right, mib, percent in segments:
                overlap = max(0, min(b, right) - max(a, left))
                memory += mib * overlap
                cpu += percent * overlap
                covered += overlap
            if covered != b - a or covered <= 0:
                raise ValueError(f"Incomplete resource bin: {directory}/{node}")
            row[node + "_memory_mib"] = memory / covered
            row[node + "_cpu_pct"] = cpu / covered
            row[node + "_cpu_capacity"] = series[0]["cpu_capacity"]
    return result
