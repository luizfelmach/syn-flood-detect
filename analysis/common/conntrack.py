"""Sample firewall conntrack allocations, configured capacity and per-CPU counters.

The drop counter includes allocation and protocol/confirmation failures; it is
not an exclusive table-full counter. early_drop counts evicted entries, not
dropped packets. Neither includes intentional XDP drops before conntrack.
See Linux net/netfilter/nf_conntrack_{core,standalone}.c.
"""

from contextlib import contextmanager
import csv
import math
from pathlib import Path
import shlex
import subprocess
import threading
import time

from .collection import ROOT, save
from .progress import report


COUNTERS = ("drop", "early_drop", "insert_failed")
FIELDS = ("conntrack_count", "conntrack_max", *COUNTERS)
LIMIT_PATH = Path("/proc/sys/net/netfilter/nf_conntrack_max")


def set_host_limit(value, image="node:local"):
    """Linux 6.18 exposes this global limit read-only in child net namespaces."""
    # Bind only the requested host sysctl. The helper has no writable root
    # filesystem and needs no privileged-container access to other host files.
    command = [
        "docker", "run", "--rm", "--network", "host", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
        "--mount", f"type=bind,src={LIMIT_PATH},dst=/conntrack-max",
        "--entrypoint", "/bin/sh", image, "-c",
        'printf "%s\\n" "$1" > /conntrack-max', "conntrack-limit", str(value),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f"Cannot configure host conntrack limit: {result.stderr.strip()}")


@contextmanager
def temporary_conntrack_limit(maximum, directory, image="node:local"):
    """Restore the host's original limit on success, failure or interruption."""
    if maximum is None:
        yield
        return
    previous = int(LIMIT_PATH.read_text())
    state = dict(original=previous, requested=maximum, restored=False)
    save(directory / "conntrack_limit.json", state)
    try:
        report(f"Temporarily setting global host conntrack limit: {previous} -> {maximum}")
        set_host_limit(maximum, image)
        if int(LIMIT_PATH.read_text()) != maximum:
            raise RuntimeError("Host conntrack limit did not match the requested value")
        yield
    finally:
        try:
            if int(LIMIT_PATH.read_text()) != previous:
                set_host_limit(previous, image)
            if int(LIMIT_PATH.read_text()) != previous:
                raise RuntimeError("Could not restore the original host conntrack limit")
            state["restored"] = True
            report(f"Host conntrack limit restored: {previous}")
        except BaseException as error:
            state["restore_error"] = str(error)
            raise
        finally:
            save(directory / "conntrack_limit.json", state)

# Proc statistics are hexadecimal and per CPU. The repeated entries column is
# namespace-wide: read nf_conntrack_count separately, never sum entries.
CONNTRACK_STATS_AWK = '''
function hex(value, result, i, digit) {
    result=0
    for (i=1; i<=length(value); i++) {
        digit=index("0123456789abcdef", tolower(substr(value,i,1)))-1
        result=result*16+digit
    }
    return result
}
FILENAME ~ /\\/nf_conntrack_count$/ {
    if (FNR != 1 || NF != 1 || $1 !~ /^[0-9]+$/) { bad=1; exit 2 }
    count=$1; next
}
FILENAME ~ /\\/nf_conntrack_max$/ {
    if (FNR != 1 || NF != 1 || $1 !~ /^[0-9]+$/) { bad=1; exit 2 }
    maximum=$1; next
}
FNR == 1 {
    for (i=1; i<=NF; i++) column[$i]=i
    if (!column["drop"] || !column["early_drop"] || !column["insert_failed"]) { bad=1; exit 2 }
    next
}
{
    for (name in column) {
        if (name != "drop" && name != "early_drop" && name != "insert_failed") continue
        position=column[name]
        if (position>NF || $position !~ /^[[:xdigit:]]+$/) { bad=1; exit 2 }
        total[name]+=hex($position)
    }
    rows++
}
END {
    if (bad || !rows || count !~ /^[0-9]+$/ || maximum !~ /^[0-9]+$/ || maximum<1) exit 2
    printf "%.0f %.0f %.0f %.0f %.0f\\n", count, maximum, total["drop"], total["early_drop"], total["insert_failed"]
}
'''


# conntrack -S uses decimal key=value counters, one row per CPU. Do not parse
# these as the hexadecimal values from /proc/net/stat/nf_conntrack.
CONNTRACK_NETLINK_AWK = '''
FILENAME ~ /\\/nf_conntrack_count$/ {
    if (FNR != 1 || NF != 1 || $1 !~ /^[0-9]+$/) { bad=1; exit 2 }
    count=$1; next
}
FILENAME ~ /\\/nf_conntrack_max$/ {
    if (FNR != 1 || NF != 1 || $1 !~ /^[0-9]+$/) { bad=1; exit 2 }
    maximum=$1; next
}
{
    delete seen
    for (i=1; i<=NF; i++) {
        if (split($i, pair, "=") != 2) { bad=1; exit 2 }
        name=pair[1]; value=pair[2]
        if (name != "cpu" && name != "drop" && name != "early_drop" && name != "insert_failed") continue
        if (seen[name]++ || value !~ /^[0-9]+$/) { bad=1; exit 2 }
        if (name == "cpu") {
            if (cpus[value+0]++) { bad=1; exit 2 }
        } else {
            total[name]+=value
        }
    }
    if (!seen["cpu"] || !seen["drop"] || !seen["early_drop"] || !seen["insert_failed"]) { bad=1; exit 2 }
    rows++
}
END {
    if (bad || !rows || count !~ /^[0-9]+$/ || maximum !~ /^[0-9]+$/ || maximum<1) exit 2
    printf "%.0f %.0f %.0f %.0f %.0f\\n", count, maximum, total["drop"], total["early_drop"], total["insert_failed"]
}
'''


def conntrack_sampler_script(interval):
    """Select one statistics source for the lifetime of the sampler."""
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("Conntrack sampling interval must be finite and positive")
    return (
        'set -eu\nprintf "PID %s\\n" "$$"\ntrap "exit 0" TERM INT\n'
        'if [ -r /proc/net/stat/nf_conntrack ]; then\n'
        '    source=procfs\n'
        'else\n'
        '    source=netlink\n'
        '    command -v conntrack >/dev/null 2>&1 || {\n'
        '        echo "Missing /proc/net/stat/nf_conntrack and conntrack executable; rebuild the node image with make build." >&2\n'
        '        exit 1\n'
        '    }\n'
        'fi\n'
        'printf "Conntrack statistics source: %s\\n" "$source" >&2\n'
        'while :; do\n'
        'if [ "$source" = procfs ]; then\n'
        # A shell read may issue one-byte reads, which proc sysctl files need
        # not support. awk reads each complete value in one buffered read.
        f'awk {shlex.quote(CONNTRACK_STATS_AWK)} /proc/sys/net/netfilter/nf_conntrack_count '
        '/proc/sys/net/netfilter/nf_conntrack_max /proc/net/stat/nf_conntrack\n'
        'else\n'
        # Capture the command before the pipeline: POSIX sh has no pipefail.
        # A failed Netlink query must never become an apparently valid zero.
        'stats=$(conntrack -S) || {\n'
        '    echo "conntrack -S failed; check Netlink support and NET_ADMIN in the firewall namespace." >&2\n'
        '    exit 1\n'
        '}\n'
        f'printf "%s\\n" "$stats" | awk {shlex.quote(CONNTRACK_NETLINK_AWK)} '
        '/proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max -\n'
        'fi\n'
        f'sleep {interval:.9f}\ndone'
    )


@contextmanager
def sample_conntrack(prefix, directory, interval):
    """Read only this firewall namespace through one persistent Docker exec."""
    script = conntrack_sampler_script(interval)
    ready, stopping = threading.Event(), threading.Event()
    errors, remote_pid = [], []
    firewall = prefix + "firewall"

    def sampling_error():
        path = directory / "conntrack.log"
        detail = path.read_text().strip()[-2000:]
        return RuntimeError(f"Conntrack sampling failed: {errors[0]}; see {path}"
                            + (f"\n{detail}" if detail else ""))

    with (directory / "conntrack.csv").open("w", newline="") as stream, \
         (directory / "conntrack.log").open("w") as log:
        writer = csv.DictWriter(stream, fieldnames=("timestamp_monotonic_ns", *FIELDS))
        writer.writeheader()
        proc = subprocess.Popen(
            ["docker", "exec", firewall, "sh", "-c", script], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1,
        )

        def monitor():
            try:
                header = proc.stdout.readline().strip().split()
                if len(header) != 2 or header[0] != "PID" or int(header[1]) <= 0:
                    raise RuntimeError("Conntrack sampler did not report its remote PID")
                remote_pid.append(int(header[1]))
                for line in proc.stdout:
                    values = [int(value) for value in line.split()]
                    if len(values) != len(FIELDS) or any(value < 0 for value in values) or values[1] == 0:
                        raise ValueError("Invalid conntrack counters")
                    writer.writerow(dict(timestamp_monotonic_ns=time.monotonic_ns(), **dict(zip(FIELDS, values))))
                    stream.flush()
                    ready.set()
                if not stopping.is_set():
                    raise RuntimeError("Conntrack sampler exited before the observation finished")
            except Exception as error:
                errors.append(error)
                ready.set()

        thread = threading.Thread(target=monitor, name="conntrack-sampler", daemon=True)
        thread.start()
        try:
            if not ready.wait(10):
                raise RuntimeError(f"Conntrack sampler did not become ready; see {directory / 'conntrack.log'}")
            if errors:
                raise sampling_error() from errors[0]
            yield
        finally:
            stopping.set()
            try:
                if remote_pid and proc.poll() is None:
                    result = subprocess.run(
                        ["docker", "exec", firewall, "kill", "-TERM", str(remote_pid[0])],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode and proc.poll() is None:
                        errors.append(RuntimeError(f"Could not stop conntrack sampler: {result.stderr.strip()}"))
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
                    errors.append(RuntimeError("Conntrack sampler did not stop cleanly"))
            finally:
                thread.join(timeout=5)
                if thread.is_alive():
                    errors.append(RuntimeError("Conntrack sampler reader did not stop"))
                else:
                    proc.stdout.close()
            if errors:
                raise sampling_error() from errors[0]


def conntrack_series(directory, metadata, bin_seconds):
    """Hold occupancy snapshots; weight counter rates by actual time overlap."""
    with (directory / "conntrack.csv").open() as stream:
        reader = csv.DictReader(stream)
        if not {"timestamp_monotonic_ns", *FIELDS}.issubset(reader.fieldnames or []):
            raise ValueError(f"Missing conntrack counters: {directory}")
        samples = [{key: int(row[key]) for key in ("timestamp_monotonic_ns", *FIELDS)} for row in reader]
    start, end = metadata["start_ns"], metadata["end_ns"]
    if (end <= start or len(samples) < 2 or samples[0]["timestamp_monotonic_ns"] > start
            or samples[-1]["timestamp_monotonic_ns"] < end):
        raise ValueError(f"Missing conntrack coverage: {directory}")
    if any(any(row[key] < 0 for key in FIELDS) or row["conntrack_max"] == 0 for row in samples):
        raise ValueError(f"Invalid conntrack counters: {directory}")
    if len({row["conntrack_max"] for row in samples}) != 1:
        raise ValueError(f"Conntrack capacity changed during collection: {directory}")
    segments = []
    for left, right in zip(samples, samples[1:]):
        a, b = left["timestamp_monotonic_ns"], right["timestamp_monotonic_ns"]
        if b <= a:
            raise ValueError(f"Unordered conntrack samples: {directory}")
        if any(right[key] < left[key] for key in COUNTERS):
            raise ValueError(f"Conntrack counter regressed: {directory}")
        if a < end and b > start and b - a > max(4 * bin_seconds, 1) * 1e9:
            raise ValueError(f"Conntrack sampling gap: {directory}")
        segments.append((a, b, {key: (right[key] - left[key]) * 1e9 / (b - a) for key in COUNTERS}))
    duration = (end - start) / 1e9
    seconds = [index * bin_seconds for index in range(math.ceil(duration / bin_seconds))] + [duration]
    result, sample = [], 0
    for index, second in enumerate(seconds):
        timestamp = min(end, start + round(second * 1e9))
        boundary = min(end, start + round(seconds[index + 1] * 1e9)) if index + 1 < len(seconds) else end
        while sample + 1 < len(samples) and samples[sample + 1]["timestamp_monotonic_ns"] <= timestamp:
            sample += 1
        width = boundary - timestamp
        rates = {key + "_per_s": (
            sum(max(0, min(boundary, b) - max(timestamp, a)) * values[key]
                for a, b, values in segments) / width if width else result[-1][key + "_per_s"]
        ) for key in COUNTERS}
        result.append(dict(run=metadata["id"], mode=metadata["mode"], second=second,
                           **{key: samples[sample][key] for key in FIELDS}, interval_s=width / 1e9, **rates))
    return result
