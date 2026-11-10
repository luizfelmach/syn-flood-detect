"""Sample port-80 IPv4 SYN_RECV occupancy and namespace-wide queue-full drops."""

from contextlib import contextmanager
import csv
import math
import subprocess
import threading
import time

from .collection import ROOT


# /proc/net/tcp: local address is column 2; TCP_SYN_RECV is state 03 in column 4.
SYN_RECV_AWK = '$4 == "03" { split($2, address, ":"); if (address[2] == "0050") count++ } END { print count+0 }'

# Match the counter by name; its column can change between kernel versions.
QUEUE_STATS_AWK = '''
FNR == NR {
    if ($4 == "03") { split($2, address, ":"); if (address[2] == "0050") count++ }
    next
}
$1 == "TcpExt:" && !header {
    for (i=2; i<=NF; i++) if ($i == "TCPReqQFullDrop") column=i
    header=1; next
}
$1 == "TcpExt:" && header {
    if (!column || column>NF || $column !~ /^[0-9]+$/) exit 2
    drops=$column; found=1; exit
}
END { if (!found) exit 2; print count+0, drops }
'''


@contextmanager
def sample_syn_queue(prefix, directory, interval):
    """One persistent Docker exec avoids starting a Docker client per sample."""
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("Queue sampling interval must be finite and positive")
    script = (
        'set -eu\nprintf "PID %s\\n" "$$"\ntrap "exit 0" TERM INT\n'
        f"while :; do awk '{QUEUE_STATS_AWK}' /proc/net/tcp /proc/net/netstat; sleep {interval:.9f}; done"
    )
    server = prefix + "server"
    ready, stopping = threading.Event(), threading.Event()
    errors, remote_pid = [], []
    with (directory / "syn_queue.csv").open("w", newline="") as stream, \
         (directory / "syn_queue.log").open("w") as log:
        writer = csv.DictWriter(stream, fieldnames=("timestamp_monotonic_ns", "syn_recv", "tcp_req_q_full_drop"))
        writer.writeheader()
        proc = subprocess.Popen(
            ["docker", "exec", server, "sh", "-c", script], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1,
        )

        def monitor():
            try:
                header = proc.stdout.readline().strip().split()
                if len(header) != 2 or header[0] != "PID" or int(header[1]) <= 0:
                    raise RuntimeError("Queue sampler did not report its remote PID")
                remote_pid.append(int(header[1]))
                for line in proc.stdout:
                    count, drops = map(int, line.split())
                    if count < 0 or drops < 0:
                        raise ValueError("Negative queue counters")
                    writer.writerow(dict(timestamp_monotonic_ns=time.monotonic_ns(), syn_recv=count,
                                         tcp_req_q_full_drop=drops))
                    stream.flush()
                    ready.set()
                if not stopping.is_set():
                    raise RuntimeError("Queue sampler exited before the observation finished")
            except Exception as error:
                errors.append(error)
                ready.set()

        thread = threading.Thread(target=monitor, name="syn-queue-sampler", daemon=True)
        thread.start()
        try:
            if not ready.wait(10):
                raise RuntimeError(f"Queue sampler did not become ready; see {directory / 'syn_queue.log'}")
            if errors:
                raise RuntimeError(f"Queue sampling failed: {errors[0]}") from errors[0]
            yield
        finally:
            stopping.set()
            try:
                if remote_pid and proc.poll() is None:
                    result = subprocess.run(
                        ["docker", "exec", server, "kill", "-TERM", str(remote_pid[0])],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode and proc.poll() is None:
                        errors.append(RuntimeError(f"Could not stop queue sampler: {result.stderr.strip()}"))
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
                    errors.append(RuntimeError("Queue sampler did not stop cleanly"))
            finally:
                thread.join(timeout=5)
                if thread.is_alive():
                    errors.append(RuntimeError("Queue sampler reader did not stop"))
                else:
                    proc.stdout.close()
            if errors:
                raise RuntimeError(f"Queue sampling failed: {errors[0]}") from errors[0]


def queue_series(directory, metadata, bin_seconds):
    """Hold occupancy snapshots and distribute counter deltas over their actual intervals."""
    with (directory / "syn_queue.csv").open() as stream:
        reader = csv.DictReader(stream)
        if not {"timestamp_monotonic_ns", "syn_recv", "tcp_req_q_full_drop"}.issubset(reader.fieldnames or []):
            raise ValueError(f"Missing queue counters: {directory}")
        samples = [{key: int(value) for key, value in row.items()} for row in reader]
    start, end = metadata["start_ns"], metadata["end_ns"]
    if (len(samples) < 2 or samples[0]["timestamp_monotonic_ns"] > start
            or samples[-1]["timestamp_monotonic_ns"] < end):
        raise ValueError(f"Missing SYN_RECV coverage: {directory}")
    if any(row["syn_recv"] < 0 or row["tcp_req_q_full_drop"] < 0 for row in samples):
        raise ValueError(f"Negative queue counters: {directory}")
    segments = []
    for left, right in zip(samples, samples[1:]):
        gap = right["timestamp_monotonic_ns"] - left["timestamp_monotonic_ns"]
        if gap <= 0:
            raise ValueError(f"Unordered SYN_RECV samples: {directory}")
        delta = right["tcp_req_q_full_drop"] - left["tcp_req_q_full_drop"]
        if delta < 0:
            raise ValueError(f"Queue drop counter regressed: {directory}")
        segments.append((left["timestamp_monotonic_ns"], right["timestamp_monotonic_ns"], delta * 1e9 / gap))
        if left["timestamp_monotonic_ns"] < end and right["timestamp_monotonic_ns"] > start:
            if gap > max(4 * bin_seconds, 1) * 1e9:
                raise ValueError(f"SYN_RECV sampling gap: {directory}")
    result, sample = [], 0
    duration = (end - start) / 1e9
    seconds = [index * bin_seconds for index in range(math.ceil(duration / bin_seconds))] + [duration]
    for index, second in enumerate(seconds):
        timestamp = min(end, start + round(second * 1e9))
        while sample + 1 < len(samples) and samples[sample + 1]["timestamp_monotonic_ns"] <= timestamp:
            sample += 1
        boundary = min(end, start + round(seconds[index + 1] * 1e9)) if index + 1 < len(seconds) else end
        width = boundary - timestamp
        rate = (sum(max(0, min(boundary, b) - max(timestamp, a)) * value
                    for a, b, value in segments) / width) if width else result[-1]["queue_drop_per_s"]
        result.append(dict(run=metadata["id"], mode=metadata["mode"], second=second,
                           syn_recv=samples[sample]["syn_recv"],
                           tcp_req_q_full_drop=samples[sample]["tcp_req_q_full_drop"],
                           interval_s=width / 1e9, queue_drop_per_s=rate))
    return result
