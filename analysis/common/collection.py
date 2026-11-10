#!/usr/bin/env python3
"""External experiment runner; never edits the detector or existing simulators."""

import json
from decimal import Decimal
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from .progress import report

ROOT = Path(__file__).resolve().parents[2]


def command(*args):
    return subprocess.check_output(
        args, cwd=ROOT, text=True, stderr=subprocess.STDOUT
    ).strip()


def control(prefix, *args):
    return command(
        "docker", "exec", prefix + "firewall", "/usr/local/bin/syn-flood-detect", *args
    )


def save(path, obj):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    tmp.replace(path)


def sleep_checked(seconds, workers, phase=None):
    started = time.monotonic()
    deadline = started + seconds
    next_update = started + 5
    if phase:
        report(f"{phase}: started ({seconds:g} s)")
    while time.monotonic() < deadline:
        for proc, _, _ in workers:
            if proc.poll() is not None:
                raise RuntimeError(f"Simulator exited unexpectedly: {proc.args}")
        now = time.monotonic()
        if phase and now >= next_update:
            report(
                f"{phase}: {now - started:.1f} s elapsed, {max(0, deadline - now):.1f} s remaining"
            )
            next_update = now + 5
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    if phase:
        report(f"{phase}: finished ({time.monotonic() - started:.1f} s elapsed)")


def start(kind, count, interval, directory, seed, prefix, *, steps=None, step_seconds=None):
    path = directory / f"{kind}.log"
    log = path.open("w")
    proc = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "analysis/common/simulator.py"),
            kind,
            str(seed),
            str(count),
            format(Decimal(str(interval)), "f"),
            prefix,
        ] + ([",".join(map(str, steps)), str(step_seconds)] if steps else []),
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return proc, log, path


def ready(worker, count, workers, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sources = set(re.findall(r"source=([0-9.]+)", worker[2].read_text()))
        if len(sources) >= count:
            return sorted(sources)
        sleep_checked(0.25, workers)
    raise RuntimeError(f"Timeout waiting for {count} sources; inspect {worker[2]}")


def stop(worker):
    proc, log, _ = worker
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise RuntimeError(
                "Simulator cleanup timed out; inspect remote processes before resuming"
            )
    log.close()
    if proc.returncode:
        raise RuntimeError(f"Simulator failed with exit code {proc.returncode}")


def tail_record(path):
    with path.open("rb") as f:
        f.seek(max(0, path.stat().st_size - 8192))
        rows = f.read().splitlines(keepends=True)
    return rows[-1] if len(rows) > 1 else b""


def wait_for_idle(prefix, timeout=5):
    """Do not reuse a lab while remote traffic generators are still alive."""
    deadline = time.monotonic() + timeout
    while True:
        active = []
        for node, process in (("client", "curl"), ("attacker", "hping3")):
            result = subprocess.run(
                ["docker", "exec", prefix + node, "pgrep", "-x", process],
                text=True, capture_output=True, check=False, timeout=10,
            )
            if result.returncode == 0:
                active.append(f"{node}/{process}")
            elif result.returncode != 1:
                raise RuntimeError(f"Cannot verify idle lab: {result.stderr.strip()}")
        if not active:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Traffic generators remain active: {', '.join(active)}")
        time.sleep(0.1)


def capture_tail(path, offset, destination, baseline=b""):
    with path.open("rb") as src, destination.open("wb") as dst:
        dst.write(src.readline())
        if baseline:
            dst.write(baseline)
        src.seek(offset)
        while chunk := src.read(1024 * 1024):
            dst.write(chunk)


def run_one(
    case, output, duration, timeout, prefix, packet_dir, *, before=None, after=None
):
    directory = output / case["id"]
    directory.mkdir(exist_ok=True)
    metadata = {
        **case,
        "status": "running",
        "duration_s": duration,
        "phases": {},
        "sources": {},
    }
    if before is not None:
        metadata.update(before_s=before, after_s=after)
    path = directory / "run.json"
    workers = []
    started_capture = False

    def stage(name):
        metadata["stage"] = name
        save(path, metadata)
        report(name)

    try:
        stage("Verifying previous traffic generators have stopped")
        wait_for_idle(prefix)
        stage("Applying detector configuration")
        metadata["config_before"] = control(prefix, "show")
        # Keep packet processing from updating history while config/reset clears it.
        control(prefix, "mode", "allow")
        control(
            prefix,
            "config",
            "--idle-timeout-ms",
            str(case["idle_timeout_ms"]),
            "--syn-count-block-threshold",
            str(case["threshold"]),
            "--ubf-size",
            str(case["ubf_size"]),
            "--hash-algorithm",
            case["hash_algorithm"],
        )
        control(prefix, "reset")
        control(prefix, "mode", case["mode"])
        metadata["config"] = control(prefix, "show")
        fields = dict(
            re.findall(
                r"(mode|idle_timeout_ms|syn_count_block_threshold|ubf_size|hash_algorithm)=(\w+)",
                metadata["config"],
            )
        )
        expected = dict(
            mode=case["mode"],
            idle_timeout_ms=str(case["idle_timeout_ms"]),
            syn_count_block_threshold=str(case["threshold"]),
            ubf_size=str(case["ubf_size"]),
            hash_algorithm=case["hash_algorithm"],
        )
        if any(fields.get(k) != v for k, v in expected.items()):
            raise RuntimeError(
                f"Applied configuration differs from the requested configuration: {metadata['config']}"
            )
        report(f"Applied configuration: {metadata['config']}")
        time.sleep(1.3)
        packets = max(
            packet_dir.glob("packets-*.csv"), key=lambda p: p.stat().st_mtime_ns
        )
        stats = packets.with_name(packets.name.replace("packets-", "stats-", 1))
        packet_offset, stats_offset = packets.stat().st_size, stats.stat().st_size
        baseline = tail_record(stats)
        metadata["collector_file"] = packets.name
        metadata["start_ns"] = time.monotonic_ns()
        started_capture = True
        save(path, metadata)
        if case["clients"]:
            stage(
                f"Initializing {case['clients']} legitimate sources; log: {directory / 'client.log'}"
            )
            worker = start(
                "client",
                case["clients"],
                case["client_interval"],
                directory,
                case["client_seed"],
                prefix,
            )
            workers.append(worker)
            metadata["sources"]["client"] = ready(
                worker, case["clients"], workers, timeout
            )
            metadata["phases"]["clients_ready_ns"] = time.monotonic_ns()
            report(f"Legitimate sources ready: {len(metadata['sources']['client'])}")
        if before is not None:
            stage("Before-attack observation")
            metadata["phases"]["before_start_ns"] = time.monotonic_ns()
            save(path, metadata)
            sleep_checked(before, workers, "Before attack")
            metadata["phases"]["before_end_ns"] = time.monotonic_ns()
        if case["attackers"]:
            stage(
                f"Initializing {case['attackers']} attacker sources; log: {directory / 'attack.log'}"
            )
            metadata["phases"]["attack_launch_ns"] = time.monotonic_ns()
            worker = start(
                "attack",
                case["attackers"],
                case["attack_interval"],
                directory,
                case["attack_seed"],
                prefix,
                steps=case.get("attack_steps"),
                step_seconds=case.get("step_duration_s"),
            )
            workers.append(worker)
            metadata["sources"]["attack"] = ready(
                worker, case.get("attack_steps", [case["attackers"]])[0], workers, timeout
            )
            report(f"Attacker sources ready: {len(metadata['sources']['attack'])}")
        stage("Measurement phase")
        metadata["phases"]["measure_start_ns"] = time.monotonic_ns()
        save(path, metadata)
        sleep_checked(duration, workers, "Measurement")
        metadata["phases"]["measure_end_ns"] = time.monotonic_ns()
        if case.get("attack_steps"):
            metadata["sources"]["attack"] = sorted(set(re.findall(
                r"source=([0-9.]+)", worker[2].read_text(),
            )))
            if len(metadata["sources"]["attack"]) != case["attackers"]:
                raise RuntimeError("Attacker ramp did not start all sources within the measurement duration")
            metadata["attack_ramp"] = [
                dict(timestamp_monotonic_ns=int(timestamp), attackers=int(count))
                for timestamp, count in re.findall(
                    r"ramp timestamp_monotonic_ns=(\d+) attackers=(\d+)",
                    worker[2].read_text(),
                )
            ]
            if [step["attackers"] for step in metadata["attack_ramp"]] != case["attack_steps"]:
                raise RuntimeError("Attacker ramp did not complete the requested steps")
        if case["attackers"]:
            stage("Stopping attacker generators")
            stop(workers[-1])
            workers.pop()
            metadata["phases"]["attack_stopped_ns"] = time.monotonic_ns()
        if after is not None:
            stage("After-attack observation")
            metadata["phases"]["after_start_ns"] = time.monotonic_ns()
            save(path, metadata)
            sleep_checked(after, workers, "After attack")
            metadata["phases"]["after_end_ns"] = time.monotonic_ns()
        metadata["end_ns"] = time.monotonic_ns()
        metadata["status"] = "complete"
    except BaseException as error:
        metadata["status"] = "failed"
        metadata["error"] = str(error) or type(error).__name__
        report(
            f"Run failed during {metadata.get('stage', 'setup')}: {metadata['error']}; logs: {directory}"
        )
        raise
    finally:
        report("Stopping remaining traffic generators")
        cleanup_errors = []
        for worker in reversed(workers):
            try:
                stop(worker)
            except Exception as error:
                cleanup_errors.append(str(error))
        try:
            wait_for_idle(prefix)
        except Exception as error:
            cleanup_errors.append(str(error))
        metadata.setdefault("end_ns", time.monotonic_ns())
        if cleanup_errors:
            metadata["status"] = "failed"
            metadata["cleanup_errors"] = cleanup_errors
        try:
            if started_capture:
                report(
                    f"Flushing and collecting packet/statistics CSVs into {directory}"
                )
                time.sleep(1.5)  # collector snapshots and flushes once per second
                capture_tail(packets, packet_offset, directory / "packets.csv")
                capture_tail(stats, stats_offset, directory / "stats.csv", baseline)
        except Exception as error:
            metadata.update(status="failed", capture_error=str(error))
            raise
        finally:
            save(path, metadata)
        report(f"Collection status: {metadata['status']}; metadata: {path}")
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
