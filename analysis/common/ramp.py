"""Vary active attacker sources, pausing and resuming their existing generators."""

import asyncio
import re
import signal
import time


async def quiet_attack_worker(module, index, address, interval, processes):
    """Log each source once; firewall packet CSVs remain the rate measurement."""
    process = await module.docker(
        "hping3", "--numeric", "--quiet", "--interface", module.INTERFACE,
        "--syn", "--interval", module.hping_interval(interval), "--destport", "80",
        "--spoof", address, module.DESTINATION, processes=processes,
    )
    print(f"attack={index} source={address} started", flush=True)
    await process.wait()
    processes.discard(process)
    if process.returncode:
        raise RuntimeError(f"Attacker source {address} exited with code {process.returncode}")


async def simulate_ramp(module, steps, interval, step_seconds):
    processes, workers = set(), []
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    with module.node_lock():
        for sig in signals:
            loop.add_signal_handler(sig, stopped.set)
        stop_waiter = asyncio.create_task(stopped.wait())
        initialized = False
        try:
            await module.command("ip", "link", "show", "dev", module.INTERFACE, processes=processes)
            initialized = True
            allocated, addresses = set(), []
            active = 0

            async def signal_sources(signum, sources):
                if sources:
                    pattern = "^hping3 .*--spoof (" + "|".join(re.escape(ip) for ip in sources) + ") "
                    await module.command("pkill", signum, "-f", pattern, processes=processes)

            ramp_start = loop.time()
            for step_index, count in enumerate(steps):
                if stopped.is_set():
                    break
                if count < active:
                    await signal_sources("-STOP", addresses[count:active])
                elif count > active:
                    await signal_sources("-CONT", addresses[active:min(count, len(workers))])
                for index in range(len(workers), count):
                    address = module.allocate_ip(module.PREFIXES[index % len(module.PREFIXES)], allocated)
                    addresses.append(address)
                    workers.append(asyncio.create_task(module.attack_worker(index + 1, address, interval, processes)))
                active = count
                print(f"ramp timestamp_monotonic_ns={time.monotonic_ns()} attackers={count}", flush=True)
                remaining = max(0, ramp_start + (step_index + 1) * step_seconds - loop.time())
                done, _ = await asyncio.wait([stop_waiter, *workers], timeout=remaining,
                                             return_when=asyncio.FIRST_COMPLETED)
                if any(task in done for task in workers):
                    raise RuntimeError("An attacker worker exited during the ramp")
            if not stopped.is_set():
                done, _ = await asyncio.wait([stop_waiter, *workers], return_when=asyncio.FIRST_COMPLETED)
                if any(task in done for task in workers):
                    raise RuntimeError("An attacker worker exited after the ramp")
        finally:
            try:
                for task in (stop_waiter, *workers):
                    task.cancel()
                await asyncio.gather(stop_waiter, *workers, return_exceptions=True)
                await asyncio.gather(*(module.terminate(process) for process in processes))
                processes.clear()
                if initialized:
                    # Stopped processes must run again to receive SIGTERM and exit.
                    await module.command("pkill", "-CONT", "-x", "hping3", processes=processes, check=False)
                    await module.command("pkill", "-TERM", "-x", "hping3", processes=processes, check=False)
            finally:
                for sig in signals:
                    loop.remove_signal_handler(sig)
