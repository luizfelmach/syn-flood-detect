"""Attacker ramps retain existing sources and clean up on worker failures."""

import asyncio
from contextlib import nullcontext, redirect_stdout
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.ramp import quiet_attack_worker, simulate_ramp


class RampTests(unittest.IsolatedAsyncioTestCase):
    async def test_quiet_generator_keeps_interval_and_logs_source_once(self):
        process = Mock(returncode=0)
        process.wait = AsyncMock()
        processes = {process}
        module = SimpleNamespace(docker=AsyncMock(return_value=process), INTERFACE="eth1",
                                 DESTINATION="203.0.113.2", hping_interval=lambda value: "u10000")
        with redirect_stdout(io.StringIO()) as output:
            await quiet_attack_worker(module, 1, "37.120.0.1", .01, processes)
        arguments = module.docker.call_args.args
        self.assertNotIn("--debug", arguments)
        self.assertEqual(arguments[arguments.index("--interval") + 1], "u10000")
        self.assertEqual(output.getvalue().count("source=37.120.0.1"), 1)
        self.assertEqual(processes, set())

    async def test_command_overhead_does_not_extend_step_deadlines(self):
        clock, waits, callbacks = [0.], [], []

        async def worker(*args):
            await asyncio.Future()

        async def command(*args, **kwargs):
            if "-f" in args:
                clock[0] += 2  # Each source-control command takes two seconds.

        async def wait(tasks, timeout=None, **kwargs):
            await asyncio.sleep(0)
            if timeout is None:
                callbacks[0]()
                return {tasks[0]}, set()
            waits.append(timeout)
            clock[0] += timeout
            return set(), set(tasks)

        def allocate(prefix, allocated):
            address = str(len(allocated))
            allocated.add(address)
            return address

        module = SimpleNamespace(node_lock=nullcontext, command=command, INTERFACE="eth1",
                                 allocate_ip=allocate, PREFIXES=("test",), attack_worker=worker)
        loop = SimpleNamespace(time=lambda: clock[0],
                               add_signal_handler=lambda sig, callback: callbacks.append(callback),
                               remove_signal_handler=lambda sig: None)
        with patch("common.ramp.asyncio.get_running_loop", return_value=loop), \
             patch("common.ramp.asyncio.wait", side_effect=wait), redirect_stdout(io.StringIO()):
            await simulate_ramp(module, [3, 1, 0, 2, 3], .1, 10)
        self.assertEqual(waits, [10, 8, 8, 8, 8])
        self.assertEqual(clock[0], 50)

    async def test_decreases_to_zero_and_resumes_the_same_sources(self):
        started, commands, callbacks = [], [], []

        async def worker(index, address, interval, processes):
            started.append(index)
            await asyncio.Future()

        async def command(*args, **kwargs):
            commands.append(args)

        def allocate(prefix, allocated):
            address = f"37.120.0.{len(allocated) + 1}"
            allocated.add(address)
            return address

        module = SimpleNamespace(node_lock=nullcontext, command=command, INTERFACE="eth1",
                                 allocate_ip=allocate, PREFIXES=("test",), attack_worker=worker)
        loop = asyncio.get_running_loop()
        timer = loop.call_later(.1, lambda: callbacks[0]())
        try:
            with patch.object(loop, "add_signal_handler", side_effect=lambda sig, callback: callbacks.append(callback)), \
                 patch.object(loop, "remove_signal_handler"), redirect_stdout(io.StringIO()) as output:
                await simulate_ramp(module, [3, 1, 0, 2, 3], .1, .01)
        finally:
            timer.cancel()
        self.assertEqual(started, [1, 2, 3])
        selective = [command for command in commands if "-f" in command]
        self.assertEqual([command[1] for command in selective], ["-STOP", "-STOP", "-CONT", "-CONT"])
        self.assertIn("37\\.120\\.0\\.2", selective[0][-1])
        self.assertEqual([line.split("attackers=")[1] for line in output.getvalue().splitlines()], ["3", "1", "0", "2", "3"])
        self.assertEqual(commands[-2:], [("pkill", "-CONT", "-x", "hping3"), ("pkill", "-TERM", "-x", "hping3")])

    async def test_adds_sources_without_restarting_previous_workers(self):
        started, cancelled, commands = [], [], []
        stop = None

        async def worker(index, address, interval, processes):
            started.append(index)
            if index == 5:
                # Exercise the same signal callback that stops a real simulation.
                asyncio.get_running_loop().call_soon(stop)
            try:
                await asyncio.Future()
            finally:
                cancelled.append(index)

        async def command(*args, **kwargs):
            commands.append(args)

        module = SimpleNamespace(node_lock=nullcontext, command=command, INTERFACE="eth1",
                                 allocate_ip=lambda prefix, allocated: str(len(started)),
                                 PREFIXES=("test",), attack_worker=worker)
        loop = asyncio.get_running_loop()
        original_add, original_remove = loop.add_signal_handler, loop.remove_signal_handler
        # Avoid replacing the test process's signal handlers.
        def register(sig, callback):
            nonlocal stop
            stop = callback
        loop.add_signal_handler = register
        loop.remove_signal_handler = lambda sig: None
        try:
            with redirect_stdout(io.StringIO()) as output:
                await simulate_ramp(module, [2, 3, 5], .1, .01)
        finally:
            loop.add_signal_handler, loop.remove_signal_handler = original_add, original_remove
        self.assertEqual(started, [1, 2, 3, 4, 5])
        self.assertCountEqual(cancelled, started)
        self.assertEqual(commands[-1], ("pkill", "-TERM", "-x", "hping3"))
        self.assertEqual([line.split("attackers=")[1] for line in output.getvalue().splitlines()], ["2", "3", "5"])


if __name__ == "__main__":
    unittest.main()
