"""Run an existing simulator against this experiment's exclusive container."""

import importlib.util
import asyncio
from functools import partial
from pathlib import Path
import random
import sys


def main():
    _, kind, seed, count, interval, prefix, *ramp = sys.argv
    name = {"client": "simulate-clients.py", "attack": "simulate-attack.py"}[kind]
    path = Path(__file__).resolve().parents[2] / "scripts" / name
    spec = importlib.util.spec_from_file_location("traffic_simulator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CONTAINER = prefix + ("client" if kind == "client" else "attacker")
    random.seed(int(seed))
    if ramp:
        from ramp import quiet_attack_worker, simulate_ramp

        steps, step_seconds = ramp
        module.attack_worker = partial(quiet_attack_worker, module)
        asyncio.run(simulate_ramp(module, [int(value) for value in steps.split(",")],
                                  float(interval), float(step_seconds)))
        return 0
    sys.argv = [str(path), count, interval]
    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
