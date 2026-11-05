"""Run an existing simulator against this experiment's exclusive container."""

import importlib.util
from pathlib import Path
import random
import sys


def main():
    _, kind, seed, count, interval, prefix = sys.argv
    name = {"client": "simulate-clients.py", "attack": "simulate-attack.py"}[kind]
    path = Path(__file__).resolve().parents[2] / "scripts" / name
    spec = importlib.util.spec_from_file_location("traffic_simulator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CONTAINER = prefix + ("client" if kind == "client" else "attacker")
    random.seed(int(seed))
    sys.argv = [str(path), count, interval]
    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
