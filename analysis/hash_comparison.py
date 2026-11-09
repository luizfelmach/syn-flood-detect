#!/usr/bin/env python3
"""Compare UBF index collisions locally, without traffic or a detector lab."""

import argparse
import json
import platform
import sys
import time
import importlib.util
from ipaddress import IPv4Address
from pathlib import Path
import random
import uuid
from statistics import mean, stdev

from common.hashing import HASH_FUNCTIONS as DETECTOR_HASH_FUNCTIONS
from common.cache import CACHE_ROOT
from common.collection import ROOT, save
from common.metrics import COLORS
from common.progress import report
from common.presentation import SingleLineHelpFormatter, preflight, show_png


def elf_hash(data):
    """SysV ELF mixing over all input bytes, including embedded zero bytes."""
    value = 0
    for byte in data:
        value = ((value << 4) + byte) & 0xFFFFFFFF
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value


# Comparison-only algorithms; keep the detector's supported hashes unchanged.
def rotating_hash(data):
    """Rotating Hash described by Bob Jenkins, using a 32-bit state."""
    value = len(data)
    for byte in data:
        value = ((value << 4) ^ (value >> 28) ^ byte) & 0xFFFFFFFF
    return value


HASH_FUNCTIONS = {
    "fnv1a": DETECTOR_HASH_FUNCTIONS["fnv1a"],
    "halfsiphash": DETECTOR_HASH_FUNCTIONS["halfsiphash"],
    "rotating": rotating_hash,
    "elf": elf_hash,
}
ALGORITHMS = tuple(HASH_FUNCTIONS)
LABELS = ("FNV-1a", "HalfSipHash", "Rotating Hash", "ELF hash")


def population_counts(total, attacker_percent):
    attackers = total * attacker_percent // 100
    return total - attackers, attackers


def parse(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare UBF index collisions across hash algorithms. Each execution draws fresh origins using operating-system randomness; no traffic or lab is required.",
        usage=argparse.SUPPRESS,
        add_help=False,
        formatter_class=SingleLineHelpFormatter,
    )
    required = parser.add_argument_group("Required")
    optional = parser.add_argument_group("Optional")
    required.add_argument("--ubf-size", type=int, metavar="VALUE", help="2048")
    required.add_argument("--sources", metavar="VALUES", help="100,250,500,1000,2000,4000,8000")
    required.add_argument("--attacker-percent", type=int, metavar="VALUE", help="50")
    optional.add_argument("--repetitions", type=int, default=1, metavar="COUNT", help="1")
    optional.add_argument(
        "--out", type=Path, metavar="FILE.png", help="results/figure.png (replaced if it exists)"
    )
    optional.add_argument("--dry-run", action="store_true", help="")
    optional.add_argument("-h", "--help", action="help", help="")
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        parser.print_help()
        parser.exit(0)
    args = parser.parse_args(argv)
    mandatory = ("ubf_size", "sources", "attacker_percent")
    missing = ["--" + field.replace("_", "-") for field in mandatory if getattr(args, field) is None]
    if missing:
        parser.error("Missing required parameters: " + ", ".join(missing) + ". Use --help for requirements.")
    try:
        args.sources = sorted(set(int(value) for value in args.sources.split(",")))
        if not args.sources or min(args.sources) < 1:
            raise ValueError
    except ValueError:
        parser.error("--sources: expected comma-separated positive integers")
    if not 1 <= args.ubf_size <= 8192:
        parser.error("--ubf-size must be in 1..8192")
    if not 0 <= args.attacker_percent <= 100:
        parser.error("--attacker-percent must be in 0..100")
    for kind, count in zip(("client", "attack"), population_counts(max(args.sources), args.attacker_percent)):
        capacity = len(set(source_generator(kind).PREFIXES)) * 65534
        if count > capacity:
            parser.error(f"{kind} population exceeds the available IPv4 addresses ({capacity})")
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    if args.out and args.out.suffix.lower() != ".png":
        parser.error("--out must end in .png")
    args.title, args.xlabel, args.ylabel = ("Colisões nos índices do UBF", None, None)
    args.xlim, args.ylim = (None, (0, 100))
    args.figsize, args.dpi = ([7.2, 4.5], 200)
    args.xscale, args.yscale = ("linear", "linear")
    args.cmap, args.vmin, args.vmax = ("Blues", 0, 100)
    return args


def source_generator(kind):
    """Load the actual generator without calling main, networking, or locks."""
    filename = {"client": "simulate-clients.py", "attack": "simulate-attack.py"}[kind]
    spec = importlib.util.spec_from_file_location("hash_origins_" + kind, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate_sources(kind, count):
    module = source_generator(kind)
    capacity = len(set(module.PREFIXES)) * 65534
    if not 0 <= count <= capacity:
        raise ValueError(f"{kind} population must be in 0..{capacity}")
    # Use OS randomness without changing the simulators or global random state.
    module.random = random.SystemRandom()
    allocated = set()
    return [module.allocate_ip(module.PREFIXES[i % len(module.PREFIXES)], allocated)
            for i in range(count)]


def service_key(source):
    return IPv4Address(source).packed + IPv4Address("203.0.113.2").packed + (80).to_bytes(2, "big")


def collision_pct(total, occupied):
    return 100 * (total - occupied) / total


def calculate(args):
    rows = []
    max_clients, max_attackers = population_counts(max(args.sources), args.attacker_percent)
    for repetition in range(args.repetitions):
        clients = [service_key(ip) for ip in generate_sources("client", max_clients)]
        attackers = [service_key(ip) for ip in generate_sources("attack", max_attackers)]
        for algorithm in ALGORITHMS:
            hash_function = HASH_FUNCTIONS[algorithm]
            occupied = set()
            previous_clients = previous_attackers = 0
            for total in args.sources:
                client_count, attack_count = population_counts(total, args.attacker_percent)
                for keys in (clients[previous_clients:client_count], attackers[previous_attackers:attack_count]):
                    occupied.update(hash_function(key) % args.ubf_size for key in keys)
                rows.append(dict(repetition=repetition + 1, algorithm=algorithm,
                                 ubf_size=args.ubf_size, sources=total, clients=client_count,
                                 attackers=attack_count, attacker_percent=args.attacker_percent,
                                 occupied_indices=len(occupied), collisions=total - len(occupied),
                                 collision_pct=collision_pct(total, len(occupied))))
                previous_clients, previous_attackers = client_count, attack_count
        report(f"Repetition {repetition + 1}/{args.repetitions} complete")
    return rows


def summarize(rows):
    groups = {}
    for row in rows:
        key = row["algorithm"], row["sources"]
        groups.setdefault(key, []).append(row)
    summary = []
    for (algorithm, sources), group in groups.items():
        values = [row["collision_pct"] for row in group]
        summary.append(dict(algorithm=algorithm, sources=sources, ubf_size=group[0]["ubf_size"],
                            attacker_percent=group[0]["attacker_percent"], repetitions=len(values),
                            collision_pct_mean=mean(values),
                            collision_pct_std=stdev(values) if len(values) > 1 else 0.0))
    return summary


def render(args, rows, output):
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.ticker import MaxNLocator

    plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"],
                         "font.size": 10, "axes.titlesize": 11, "axes.linewidth": 0.7,
                         "xtick.direction": "in", "ytick.direction": "in",
                         "legend.fontsize": 8, "legend.frameon": False})
    fig = Figure(figsize=args.figsize, layout="constrained")
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    summary = summarize(rows)
    for algorithm, label, color in zip(ALGORITHMS, LABELS, COLORS):
        lookup = {row["sources"]: row for row in summary if row["algorithm"] == algorithm}
        ys = [lookup[total]["collision_pct_mean"] for total in args.sources]
        stds = [lookup[total]["collision_pct_std"] for total in args.sources]
        ax.plot(args.sources, ys, marker="o", markerfacecolor="white",
                markersize=4, linewidth=1.2, color=color, label=label)
        if args.repetitions > 1:
            ax.fill_between(args.sources,
                            [max(0, y - std) for y, std in zip(ys, stds)],
                            [min(100, y + std) for y, std in zip(ys, stds)],
                            color=color, alpha=0.15)
    ax.set(title=f"{args.title}\nUBF_SIZE = {args.ubf_size}",
           xlabel=args.xlabel or "Quantidade de chaves inseridas", ylabel=args.ylabel or "Colisões (%)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)
    ax.grid(axis="y", color=".88", linewidth=0.5)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=len(ALGORITHMS))
    for axis in ("x", "y"):
        getattr(ax, "set_" + axis + "scale")(getattr(args, axis + "scale"))
        if getattr(args, axis + "lim"):
            getattr(ax, "set_" + axis + "lim")(getattr(args, axis + "lim"))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def cases_for(args):
    cases = []
    for rep in range(1, args.repetitions + 1):
        for algorithm in ALGORITHMS:
            for total in args.sources:
                clients, attackers = population_counts(total, args.attacker_percent)
                cases.append(dict(
                    id=f"{len(cases) + 1:04d}-r{rep}", repetition=rep,
                    hash_algorithm=algorithm, ubf_size=args.ubf_size, sources=total,
                    clients=clients, attackers=attackers,
                ))
    return cases


def execute(args, cases):
    if args.dry_run:
        return
    directory = CACHE_ROOT / "hash_comparison" / "attempts" / uuid.uuid4().hex
    report("Generating fresh origins with operating-system randomness; cache reuse disabled")
    collect(args, cases, directory)
    output = args.out.resolve() if args.out else directory / "figure.png"
    print(f"PNG: {output}\nData: {directory}", flush=True)
    if args.out is None:
        report("Opening PNG window; close the window to finish")
        show_png(output)


def collect(args, cases, directory):
    started = time.monotonic()
    report("Preflight: checking output and plotting dependencies")
    preflight(args.out, args.cmap)
    directory.mkdir(parents=True, exist_ok=False)
    report(f"Data directory: {directory}")
    manifest = dict(
        kind="hash_comparison", status="running", command=[sys.executable, *sys.argv],
        options={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        cases=cases, python=platform.python_version(), randomness="os",
    )
    save(directory / "experiment.json", manifest)
    try:
        rows = calculate(args)
        save(directory / "rows.json", rows)
        output = args.out.resolve() if args.out else directory / "figure.png"
        report(f"Rendering PNG: {output}")
        render(args, rows, output)
        manifest.update(status="complete", figure=str(output), elapsed_s=time.monotonic() - started)
        report(f"Experiment complete; elapsed: {manifest['elapsed_s']:.1f} s")
        return rows
    except BaseException as error:
        manifest.update(status="failed", error=str(error) or type(error).__name__,
                        elapsed_s=time.monotonic() - started)
        report(f"Failed: {manifest['error']}; evidence: {directory}")
        raise
    finally:
        save(directory / "experiment.json", manifest)


def main(argv=None):
    args = parse(argv)
    cases = cases_for(args)
    print("Experiment configuration:", flush=True)
    for name, value in [
        ("UBF_SIZE", args.ubf_size),
        ("Sources", args.sources),
        ("Attacker percentage", args.attacker_percent),
        ("Hash algorithms", ALGORITHMS),
        ("Repetitions", args.repetitions),
        ("Randomness", "operating system (fresh origins on every execution)"),
    ]:
        print(f"  {name}: {value}", flush=True)
    print(f"  Output: {args.out or 'automatic PNG under results/analysis/cache/ and native window'}", flush=True)
    print(f"  Parameter combinations: {len(cases) // args.repetitions}; total runs: {len(cases)}", flush=True)
    print("Local hash calculations only; no traffic or lab required.", flush=True)
    if args.dry_run:
        print(json.dumps(cases, indent=2))
        return 0
    try:
        execute(args, cases)
    except KeyboardInterrupt:
        print("Experiment interrupted; collected data are preserved.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
