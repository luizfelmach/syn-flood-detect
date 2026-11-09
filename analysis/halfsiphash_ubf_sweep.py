#!/usr/bin/env python3
"""Sweep UBF sizes for HalfSipHash with a fixed number of origins."""

import argparse
import json
import platform
import sys
import time
from pathlib import Path
import uuid
from statistics import mean, stdev

from common.cache import CACHE_ROOT
from common.collection import save
from common.hashing import halfsiphash_2_4_32
from common.metrics import COLORS
from common.progress import report
from common.presentation import SingleLineHelpFormatter, preflight, show_png
from hash_comparison import population_counts, source_generator, generate_sources, service_key, collision_pct


def parse(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare HalfSipHash collisions across a neighborhood of UBF sizes. Each execution draws fresh origins using operating-system randomness; no traffic or lab is required.",
        usage=argparse.SUPPRESS,
        add_help=False,
        formatter_class=SingleLineHelpFormatter,
    )
    required = parser.add_argument_group("Required")
    optional = parser.add_argument_group("Optional")
    required.add_argument("--ubf-center", type=int, metavar="VALUE", help="4096")
    required.add_argument("--ubf-radius", type=int, metavar="VALUE", help="256")
    required.add_argument("--sources", type=int, metavar="VALUE", help="2000")
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
    mandatory = ("ubf_center", "ubf_radius", "sources", "attacker_percent")
    missing = ["--" + field.replace("_", "-") for field in mandatory if getattr(args, field) is None]
    if missing:
        parser.error("Missing required parameters: " + ", ".join(missing) + ". Use --help for requirements.")
    if args.ubf_radius < 0:
        parser.error("--ubf-radius must be nonnegative")
    lower, upper = args.ubf_center - args.ubf_radius, args.ubf_center + args.ubf_radius
    if not 1 <= lower <= upper <= 8192:
        parser.error("The complete UBF interval must be within 1..8192")
    if args.sources < 1:
        parser.error("--sources must be positive")
    args.ubf_size = list(range(lower, upper + 1))
    if not 0 <= args.attacker_percent <= 100:
        parser.error("--attacker-percent must be in 0..100")
    for kind, count in zip(("client", "attack"), population_counts(args.sources, args.attacker_percent)):
        capacity = len(set(source_generator(kind).PREFIXES)) * 65534
        if count > capacity:
            parser.error(f"{kind} population exceeds the available IPv4 addresses ({capacity})")
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    if args.out and args.out.suffix.lower() != ".png":
        parser.error("--out must end in .png")
    args.title, args.xlabel, args.ylabel = ("Colisões do HalfSipHash por tamanho do UBF", None, None)
    args.xlim, args.ylim = (None, None)
    args.figsize, args.dpi = ([7.2, 4.5], 200)
    args.xscale, args.yscale = ("linear", "linear")
    args.cmap, args.vmin, args.vmax = ("Blues", 0, 100)
    return args


def calculate(args):
    rows = []
    max_clients, max_attackers = population_counts(args.sources, args.attacker_percent)
    for repetition in range(args.repetitions):
        clients = [service_key(ip) for ip in generate_sources("client", max_clients)]
        attackers = [service_key(ip) for ip in generate_sources("attack", max_attackers)]
        hashes = [halfsiphash_2_4_32(key) for key in clients + attackers]
        for size in args.ubf_size:
            occupied = len({value % size for value in hashes})
            rows.append(dict(repetition=repetition + 1, algorithm="halfsiphash",
                             ubf_size=size, sources=args.sources, clients=max_clients,
                             attackers=max_attackers, attacker_percent=args.attacker_percent,
                             occupied_indices=occupied, collisions=args.sources - occupied,
                             collision_pct=collision_pct(args.sources, occupied)))
        report(f"Repetition {repetition + 1}/{args.repetitions} complete")
    return rows


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault(row["ubf_size"], []).append(row)
    summary = []
    for size, group in sorted(groups.items()):
        values = [row["collision_pct"] for row in group]
        summary.append(dict(ubf_size=size, sources=group[0]["sources"],
                            repetitions=len(group), collisions_total=sum(row["collisions"] for row in group),
                            collision_pct_mean=mean(values),
                            collision_pct_std=stdev(values) if len(values) > 1 else 0.0))
    return summary


def ranked(summary):
    # Every size has the same number of keys and repetitions. Integer totals
    # preserve exact ties without floating-point equality artifacts.
    return sorted(summary, key=lambda row: (row["collisions_total"], row["ubf_size"]))


def minima(summary):
    ordered = ranked(summary)
    return [row for row in ordered if row["collisions_total"] == ordered[0]["collisions_total"]]


def print_ranking(summary):
    print("Lowest observed mean collision rates (sample-specific):", flush=True)
    for row in ranked(summary)[:10]:
        print(f"  UBF_SIZE={row['ubf_size']}: {row['collision_pct_mean']:.4f}%", flush=True)
    best = minima(summary)
    print("All tied minima: " + ", ".join(str(row["ubf_size"]) for row in best), flush=True)


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
    xs = [row["ubf_size"] for row in summary]
    ys = [row["collision_pct_mean"] for row in summary]
    stds = [row["collision_pct_std"] for row in summary]
    low = [max(0, y - std) for y, std in zip(ys, stds)]
    high = [min(100, y + std) for y, std in zip(ys, stds)]
    ax.plot(xs, ys, linewidth=1, color=COLORS[0], label="HalfSipHash",
            marker="o" if len(xs) == 1 else None, markersize=4)
    if args.repetitions > 1:
        ax.fill_between(xs, low, high, color=COLORS[0], alpha=0.15)
    ax.axvline(args.ubf_center, color=".45", linestyle="--", linewidth=0.8,
               label=f"UBF_SIZE = {args.ubf_center}")
    best = minima(summary)
    ax.scatter([row["ubf_size"] for row in best], [row["collision_pct_mean"] for row in best],
               color=COLORS[1], marker="o", s=24, zorder=4, label="Menor média observada")
    point = best[0]
    right_side = point["ubf_size"] > (xs[0] + xs[-1]) / 2
    ax.annotate(
        f"UBF_SIZE = {point['ubf_size']}",
        xy=(point["ubf_size"], point["collision_pct_mean"]),
        xytext=(-10 if right_side else 10, 12), textcoords="offset points",
        ha="right" if right_side else "left", va="bottom", fontsize=9,
        color=COLORS[1], bbox=dict(facecolor="white", edgecolor="none", alpha=0.85, pad=2),
        zorder=5,
    )
    margin = max(0.1, (max(high) - min(low)) * 0.08)
    ax.set_ylim(max(0, min(low) - margin), min(100, max(high) + margin))
    if len(xs) == 1:
        ax.set_xlim(xs[0] - 0.5, xs[0] + 0.5)
    ax.set(title=f"{args.title}\nSOURCES = {args.sources}",
           xlabel=args.xlabel or "UBF_SIZE", ylabel=args.ylabel or "Colisões (%)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)
    ax.grid(axis="y", color=".88", linewidth=0.5)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=3)
    for axis in ("x", "y"):
        getattr(ax, "set_" + axis + "scale")(getattr(args, axis + "scale"))
        if getattr(args, axis + "lim"):
            getattr(ax, "set_" + axis + "lim")(getattr(args, axis + "lim"))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def cases_for(args):
    clients, attackers = population_counts(args.sources, args.attacker_percent)
    cases = []
    for rep in range(1, args.repetitions + 1):
        for size in args.ubf_size:
            cases.append(dict(id=f"{len(cases) + 1:04d}-r{rep}", repetition=rep,
                              hash_algorithm="halfsiphash", ubf_size=size, sources=args.sources,
                              clients=clients, attackers=attackers))
    return cases


def execute(args, cases):
    if args.dry_run:
        return
    directory = CACHE_ROOT / "halfsiphash_ubf_sweep" / "attempts" / uuid.uuid4().hex
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
        kind="halfsiphash_ubf_sweep", status="running", command=[sys.executable, *sys.argv],
        options={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        cases=cases, python=platform.python_version(), randomness="os",
    )
    save(directory / "experiment.json", manifest)
    try:
        rows = calculate(args)
        save(directory / "rows.json", rows)
        summary = summarize(rows)
        save(directory / "summary.json", summary)
        print_ranking(summary)
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
        ("UBF_SIZE range", f"{args.ubf_size[0]}..{args.ubf_size[-1]} (step 1)"),
        ("Sources", args.sources),
        ("Attacker percentage", args.attacker_percent),
        ("Hash algorithm", "halfsiphash"),
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
