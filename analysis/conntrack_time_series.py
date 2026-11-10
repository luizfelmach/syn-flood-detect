#!/usr/bin/env python3
"""Compare firewall conntrack occupancy and drops during identical SYN ramps."""

import json
import sys

from common.cache import execute_cached
from common.collection import run_one
from common.conntrack import conntrack_series, sample_conntrack, temporary_conntrack_limit
from common.metrics import COLORS, write_csv
from common.resource_series import cases_for as resource_cases, parse as resource_parse, smooth
from time_series import collect as collect_experiment


def parse(argv=None):
    def configure_parser(optional):
        def capacity(value):
            number = int(value)
            if not 1 <= number <= 2**31 - 1:
                raise ValueError("capacity must be in 1..2147483647")
            return number

        optional.add_argument("--conntrack-max", type=capacity, metavar="ENTRIES",
                              help="Temporarily set the global host limit using a Docker helper with a bind mount of this sysctl, then restore it")

    args = resource_parse("conntrack", argv, description=(
        "Compare firewall conntrack table occupancy with filtering and in allow mode during identical attacker ramps. "
        "Each mode uses a fresh isolated lab, identical traffic and seeds. "
        "Read namespace-wide nf_conntrack_count, nf_conntrack_max and per-CPU /proc/net/stat/nf_conntrack. "
        "Drop includes conntrack allocation/confirmation/protocol failures, not only table-full events or XDP blocks. "
        "early_drop counts evicted entries and is preserved separately in CSV, never added to packet drops. "
        "Use five-sample moving means; raw snapshots and unsmoothed rates are preserved in CSVs."
    ), configure_parser=configure_parser)
    args._cache_arguments.pop("resource_version")
    args._cache_arguments["conntrack_version"] = 2
    return args


def cases_for(args):
    case = resource_cases(args)[0]
    return [dict(case, id=f"{index:04d}-r1", mode=mode)
            for index, mode in enumerate(("filter", "allow"), 1)]


def prepare(args, rows, runs, directory):
    panels, combined = [], []
    for row, (run_dir, metadata) in zip(rows, runs):
        view = dict(metadata)
        if args.before == 0:
            view["start_ns"] = metadata["phases"]["measure_start_ns"]
        if args.after == 0:
            view["end_ns"] = metadata["phases"]["measure_end_ns"]
        temporal = conntrack_series(run_dir, view, args.bin_seconds)
        if args.conntrack_max is not None:
            if any(point["conntrack_max"] != args.conntrack_max for point in temporal):
                raise ValueError("Measured conntrack capacity differs from --conntrack-max")
            limit = json.loads((run_dir / "conntrack_limit.json").read_text())
            if limit["requested"] != args.conntrack_max or not limit["restored"]:
                raise ValueError("Incomplete host conntrack limit restoration")
        write_csv(run_dir / "timeseries.csv", temporal)
        combined.extend(dict(point, quality=row["quality"]) for point in temporal)
        panels.append(dict(mode=metadata["mode"], quality=row["quality"], temporal=temporal))
    write_csv(directory / "timeseries.csv", combined)
    return panels


def render(args, rows, panels, output):
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure
    from matplotlib.ticker import MaxNLocator

    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 10,
        "axes.titlesize": 11, "axes.linewidth": .7, "xtick.direction": "in",
        "ytick.direction": "in", "legend.fontsize": 10, "legend.frameon": False,
    })
    fig = Figure(figsize=(8, 4.8), layout="constrained")
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    right = ax.twinx()
    maximum, drop_maximum, end = 0, 0, 0
    capacities = set()
    for panel in panels:
        temporal = panel["temporal"]
        label, color = ("Com filtro", COLORS[0]) if panel["mode"] == "filter" else ("Sem filtro", "#E69F00")
        end = max(end, temporal[-1]["second"])
        if panel["quality"] != "ok":
            ax.text(.5, .5 if panel["mode"] == "filter" else .4,
                    f"{label}: N/A — coleta inválida; consulte runs.csv", ha="center", transform=ax.transAxes)
            continue
        capacities.update(point["conntrack_max"] for point in temporal)
        values = smooth([point["conntrack_count"] for point in temporal], window=5)
        maximum = max(maximum, max(point["conntrack_count"] for point in temporal))
        seconds = [point["second"] for point in temporal]
        ax.plot(seconds, values, color=color, linewidth=1.4, label=label)
        drops = smooth([point["drop_per_s"] for point in temporal],
                       [point["interval_s"] for point in temporal], window=5)
        drop_maximum = max(drop_maximum, max(drops))
        right.plot(seconds, drops, color=color, linestyle=":", linewidth=1.2,
                   label="Descartes " + label.lower())
    if len(capacities) > 1:
        raise ValueError("Cannot compare runs with different conntrack capacities")
    capacity = next(iter(capacities), 0)
    # Keep small measured occupancies readable when the configured limit is far
    # above them. The exact capacity remains explicit even when outside the view.
    show_capacity = capacity > 0 and capacity <= max(1, maximum) * 2
    ceiling = max(maximum, capacity if show_capacity else 0)
    ax.set(title="Ocupação da tabela de conexões no firewall",
           xlabel="Tempo (s)", ylabel="Entradas no conntrack", xlim=(0, end), ylim=(0, max(1, ceiling * 1.12)))
    if capacity:
        caption = f"Limite configurado: {capacity:,} entradas".replace(",", ".")
        if show_capacity:
            ax.axhline(capacity, color=".4", linestyle="--", linewidth=.9, zorder=0)
            ax.text(.98, capacity * 1.015, caption, transform=ax.get_yaxis_transform(),
                    ha="right", va="bottom", fontsize=9, color=".3")
        else:
            ax.text(.98, .97, caption + " (fora da escala)", transform=ax.transAxes,
                    ha="right", va="top", fontsize=9, color=".3")
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    right.set(ylabel="Descartes do conntrack (pacotes/s)", ylim=(0, max(1, drop_maximum * 1.1)))
    right.yaxis.set_major_locator(MaxNLocator(nbins=6))
    right.spines["top"].set_visible(False)
    ax.grid(axis="y", color=".88", linewidth=.5)
    ax.spines["top"].set_visible(False)
    if ax.lines:
        handles, labels = ax.get_legend_handles_labels()
        extra_handles, extra_labels = right.get_legend_handles_labels()
        fig.legend(handles + extra_handles, labels + extra_labels, loc="outside lower center", ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def collect(args, cases, directory):
    def runner(case, output, duration, timeout, prefix, packet_dir, **observation):
        run_dir = output / case["id"]
        run_dir.mkdir(exist_ok=True)
        with temporary_conntrack_limit(args.conntrack_max, run_dir, args.image):
            with sample_conntrack(prefix, run_dir, args.bin_seconds):
                run_one(case, output, duration * len(args.attackers), timeout, prefix, packet_dir, **observation)

    collect_experiment(args, cases, directory, kind="conntrack_time_series", runner=runner,
                       prepare=prepare, renderer=render, isolated_runs=True)


def main(argv=None):
    args = parse(argv)
    cases = cases_for(args)
    print("Experiment configuration:", flush=True)
    for name, value in vars(args).items():
        if not name.startswith("_"):
            print(f"  {name}: {value}", flush=True)
    print("  Modes: filter / allow; two fresh labs; identical traffic and seeds", flush=True)
    if args.dry_run:
        print(json.dumps(cases, indent=2))
        return 0
    try:
        execute_cached("conntrack_time_series", args, cases, collect, render, prepare=prepare,
                       extra_files=("conntrack.csv",) + (("conntrack_limit.json",) if args.conntrack_max is not None else ()),
                       isolated_runs=True)
    except KeyboardInterrupt:
        print("Experiment interrupted; inspect each run's lab/lab.json for cleanup status.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
