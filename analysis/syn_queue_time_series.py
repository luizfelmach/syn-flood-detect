#!/usr/bin/env python3
"""Compare server SYN_RECV occupancy and queue-full drop rates during a SYN ramp."""

import json
import sys

from common.cache import execute_cached
from common.collection import run_one
from common.metrics import COLORS, write_csv
from common.resource_series import cases_for as resource_cases, parse as resource_parse, smooth
from common.syn_queue import queue_series, sample_syn_queue
from time_series import collect as collect_experiment


def parse(argv=None):
    args = resource_parse("syn_queue", argv, description=(
        "Compare server port-80 SYN_RECV occupancy with filtering and in allow mode during the same attacker ramp. "
        "Each mode uses a fresh isolated lab, identical seeds and traffic. "
        "Sample IPv4 /proc/net/tcp and TCPReqQFullDrop through one persistent Docker exec at --bin-seconds intervals. "
        "Drop counters cover the server network namespace, not only port 80. "
        "Curves use a five-sample moving mean; raw snapshots and unsmoothed series are preserved in CSVs."
    ))
    args._cache_arguments.pop("resource_version")
    args._cache_arguments["syn_queue_version"] = 2
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
        temporal = queue_series(run_dir, view, args.bin_seconds)
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
    for panel in panels:
        temporal = panel["temporal"]
        label, color = ("Com filtro", COLORS[0]) if panel["mode"] == "filter" else ("Sem filtro", "#E69F00")
        end = max(end, temporal[-1]["second"])
        if panel["quality"] != "ok":
            ax.text(.5, .5 if panel["mode"] == "filter" else .4,
                    f"{label}: N/A — coleta inválida; consulte runs.csv", ha="center", transform=ax.transAxes)
            continue
        values = smooth([point["syn_recv"] for point in temporal], window=5)
        maximum = max(maximum, max(point["syn_recv"] for point in temporal))
        ax.plot([point["second"] for point in temporal], values, color=color, linewidth=1.4, label=label)
        drops = smooth([point["queue_drop_per_s"] for point in temporal],
                       [point["interval_s"] for point in temporal], window=5)
        drop_maximum = max(drop_maximum, max(drops))
        right.plot([point["second"] for point in temporal], drops, color=color, linestyle=":",
                   linewidth=1.2, label="Descartes " + label.lower())
    ax.set(title="Ocupação da fila de conexões incompletas no servidor",
           xlabel="Tempo (s)", ylabel="Conexões em SYN_RECV", xlim=(0, end), ylim=(0, max(1, maximum * 1.1)))
    if maximum > 0:
        ax.axhline(maximum, color=".4", linestyle="--", linewidth=.9, zorder=0)
        ax.text(.98, maximum * 1.015, f"Máximo observado: {maximum:g} conexões",
                transform=ax.get_yaxis_transform(), ha="right", va="bottom", fontsize=9,
                color=".3", bbox=dict(facecolor="white", edgecolor="none", alpha=.85, pad=1.5))
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
    right.set(ylabel="Descartes por fila cheia (SYN/s)", ylim=(0, max(1, drop_maximum * 1.1)))
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
        with sample_syn_queue(prefix, run_dir, args.bin_seconds):
            run_one(case, output, duration * len(args.attackers), timeout, prefix, packet_dir, **observation)

    collect_experiment(args, cases, directory, kind="syn_queue_time_series", runner=runner,
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
        execute_cached("syn_queue_time_series", args, cases, collect, render, prepare=prepare,
                       extra_files=("syn_queue.csv",), isolated_runs=True)
    except KeyboardInterrupt:
        print("Experiment interrupted; inspect each run's lab/lab.json for cleanup status.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
