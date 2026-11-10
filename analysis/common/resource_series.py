"""Memory and CPU time series during one continuous attacker ramp."""

import argparse
import json
import math
from pathlib import Path
import sys

from .cache import argument_values, execute_cached
from .collection import run_one
from .metrics import COLORS, write_csv
from .presentation import SingleLineHelpFormatter
from .resources import resource_bins, sample_resources
from time_series import collect as collect_experiment, temporal_rates


def parse(metric, argv=None, *, mode="filter", description=None, configure_parser=None):
    parser = argparse.ArgumentParser(
        description=description or (f"Plot server/firewall {metric} and observed attacker SYN/s during one attacker ramp. "
                     f"PACKET_HANDLING_MODE={mode}. "
                     "Memory and CPU reuse the same valid collection for identical arguments. "
                     "Requires local Docker and readable host cgroup v2 counters. "
                     "CPU is a percentage of total available CPU capacity, not isolated XDP CPU. "
                     "Memory is total cgroup usage including page cache. "
                     "Curves use a centered five-bin moving mean; CSVs retain unsmoothed data."),
        usage=argparse.SUPPRESS, add_help=False, formatter_class=SingleLineHelpFormatter,
    )
    required = parser.add_argument_group("Required")
    optional = parser.add_argument_group("Optional")
    required.add_argument("--epoch-time-ms", dest="epoch_ms", type=int, metavar="VALUE", help="500")
    required.add_argument("--syn-count-block-threshold", dest="threshold", type=int, metavar="VALUE", help="3")
    required.add_argument("--ubf-size", type=int, metavar="VALUE", help="2048")
    required.add_argument("--clients", type=int, help="2")
    required.add_argument("--attackers", metavar="VALUES", help="30,20,10,0,10,20,30 (active sources at each step, in order)")
    for flag, example in (("duration", "10"), ("client-interval", "0.5"),
                          ("attack-interval", "0.1"), ("bin-seconds", "0.5"),
                          ("before", "2"), ("after", "2")):
        required.add_argument("--" + flag, type=float, metavar="SECONDS",
                              help=example + (" per ramp step" if flag == "duration" else ""))
    optional.add_argument("--hash-algorithm", choices=("fnv1a", "murmur3", "halfsiphash"),
                          default="halfsiphash", help="halfsiphash")
    optional.add_argument("--seed", type=int, default=20261028, help="20261028")
    optional.add_argument("--image", default="node:local", help="node:local (no automatic build)")
    optional.add_argument("--out", type=Path, metavar="FILE.png", help="results/figure.png (replaced if it exists)")
    optional.add_argument("--dry-run", action="store_true", help="")
    optional.add_argument("-h", "--help", action="help", help="")
    if configure_parser is not None:
        configure_parser(optional)
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        parser.print_help()
        parser.exit(0)
    args = parser.parse_args(argv)
    missing = [action.option_strings[0] for action in required._group_actions
               if getattr(args, action.dest) is None]
    if missing:
        parser.error("Missing required parameters: " + ", ".join(missing) + ". Use --help for requirements.")
    for name, maximum, flag in (("epoch_ms", 2**64 - 1, "epoch-time-ms"),
                                ("threshold", 2**32 - 1, "syn-count-block-threshold"),
                                ("ubf_size", 8192, "ubf-size"), ("clients", 9999, "clients")):
        if not 1 <= getattr(args, name) <= maximum:
            parser.error(f"--{flag} must be in 1..{maximum}")
    try:
        args.attackers = [int(value) for value in args.attackers.split(",")]
        if (not args.attackers or any(not 0 <= value <= 9999 for value in args.attackers)
                or not any(args.attackers)):
            raise ValueError()
    except ValueError:
        parser.error("--attackers must be comma-separated integers in 0..9999, including at least one positive count")
    for name in ("duration", "client_interval", "attack_interval", "bin_seconds", "before", "after"):
        value = getattr(args, name)
        if not math.isfinite(value) or value < 0 or (value == 0 and name not in ("before", "after")):
            parser.error(f"--{name.replace('_', '-')} must be finite and "
                         + ("nonnegative" if name in ("before", "after") else "positive"))
    if args.out and args.out.suffix.lower() != ".png":
        parser.error("--out must end in .png")
    if not args.image.strip():
        parser.error("--image must name an existing local image")
    args._cache_arguments = argument_values(parser, args)
    args._cache_arguments["resource_version"] = 4
    args.packet_handling_mode = mode
    if mode != "filter":
        args._cache_arguments["packet_handling_mode"] = mode
    args.metric = metric
    args.ready_timeout, args.repetitions = 300, 1
    args.cmap, args.dpi = "Blues", 200
    return args


def cases_for(args):
    return [dict(
        scenario=2, epoch_ms=args.epoch_ms, threshold=args.threshold,
        ubf_size=args.ubf_size, hash_algorithm=args.hash_algorithm,
        clients=args.clients, attackers=max(args.attackers), client_interval=args.client_interval,
        attack_interval=args.attack_interval, mode=args.packet_handling_mode, repetition=1,
        client_seed=args.seed + 1020, attack_seed=args.seed + 1021,
        attack_steps=args.attackers, step_duration_s=args.duration, id="0001-r1",
    )]


def cache_kind(args):
    return "resource_time_series" + ("_allow" if args.packet_handling_mode == "allow" else "")


def prepare(args, rows, runs, directory):
    panels, combined = [], []
    for row, (run_dir, metadata) in zip(rows, runs):
        metadata = dict(metadata)
        if args.before == 0:
            metadata["start_ns"] = metadata["phases"]["measure_start_ns"]
        if args.after == 0:
            metadata["end_ns"] = metadata["phases"]["measure_end_ns"]
        rates = temporal_rates(run_dir, metadata, args.bin_seconds)
        temporal = resource_bins(run_dir, metadata, rates, args.bin_seconds)
        for point in temporal:
            timestamp = metadata["start_ns"] + point["second"] * 1e9
            point["attackers"] = next((step["attackers"] for step in reversed(metadata["attack_ramp"])
                                       if step["timestamp_monotonic_ns"] <= timestamp), 0)
            if timestamp >= metadata["phases"]["attack_stopped_ns"]:
                point["attackers"] = 0
        write_csv(run_dir / "resource_timeseries.csv", temporal)
        combined.extend(dict(point, quality=row["quality"]) for point in temporal)
        panels.append(dict(metadata=metadata, quality=row["quality"], temporal=temporal))
    write_csv(directory / "timeseries.csv", combined)
    return panels


def smooth(values, weights=None, window=3):
    """Centered moving mean, weighted by duration when the last bin is partial."""
    weights = [1] * len(values) if weights is None else weights
    radius = window // 2
    result = []
    for index in range(len(values)):
        indices = range(max(0, index - radius), min(len(values), index + radius + 1))
        result.append(sum(values[j] * weights[j] for j in indices) / sum(weights[j] for j in indices))
    return result


def render(args, rows, panels, output):
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure
    from matplotlib.lines import Line2D
    from matplotlib.ticker import MaxNLocator

    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 10,
        "axes.titlesize": 11, "axes.linewidth": 0.7, "xtick.direction": "in",
        "ytick.direction": "in", "legend.fontsize": 10, "legend.frameon": False,
    })
    panel = panels[0]
    metadata, temporal = panel["metadata"], panel["temporal"]
    fig = Figure(figsize=(8, 4.5), layout="constrained")
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    right = ax.twinx()
    key = "memory_mib" if args.metric == "memory" else "cpu_pct"
    ylabel = "Memória total (MiB)" if args.metric == "memory" else "CPU (%)"
    title = "Memória do servidor e do firewall" if args.metric == "memory" else "CPU do servidor e do firewall"
    if args.packet_handling_mode == "allow":
        title += " (allow)"
    end = (metadata["end_ns"] - metadata["start_ns"]) / 1e9
    maximum, syn_maximum = 0, 0
    if panel["quality"] == "ok":
        centers = [(point["second"] + (temporal[index + 1]["second"] if index + 1 < len(temporal) else end)) / 2
                   for index, point in enumerate(temporal)]
        widths = [(temporal[index + 1]["second"] if index + 1 < len(temporal) else end) - point["second"]
                  for index, point in enumerate(temporal)]
        seconds = [0, *centers, end]
        for node, color, style in (("server", COLORS[0], "-"), ("firewall", "#E69F00", "-")):
            values = smooth([point[node + "_" + key] for point in temporal], widths, window=5)
            maximum = max(maximum, max(values))
            ax.plot(seconds, values[:1] + values + values[-1:], color=color,
                    linestyle=style, linewidth=1.4)
        syns = smooth([point["attack_syn_per_s"] for point in temporal], widths, window=5)
        syn_maximum = max(syns)
        right.plot(seconds, syns[:1] + syns + syns[-1:], color=".4",
                   linestyle="-.", linewidth=1, alpha=.8)
    else:
        ax.text(.5, .5, "N/A — coleta inválida; consulte runs.csv", ha="center", transform=ax.transAxes)
    ax.set(title=title, xlabel="Tempo (s)", ylabel=ylabel,
           ylim=(0, max(maximum * 1.12, 1 if args.metric == "memory" else .01)), xlim=(0, end))
    right.set(ylabel="SYN/s dos atacantes", ylim=(0, max(syn_maximum * 1.12, 1)))
    right.tick_params(axis="y", colors=".4")
    right.yaxis.label.set_color(".4")
    ax.yaxis.set_major_locator(MaxNLocator(nbins=5))
    right.yaxis.set_major_locator(MaxNLocator(nbins=5))
    ax.grid(axis="y", color=".88", linewidth=.5)
    fig.legend(handles=[
        Line2D([], [], color=COLORS[0], linestyle="-", label="Servidor"),
        Line2D([], [], color="#E69F00", linestyle="-", label="Firewall"),
        Line2D([], [], color=".4", linestyle="-.", label="SYN/s"),
    ], loc="outside lower center", ncol=3)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def collect(args, cases, directory):
    def runner(case, output, duration, timeout, prefix, packet_dir, **observation):
        run_dir = output / case["id"]
        run_dir.mkdir(exist_ok=True)
        with sample_resources(prefix, run_dir, args.bin_seconds):
            run_one(case, output, duration * len(args.attackers), timeout, prefix, packet_dir, **observation)

    collect_experiment(args, cases, directory, kind=cache_kind(args),
                       runner=runner, prepare=prepare, renderer=render)


def main(metric, argv=None, *, mode="filter"):
    args = parse(metric, argv, mode=mode)
    cases = cases_for(args)
    print("Experiment configuration:", flush=True)
    for name, value in vars(args).items():
        if not name.startswith("_"):
            print(f"  {name}: {value}", flush=True)
    print(f"  Total runs: {len(cases)}; one isolated lab on a cache miss; shared memory/CPU cache", flush=True)
    if args.dry_run:
        print(json.dumps(cases, indent=2))
        return 0
    try:
        execute_cached(cache_kind(args), args, cases, collect, render,
                       prepare=prepare, extra_files=("resources.csv",))
    except KeyboardInterrupt:
        print("Experiment interrupted; check lab/lab.json for cleanup status.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0
