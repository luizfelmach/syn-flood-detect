#!/usr/bin/env python3
"""Compare SYN backlog recovery with different server SYN-ACK retry limits."""

import argparse
import json
import sys

from common.cache import execute_cached
from common.collection import command, run_one, save
from common.metrics import COLORS, aggregate, write_csv
from common.resource_series import cases_for as resource_cases, parse as resource_parse, smooth
from common.syn_queue import queue_series, sample_syn_queue
from time_series import collect as collect_experiment


def retry_values(value):
    try:
        values = [int(part) for part in value.split(",")]
        if not values or len(set(values)) != len(values) or any(not 0 <= item <= 255 for item in values):
            raise ValueError()
        return values
    except ValueError:
        raise argparse.ArgumentTypeError("expected distinct comma-separated integers in 0..255") from None


def parse(argv=None):
    def configure(optional):
        optional.add_argument("--synack-retries", type=retry_values, default=[1, 3, 5],
                              metavar="VALUES", help="Server tcp_synack_retries values (default: 1,3,5)")
    args = resource_parse("syn_backlog_expiration", argv, mode="allow", configure_parser=configure,
                          description=(
        "Compare server IPv4 port-80 SYN_RECV occupancy for different tcp_synack_retries values. "
        "Use one fresh lab per value, identical attacker ramps and seeds, allow mode and SYN cookies disabled. "
        "Continue observing after attackers stop; legitimate clients remain active. "
        "Five-sample moving mean; raw snapshots and unsmoothed rates are retained. "
        "The curves measure occupancy, not individual expiration events or a guaranteed theoretical timeout."
    ))
    args._cache_arguments.pop("resource_version")
    args._cache_arguments["syn_backlog_expiration_version"] = 1
    return args


def cases_for(args):
    case = resource_cases(args)[0]
    return [dict(case, id=f"{index:04d}-r1", tcp_synack_retries=value)
            for index, value in enumerate(args.synack_retries, 1)]


def configure_server(prefix, directory, retries):
    server = prefix + "server"
    keys = ("net.ipv4.tcp_synack_retries", "net.ipv4.tcp_syncookies")
    command("docker", "exec", server, "sysctl", "-w", f"{keys[0]}={retries}", f"{keys[1]}=0")
    values = command("docker", "exec", server, "sysctl", "-n", *keys).splitlines()
    observed = dict(zip(keys, map(int, values)))
    save(directory / "server_config.json", observed)
    if observed != {keys[0]: retries, keys[1]: 0}:
        raise ValueError("Server SYN-ACK configuration did not match the requested values")


def prepare(args, rows, runs, directory):
    panels, combined, labeled_rows, summaries = [], [], [], []
    for row, (run_dir, metadata) in zip(rows, runs):
        retries = metadata["tcp_synack_retries"]
        observed = json.loads((run_dir / "server_config.json").read_text())
        if observed != {"net.ipv4.tcp_synack_retries": retries, "net.ipv4.tcp_syncookies": 0}:
            raise ValueError("Missing or incompatible server configuration evidence")
        labeled_rows.append(dict(row, tcp_synack_retries=retries))
        # The shared aggregate groups detector settings. Each retry value is a
        # separate experiment and must not be pooled with the other values.
        summaries.extend(dict(summary, tcp_synack_retries=retries) for summary in aggregate([row]))
        view = dict(metadata)
        if args.before == 0:
            view["start_ns"] = metadata["phases"]["measure_start_ns"]
        if args.after == 0:
            view["end_ns"] = metadata["phases"]["measure_end_ns"]
        temporal = [dict(point, tcp_synack_retries=retries)
                    for point in queue_series(run_dir, view, args.bin_seconds)]
        write_csv(run_dir / "timeseries.csv", temporal)
        combined.extend(dict(point, quality=row["quality"]) for point in temporal)
        panels.append(dict(retries=retries, quality=row["quality"], temporal=temporal))
    write_csv(directory / "timeseries.csv", combined)
    write_csv(directory / "runs.csv", labeled_rows)
    write_csv(directory / "summary.csv", summaries)
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
    maximum, end = 0, 0
    colors, styles = (COLORS[0], "#E69F00", COLORS[2], *COLORS[3:]), ("-", "--", "-.", ":")
    for index, panel in enumerate(panels):
        temporal = panel["temporal"]
        end = max(end, temporal[-1]["second"])
        label = f"tcp_synack_retries = {panel['retries']}"
        if panel["quality"] != "ok":
            ax.text(.5, .5 - index * .07, f"{label}: N/A — coleta inválida; consulte runs.csv",
                    ha="center", transform=ax.transAxes)
            continue
        maximum = max(maximum, max(point["syn_recv"] for point in temporal))
        ax.plot([point["second"] for point in temporal],
                smooth([point["syn_recv"] for point in temporal], window=5),
                color=colors[index % len(colors)], linestyle=styles[index % len(styles)],
                linewidth=1.4, label=label)
    ax.set(title="Expiração da fila de conexões incompletas no servidor (sem filtro)",
           xlabel="Tempo (s)", ylabel="Conexões em SYN_RECV", xlim=(0, end), ylim=(0, max(1, maximum * 1.1)))
    ax.yaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
    ax.grid(axis="y", color=".88", linewidth=.5)
    ax.spines[["top", "right"]].set_visible(False)
    if ax.lines:
        fig.legend(*ax.get_legend_handles_labels(), loc="outside lower center", ncol=3, fontsize=9)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def collect(args, cases, directory):
    def runner(case, output, duration, timeout, prefix, packet_dir, **observation):
        run_dir = output / case["id"]
        run_dir.mkdir(exist_ok=True)
        configure_server(prefix, run_dir, case["tcp_synack_retries"])
        with sample_syn_queue(prefix, run_dir, args.bin_seconds):
            run_one(case, output, duration * len(args.attackers), timeout, prefix, packet_dir, **observation)
    collect_experiment(args, cases, directory, kind="syn_backlog_expiration", runner=runner,
                       prepare=prepare, renderer=render, isolated_runs=True)


def main(argv=None):
    args = parse(argv)
    cases = cases_for(args)
    print("Experiment configuration:", flush=True)
    for name, value in vars(args).items():
        if not name.startswith("_"):
            print(f"  {name}: {value}", flush=True)
    if args.dry_run:
        print(json.dumps(cases, indent=2))
        return 0
    try:
        execute_cached("syn_backlog_expiration", args, cases, collect, render, prepare=prepare,
                       extra_files=("syn_queue.csv", "server_config.json"), isolated_runs=True)
    except KeyboardInterrupt:
        print("Experiment interrupted; inspect each run's lab/lab.json for cleanup status.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
