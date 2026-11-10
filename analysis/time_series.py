#!/usr/bin/env python3
"""Plot one experiment as a SYN rate time series."""

import argparse
import csv
from contextlib import ExitStack, nullcontext
from collections import Counter, defaultdict
import hashlib
import itertools
import json
import math
import platform
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import time
from common.cache import argument_values, execute_cached
from common.collection import ROOT, command, run_one, save
from common.lab import fresh_lab
from common.metrics import COLORS, analyze_run, aggregate, write_csv
from common.progress import report
from common.presentation import SingleLineHelpFormatter, preflight


def parse(argv=None):
    p = argparse.ArgumentParser(
        description="Plot one experiment as a SYN rate time series. Identical arguments reuse the last valid collection; otherwise combinations share one isolated lab with a reset between runs.",
        usage=argparse.SUPPRESS,
        add_help=False,
        formatter_class=SingleLineHelpFormatter,
    )
    required = p.add_argument_group("Required")
    optional = p.add_argument_group("Optional")
    optional.add_argument("--hash-algorithm", choices=("fnv1a", "murmur3", "halfsiphash"),
                          default="halfsiphash", help="Hash algorithm (default: halfsiphash)")
    names = {
        "epoch_ms": "--epoch-time-ms",
        "threshold": "--syn-count-block-threshold",
        "ubf_size": "--ubf-size",
    }
    required.add_argument(
        "--epoch-time-ms", dest="epoch_ms", metavar="VALUE", help="2000"
    )
    required.add_argument(
        "--syn-count-block-threshold", dest="threshold", metavar="VALUE", help="3"
    )
    required.add_argument("--ubf-size", dest="ubf_size", metavar="VALUE", help="2048")
    required.add_argument("--clients", type=int, help="5")
    required.add_argument("--attackers", type=int, help="10")
    required.add_argument("--duration", type=float, metavar="SECONDS", help="25")
    required.add_argument("--client-interval", type=float, metavar="SECONDS", help="1")
    required.add_argument(
        "--attack-interval", type=float, metavar="SECONDS", help="0.1"
    )
    required.add_argument("--bin-seconds", type=float, metavar="SECONDS", help="0.5")
    required.add_argument("--before", type=float, metavar="SECONDS", help="2")
    required.add_argument("--after", type=float, metavar="SECONDS", help="2")
    optional.add_argument("--seed", type=int, default=20261028, help="20261028")
    optional.add_argument("--image", default="node:local", help="node:local")
    optional.add_argument(
        "--out", type=Path, metavar="FILE.png", help="results/figure.png (replaced if it exists)"
    )
    optional.add_argument("--dry-run", action="store_true", help="")
    optional.add_argument("-h", "--help", action="help", help="")
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        p.print_help()
        p.exit(0)
    args = p.parse_args(argv)
    mandatory = [
        *names,
        "clients",
        "attackers",
        "duration",
        "client_interval",
        "attack_interval",
    ]
    mandatory.extend(("bin_seconds", "before", "after"))
    flag_for = lambda field: names.get(field, "--" + field.replace("_", "-"))
    missing = [flag_for(field) for field in mandatory if getattr(args, field) is None]
    if missing:
        p.error(
            "Missing required parameters: "
            + ", ".join(missing)
            + ". Use --help for requirements."
        )
    for field, flag in names.items():
        try:
            numbers = sorted(set((int(v) for v in getattr(args, field).split(","))))
            maximum = {
                "epoch_ms": 18446744073709551615,
                "threshold": 4294967295,
                "ubf_size": 8192,
            }[field]
            if not numbers or any((v < 1 or v > maximum for v in numbers)):
                raise ValueError()
        except ValueError:
            p.error(f"{flag}: expected positive integers within detector capacity")
        if field != None and len(numbers) != 1:
            p.error(f"{flag} accepts only one value for this figure")
        setattr(args, field, numbers)
    for field in ("duration", "client_interval", "attack_interval", "bin_seconds"):
        value = getattr(args, field, None)
        if value is not None and (not math.isfinite(value) or value <= 0):
            p.error(f"{flag_for(field)} must be finite and positive")
    for field in ("before", "after"):
        value = getattr(args, field)
        if not math.isfinite(value) or value < 0:
            p.error(f"--{field} must be finite and nonnegative")
    if not 1 <= args.clients <= 9999 or not 1 <= args.attackers <= 9999:
        p.error("--clients and --attackers must each be in 1..9999")
    if args.out and args.out.suffix.lower() != ".png":
        p.error("--out must end in .png")
    if not args.image.strip():
        p.error("--image must name an existing local image")
    args._cache_arguments = argument_values(p, args)
    args.ready_timeout = 300
    args.title, args.xlabel, args.ylabel = ("Série temporal de SYNs", None, None)
    args.xlim, args.ylim = (None, None)
    args.figsize, args.dpi = ([7.2, 4.5], 200)
    args.xscale, args.yscale = ("linear", "linear")
    args.cmap, args.vmin, args.vmax = ("Blues", 0, 100)
    args.repetitions = 1
    return args


def cases_for(args):
    cases = []
    for rep in range(1, args.repetitions + 1):
        block = []
        for epoch, threshold, size in itertools.product(
            args.epoch_ms, args.threshold, args.ubf_size
        ):
            seed = args.seed + rep * 1000 + 20
            block.append(
                dict(
                    scenario=2,
                    epoch_ms=epoch,
                    threshold=threshold,
                    ubf_size=size,
                    clients=args.clients,
                    attackers=args.attackers,
                    client_interval=args.client_interval,
                    attack_interval=args.attack_interval,
                    mode="filter",
                    repetition=rep,
                    client_seed=seed,
                    attack_seed=seed + 1,
                )
            )
        random.Random(args.seed + rep).shuffle(block)
        cases.extend(block)
    for i, case in enumerate(cases, 1):
        case["id"] = f"{i:04d}-r{case['repetition']}"
    for case in cases:
        case["hash_algorithm"] = args.hash_algorithm
    return cases


def temporal_rates(directory, metadata, bin_seconds):
    """Compute SYN rates across the full before/during/after observation."""
    start, end = metadata["start_ns"], metadata["end_ns"]
    sources = {ip: kind for kind, ips in metadata["sources"].items() for ip in ips}
    bins = defaultdict(Counter)
    with (directory / "packets.csv").open() as stream:
        for row in csv.DictReader(stream):
            timestamp = int(row["timestamp_monotonic_ns"])
            if not start <= timestamp < end:
                continue
            if (
                row["ip_protocol"] != "6"
                or row["dst_ip"] != "203.0.113.2"
                or row["dst_port"] != "80"
                or not row["tcp_flags"]
                or int(row["tcp_flags"]) & 0x3F != 2
            ):
                continue
            source = sources.get(row["src_ip"])
            if source is not None:
                bins[int((timestamp - start) / 1e9 / bin_seconds)][
                    f"{source}_{row['action']}"
                ] += 1
    series = []
    for index in range(math.ceil((end - start) / 1e9 / bin_seconds)):
        width = min(bin_seconds, (end - start) / 1e9 - index * bin_seconds)
        series.append(
            dict(
                second=index * bin_seconds,
                **{
                    key: bins[index][key] / width
                    for key in (
                        "client_PASS",
                        "client_DROP",
                        "attack_PASS",
                        "attack_DROP",
                    )
                },
            )
        )
    return series


def render(args, rows, temporal, metadata, output):
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["DejaVu Serif"],
            "font.size": 10,
            "axes.titlesize": 11,
            "axes.linewidth": 0.7,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "legend.fontsize": 8,
            "legend.frameon": False,
        }
    )
    fig = Figure(figsize=args.figsize, layout="constrained")
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    xlabel = "Tempo desde o início da execução (s)"
    ylabel = "SYN/s"
    keys = [
        ("client_PASS", "Legítimo PASS"),
        ("client_DROP", "Legítimo DROP"),
        ("attack_PASS", "Atacante PASS"),
        ("attack_DROP", "Atacante DROP"),
    ]
    valid = rows[0]["quality"] == "ok"
    for i, (key, label) in enumerate(keys):
        if valid:
            ax.step(
                [r["second"] for r in temporal]
                + [(metadata["end_ns"] - metadata["start_ns"]) / 1000000000.0],
                [r[key] for r in temporal] + [temporal[-1][key]],
                where="post",
                color=COLORS[i],
                label=label,
                linestyle=["-", "--", "-.", ":"][i],
                linewidth=1.2,
            )
    if not valid:
        ax.text(
            0.5,
            0.5,
            "N/A — coleta inválida; consulte runs.csv",
            transform=ax.transAxes,
            ha="center",
        )
    for phase, label in [
        ("attack_launch_ns", "Início do ataque"),
        ("attack_stopped_ns", "Fim do ataque"),
    ]:
        if phase in metadata["phases"]:
            ax.axvline(
                (metadata["phases"][phase] - metadata["start_ns"]) / 1000000000.0,
                color=".4",
                linestyle=":",
                linewidth=0.8,
                label=label,
            )
    xlabel = "Tempo desde o início da execução (s)"
    ylabel = f"SYN/s (intervalos de {args.bin_seconds:g} s)"
    for axis in ("x", "y"):
        scale = getattr(args, axis + "scale")
        if scale == "log":
            for line in ax.lines:
                values = line.get_xdata() if axis == "x" else line.get_ydata()
                if any((math.isfinite(float(v)) and v <= 0 for v in values)):
                    raise ValueError(
                        f"Log axis {axis} contains zero or negative values; use --{axis}scale linear. Collected data are preserved."
                    )
        getattr(ax, "set_" + axis + "scale")(scale)
        if getattr(args, axis + "lim"):
            getattr(ax, "set_" + axis + "lim")(getattr(args, axis + "lim"))
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color=".88", linewidth=0.5)
    handles, labels = ax.get_legend_handles_labels()
    if handles:
        ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=2)
    ax.set(title=args.title, xlabel=args.xlabel or xlabel, ylabel=args.ylabel or ylabel)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def execute(args, cases):
    execute_cached("time_series", args, cases, collect, render, temporal_rates)


def collect(args, cases, directory, *, kind="time_series", runner=run_one,
            prepare=None, renderer=render, isolated_runs=False):
    started = time.monotonic()
    report("Preflight: checking output, dependencies, Docker, and image availability")
    preflight(args.out, args.cmap)
    for executable in ("docker", "containerlab"):
        if not shutil.which(executable):
            raise RuntimeError(f"Missing dependency: {executable}")
    command("docker", "info", "--format", "{{.ServerVersion}}")
    try:
        image = command("docker", "image", "inspect", "-f", "{{.Id}}", args.image)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"Local Docker image {args.image!r} is unavailable. Build node:local manually with make build from the repository root, or select an existing image with --image. No automatic build was attempted."
        ) from error
    directory.mkdir(parents=True, exist_ok=False)
    report(f"Data directory: {directory}")
    report(
        f"PNG destination: {(args.out.resolve() if args.out else directory / 'figure.png')}"
    )
    manifest = dict(
        kind=kind,
        isolated_runs=isolated_runs,
        status="running",
        command=[sys.executable, *sys.argv],
        options={
            k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
        },
        cases=cases,
        python=platform.python_version(),
        kernel=platform.release(),
        git_revision=command("git", "rev-parse", "HEAD"),
        source_sha256={
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in (
                "analysis",
                "scripts",
                "syn-flood-detect",
                "syn-flood-detect-common",
                "syn-flood-detect-ebpf",
            )
            for p in (ROOT / folder).rglob("*")
            if p.suffix in (".py", ".rs")
        },
        topology_sha256=hashlib.sha256(
            (ROOT / "topo.clab.yml").read_bytes()
        ).hexdigest(),
    )
    import matplotlib
    import numpy

    manifest.update(matplotlib=matplotlib.__version__, numpy=numpy.__version__)
    save(directory / "experiment.json", manifest)
    rows, origins, temporal, metadata = ([], [], [], {})
    runs = []

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"Signal {signum}")

    previous = {
        sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        report(f"Using existing Docker image: {args.image}; pinned ID: {image}")
        manifest["image_id"] = image
        save(directory / "experiment.json", manifest)
        with ExitStack() as labs:
            if not isolated_runs:
                shared = labs.enter_context(fresh_lab(directory / "lab", image, args.ready_timeout))
            for i, case in enumerate(cases, 1):
                manifest["stage"] = f"Run {i}/{len(cases)}: {case['id']}"
                save(directory / "experiment.json", manifest)
                report(
                    f"Seeds: client={case['client_seed']}, attack={case['attack_seed']}; repetition={case['repetition']}"
                )
                print(
                    f"[{i}/{len(cases)}] EPOCH_TIME_MS={case['epoch_ms']} SYN_COUNT_BLOCK_THRESHOLD={case['threshold']} UBF_SIZE={case['ubf_size']}: {'isolated lab' if isolated_runs else 'shared lab'}",
                    flush=True,
                )
                run_dir = directory / case["id"]
                observation = dict(before=args.before, after=args.after)
                lab = (fresh_lab(run_dir / "lab", image, args.ready_timeout)
                       if isolated_runs else nullcontext(shared))
                with lab as (prefix, packet_dir):
                    runner(
                        case,
                        directory,
                        args.duration,
                        args.ready_timeout,
                        prefix,
                        packet_dir,
                        **observation,
                    )
                    report(f"Analyzing collection: {run_dir}")
                    row, origin, metadata = analyze_run(run_dir)
                    runs.append((run_dir, metadata))
                    if prepare is None:
                        temporal = temporal_rates(run_dir, metadata, args.bin_seconds)
                    rows.append(row)
                    origins.extend(origin)
                    write_csv(directory / "runs.csv", rows)
                    write_csv(directory / "summary.csv", aggregate(rows))
                    write_csv(directory / "origins.csv", origins)
                    report(
                        f"Collection quality: {row['quality']}; events lost={row['events_lost']}; aborted={row['aborted']}"
                    )
                    if row["quality"] != "ok":
                        print(
                            f"Invalid collection: {case['id']}: {row['quality']}; point will be N/A.",
                            flush=True,
                        )
        if prepare is None:
            write_csv(directory / "timeseries.csv", temporal)
        else:
            temporal = prepare(args, rows, runs, directory)
        output = args.out.resolve() if args.out else directory / "figure.png"
        manifest["stage"] = "Rendering PNG"
        report(f"Rendering PNG: {output}")
        if prepare is None:
            renderer(args, rows, temporal, metadata, output)
        else:
            renderer(args, rows, temporal, output)
        valid = sum((row["quality"] == "ok" for row in rows))
        manifest.update(
            status="complete",
            figure=str(output),
            elapsed_s=time.monotonic() - started,
            valid_runs=valid,
            invalid_runs=len(rows) - valid,
        )
        report(
            f"Experiment complete: {valid} valid, {len(rows) - valid} invalid; elapsed: {manifest['elapsed_s']:.1f} s"
        )
        print(f"PNG: {output}\nLabs removed. Data: {directory}", flush=True)
    except BaseException as error:
        manifest.update(
            status="failed",
            error=str(error) or type(error).__name__,
            elapsed_s=time.monotonic() - started,
        )
        report(
            f"Failed during {manifest.get('stage', 'setup')}: {manifest['error']}; evidence: {directory}"
        )
        for state_path in sorted(directory.rglob("lab.json")):
            state = json.loads(state_path.read_text())
            report(
                f"Cleanup status: {state['name']}: {state['status']}; details: {state_path}"
            )
        raise
    finally:
        save(directory / "experiment.json", manifest)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv=None):
    args = parse(argv)
    cases = cases_for(args)
    print("Experiment configuration:", flush=True)
    for name, value in [
        ("EPOCH_TIME_MS (ms)", args.epoch_ms),
        ("SYN_COUNT_BLOCK_THRESHOLD", args.threshold),
        ("UBF_SIZE", args.ubf_size),
        ("Legitimate sources", args.clients),
        ("Attacker sources", args.attackers),
        ("Client interval (s)", args.client_interval),
        ("Attack interval (s)", args.attack_interval),
        ("Measurement duration (s)", args.duration),
        ("Repetitions", args.repetitions),
        ("Seed", args.seed),
        ("Docker image (no build)", args.image),
    ]:
        print(
            f"  {name}: {(value if value is not None else 'not applicable')}",
            flush=True,
        )
    print(f"  Time bin width (s): {args.bin_seconds}", flush=True)
    print(
        f"  Before attack (s): {args.before}; after attack (s): {args.after}",
        flush=True,
    )
    print(
        f"  Output: {args.out or 'automatic PNG under results/analysis/cache/ and native window'}",
        flush=True,
    )
    print(
        f"  Parameter combinations: {len(cases) // args.repetitions}; total runs: {len(cases)}",
        flush=True,
    )
    duration = len(cases) * (args.duration + (args.before + args.after))
    print(
        f"{len(cases)} combinations/repetitions share 1 lab if cache misses. Minimum observation time on a miss: {duration / 60:.1f} min, plus startup and cleanup.",
        flush=True,
    )
    if args.dry_run:
        print(json.dumps(cases, indent=2))
        return 0
    try:
        execute(args, cases)
    except KeyboardInterrupt:
        print(
            "Experiment interrupted; check lab/lab.json for cleanup status.",
            file=sys.stderr,
        )
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
