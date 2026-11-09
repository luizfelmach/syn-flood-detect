#!/usr/bin/env python3
"""Compare UBF collisions while enumerating selected destination-port bits."""

import argparse
import json
from ipaddress import IPv4Address
import platform
import sys
import time
from pathlib import Path
import uuid

from common.cache import CACHE_ROOT
from common.collection import save
from common.hashing import fnv1a_32, halfsiphash_2_4_32
from common.progress import report
from common.presentation import SingleLineHelpFormatter, preflight, show_png
from common.metrics import COLORS
from hash_comparison import collision_pct


HASH_FUNCTIONS = {"fnv1a": fnv1a_32, "halfsiphash": halfsiphash_2_4_32}
LABELS = {"fnv1a": "FNV-1a", "halfsiphash": "HalfSipHash"}


def parse(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare FNV-1a and HalfSipHash UBF collisions on deterministic port-bit combinations with fixed IPv4 addresses; no traffic or lab is required.",
        usage=argparse.SUPPRESS,
        add_help=False,
        formatter_class=SingleLineHelpFormatter,
    )
    required = parser.add_argument_group("Required")
    optional = parser.add_argument_group("Optional")
    required.add_argument("--ubf-size", type=int, metavar="VALUE", help="1024")
    required.add_argument("--keys", metavar="VALUES", help="16,32,64,96,128,160,192,224,256")
    required.add_argument("--src-ip", metavar="IPv4", help="104.16.1.1")
    required.add_argument("--dst-ip", metavar="IPv4", help="203.0.113.2")
    required.add_argument("--port-base", type=int, metavar="VALUE", help="80")
    required.add_argument("--port-bits", metavar="BITS", help="4,5,6,7,12,13,14,15 (bit 0 = LSB)")
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
    mandatory = ("ubf_size", "keys", "src_ip", "dst_ip", "port_base", "port_bits")
    missing = ["--" + field.replace("_", "-") for field in mandatory if getattr(args, field) is None]
    if missing:
        parser.error("Missing required parameters: " + ", ".join(missing) + ". Use --help for requirements.")
    if not 1 <= args.ubf_size <= 8192:
        parser.error("--ubf-size must be in 1..8192")
    if not 0 <= args.port_base <= 65535:
        parser.error("--port-base must be in 0..65535")
    for name in ("src_ip", "dst_ip"):
        try:
            setattr(args, name, str(IPv4Address(getattr(args, name))))
        except ValueError:
            parser.error("--" + name.replace("_", "-") + " must be a valid IPv4 address")
    for name in ("port_bits",):
        try:
            bits = [int(value) for value in getattr(args, name).split(",")]
            if len(bits) != len(set(bits)) or any(bit < 0 or bit > 15 for bit in bits):
                raise ValueError
            setattr(args, name, sorted(bits))
        except ValueError:
            parser.error("--" + name.replace("_", "-") + ": expected distinct bit positions in 0..15")
    try:
        args.keys = sorted(set(int(value) for value in args.keys.split(",")))
        capacity = 2 ** len(args.port_bits)
        if not args.keys or min(args.keys) < 1 or max(args.keys) > capacity:
            raise ValueError
    except ValueError:
        parser.error("--keys: expected positive integers within the port-bit group's capacity")
    if args.out and args.out.suffix.lower() != ".png":
        parser.error("--out must end in .png")
    args.title, args.xlabel, args.ylabel = ("Colisões ao variar bits da porta", None, None)
    args.xlim, args.ylim = (None, (0, 100))
    args.figsize, args.dpi = ([7.2, 4.5], 200)
    args.xscale, args.yscale = ("linear", "linear")
    args.cmap, args.vmin, args.vmax = ("Blues", 0, 100)
    return args


def ports_for(base, bits):
    """Enumerate bit combinations; preserve all unselected bits, then sort ports."""
    mask = sum(1 << bit for bit in bits)
    fixed = base & ~mask
    return sorted(fixed | sum(((value >> index) & 1) << bit for index, bit in enumerate(bits))
                  for value in range(1 << len(bits)))


def keys_for(args, bits):
    prefix = IPv4Address(args.src_ip).packed + IPv4Address(args.dst_ip).packed
    return [prefix + port.to_bytes(2, "big")
            for port in ports_for(args.port_base, bits)[:max(args.keys)]]


def calculate(args):
    rows = []
    keys = keys_for(args, args.port_bits)
    for name, function in HASH_FUNCTIONS.items():
        occupied = set()
        previous = 0
        for total in args.keys:
            occupied.update(function(key) % args.ubf_size for key in keys[previous:total])
            rows.append(dict(hash_algorithm=name, keys=total,
                             ubf_size=args.ubf_size, port_bits=args.port_bits,
                             occupied_indices=len(occupied), collisions=total - len(occupied),
                             collision_pct=collision_pct(total, len(occupied))))
            previous = total
        report(f"Calculated {LABELS[name]}")
    return rows


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
    for (name, function), color in zip(HASH_FUNCTIONS.items(), COLORS):
        group = [row for row in rows if row["hash_algorithm"] == name]
        ax.plot([row["keys"] for row in group], [row["collision_pct"] for row in group],
                color=color, marker="o", markerfacecolor="white", markersize=4,
                linewidth=1.2, label=LABELS[name])
    ax.set(title=f"{args.title}\nUBF_SIZE = {args.ubf_size}",
           xlabel=args.xlabel or "Quantidade de chaves inseridas",
           ylabel=args.ylabel or "Colisões (%)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_axisbelow(True)
    ax.grid(axis="y", color=".88", linewidth=0.5)
    for axis in ("x", "y"):
        getattr(ax, "set_" + axis + "scale")(getattr(args, axis + "scale"))
        if getattr(args, axis + "lim"):
            getattr(ax, "set_" + axis + "lim")(getattr(args, axis + "lim"))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def cases_for(args):
    return [dict(hash_algorithm=name, keys=total, ubf_size=args.ubf_size,
                 src_ip=args.src_ip, dst_ip=args.dst_ip, port_base=args.port_base, port_bits=args.port_bits)
            for name in HASH_FUNCTIONS for total in args.keys]


def execute(args, cases):
    if args.dry_run:
        return
    directory = CACHE_ROOT / "hash_port_bits" / "attempts" / uuid.uuid4().hex
    report("Enumerating deterministic port combinations; no traffic or lab required")
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
        kind="hash_port_bits", status="running", command=[sys.executable, *sys.argv],
        options={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        cases=cases, python=platform.python_version(), input_generation="deterministic port-bit enumeration",
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
        ("UBF_SIZE", args.ubf_size), ("Keys", args.keys),
        ("Source IPv4", args.src_ip), ("Destination IPv4", args.dst_ip),
        ("Base port", args.port_base), ("Selected bits", args.port_bits),
        ("Hash algorithms", tuple(HASH_FUNCTIONS)),
    ]:
        print(f"  {name}: {value}", flush=True)
    print(f"  Output: {args.out or 'automatic PNG under results/analysis/cache/ and native window'}", flush=True)
    print(f"  Parameter combinations: {len(cases)}", flush=True)
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
