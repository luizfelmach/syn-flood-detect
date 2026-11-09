#!/usr/bin/env python3
"""Compare FNV-1a and HalfSipHash avalanche over the 80-bit service key."""

import argparse
import json
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
from hash_comparison import population_counts, source_generator, generate_sources, service_key


HASH_FUNCTIONS = {"fnv1a": fnv1a_32, "halfsiphash": halfsiphash_2_4_32}
LABELS = {"fnv1a": "FNV-1a", "halfsiphash": "HalfSipHash"}


def parse(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare FNV-1a and HalfSipHash avalanche before UBF reduction. Each execution draws fresh origins using operating-system randomness; no traffic or lab is required.",
        usage=argparse.SUPPRESS,
        add_help=False,
        formatter_class=SingleLineHelpFormatter,
    )
    required = parser.add_argument_group("Required")
    optional = parser.add_argument_group("Optional")
    required.add_argument("--sources", type=int, metavar="VALUE", help="2000")
    required.add_argument("--attacker-percent", type=int, metavar="VALUE", help="50")
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
    mandatory = ("sources", "attacker_percent")
    missing = ["--" + field.replace("_", "-") for field in mandatory if getattr(args, field) is None]
    if missing:
        parser.error("Missing required parameters: " + ", ".join(missing) + ". Use --help for requirements.")
    if args.sources < 1:
        parser.error("--sources must be positive")
    if not 0 <= args.attacker_percent <= 100:
        parser.error("--attacker-percent must be in 0..100")
    for kind, count in zip(("client", "attack"), population_counts(args.sources, args.attacker_percent)):
        capacity = len(set(source_generator(kind).PREFIXES)) * 65534
        if count > capacity:
            parser.error(f"{kind} population exceeds the available IPv4 addresses ({capacity})")
    if args.out and args.out.suffix.lower() != ".png":
        parser.error("--out must end in .png")
    args.title, args.xlabel, args.ylabel = ("Efeito avalanche das funções de hash", None, None)
    args.xlim, args.ylim = (None, None)
    args.figsize, args.dpi = ([10, 7], 200)
    args.xscale, args.yscale = ("linear", "linear")
    args.cmap, args.vmin, args.vmax = ("RdBu_r", 0, 100)
    return args


def flip_bit(key, bit):
    """Input bits follow byte order, MSB first inside each byte."""
    if len(key) != 10 or not 0 <= bit < 80:
        raise ValueError("Expected a ten-byte key and an input bit in 0..79")
    changed = bytearray(key)
    changed[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(changed)


def avalanche_counts(keys, functions=None):
    functions = HASH_FUNCTIONS if functions is None else functions
    matrices = {name: [[0] * 32 for _ in range(80)] for name in functions}
    for index, key in enumerate(keys, 1):
        originals = {name: function(key) for name, function in functions.items()}
        for input_bit in range(80):
            changed = flip_bit(key, input_bit)
            for name, function in functions.items():
                difference = (originals[name] ^ function(changed)) & 0xFFFFFFFF
                # Output bit 0 is the least significant bit.
                while difference:
                    bit = difference & -difference
                    matrices[name][input_bit][bit.bit_length() - 1] += 1
                    difference ^= bit
        if index % 100 == 0 or index == len(keys):
            report(f"Tuples analyzed: {index}/{len(keys)}")
    return matrices


def calculate(args):
    clients, attackers = population_counts(args.sources, args.attacker_percent)
    keys = [service_key(ip) for kind, count in (("client", clients), ("attack", attackers))
            for ip in generate_sources(kind, count)]
    counts = avalanche_counts(keys)
    return dict(
        sources=args.sources,
        input_bit_order="byte order, MSB to LSB within each byte",
        output_bit_order="LSB (0) to MSB (31)",
        fields=[dict(name="src_ip", start=0, end=31), dict(name="dst_ip", start=32, end=63),
                dict(name="dst_port", start=64, end=79)],
        keys_hex=[key.hex() for key in keys],
        algorithms={name: dict(counts=matrix,
                              percentages=[[100 * count / args.sources for count in row] for row in matrix])
                    for name, matrix in counts.items()},
    )


def render(args, data, output):
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.colors import TwoSlopeNorm

    plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"],
                         "font.size": 10, "axes.titlesize": 11, "axes.linewidth": 0.7,
                         "xtick.direction": "in", "ytick.direction": "in",
                         "legend.fontsize": 8, "legend.frameon": False})
    fig = Figure(figsize=args.figsize, layout="constrained")
    FigureCanvasAgg(fig)
    axes = fig.subplots(1, 2, sharex=True, sharey=True)
    norm = TwoSlopeNorm(vmin=0, vcenter=50, vmax=100)
    for ax, name in zip(axes, HASH_FUNCTIONS):
        matrix = data["algorithms"][name]["percentages"]
        chart = ax.imshow(matrix, origin="upper", aspect="auto", interpolation="nearest",
                          cmap=args.cmap, norm=norm)
        ax.set(title=LABELS[name], xlabel="Bit da saída (0 = LSB)")
        ax.set_xticks([0, 4, 8, 12, 16, 20, 24, 28, 31])
        ax.set_yticks([15.5, 47.5, 71.5],
                      labels=["IP de origem\nbits 0 a 31", "IP de destino\nbits 32 a 63", "Porta\nbits 64 a 79"])
        for boundary in (31.5, 63.5):
            ax.axhline(boundary, color=".25", linewidth=0.8)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("Bit da entrada (MSB primeiro em cada byte)")
    bar = fig.colorbar(chart, ax=list(axes), ticks=[0, 25, 50, 75, 100], fraction=0.04, pad=0.03)
    bar.set_label("Mudança do bit de saída (%)")
    fig.suptitle(f"{args.title}\nSOURCES = {args.sources}", fontsize=11)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=args.dpi, format="png")


def cases_for(args):
    return [dict(hash_algorithm=name, sources=args.sources, input_bits=80, output_bits=32)
            for name in HASH_FUNCTIONS]


def execute(args, cases):
    if args.dry_run:
        return
    directory = CACHE_ROOT / "hash_avalanche" / "attempts" / uuid.uuid4().hex
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
        kind="hash_avalanche", status="running", command=[sys.executable, *sys.argv],
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
        ("Sources", args.sources),
        ("Attacker percentage", args.attacker_percent),
        ("Hash algorithms", tuple(HASH_FUNCTIONS)),
        ("Randomness", "operating system (fresh origins on every execution)"),
    ]:
        print(f"  {name}: {value}", flush=True)
    print(f"  Output: {args.out or 'automatic PNG under results/analysis/cache/ and native window'}", flush=True)
    print(f"  Hash evaluations: {len(cases) * args.sources * 81}", flush=True)
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
