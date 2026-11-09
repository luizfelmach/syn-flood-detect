"""Reuse the last complete collection for an analysis with identical CLI arguments."""

import csv
import fcntl
import hashlib
import json
from pathlib import Path
import uuid

from .collection import ROOT, save
from .metrics import aggregate, analyze_run, write_csv
from .presentation import preflight, show_png
from .progress import report

CACHE_ROOT = ROOT / "results" / "analysis" / "cache"
CACHE_VERSION = 3


def argument_values(parser, args):
    """Capture parsed options independently of the checkout and PNG destination."""
    values = {}
    for action in parser._actions:
        if action.dest in ("dry_run", "out") or not hasattr(args, action.dest):
            continue
        value = getattr(args, action.dest)
        values[action.dest] = str(value.resolve()) if isinstance(value, Path) else value
    return values


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect_collection(directory, cases):
    """Require complete measurements, successful lab cleanup and current quality checks."""
    manifest = json.loads((directory / "experiment.json").read_text())
    if manifest["status"] != "complete" or manifest["cases"] != cases:
        raise ValueError("incomplete or incompatible experiment")
    lab = json.loads((directory / "lab" / "lab.json").read_text())
    if lab["status"] != "destroyed":
        raise ValueError("lab cleanup incomplete")
    rows, origins, runs = [], [], []
    for case in cases:
        run_dir = directory / case["id"]
        row, origin, metadata = analyze_run(run_dir)
        if row["quality"] != "ok" or any(metadata[k] != v for k, v in case.items()):
            raise ValueError("invalid or incompatible run")
        rows.append(row)
        origins.extend(origin)
        runs.append((run_dir, metadata))
    return rows, origins, runs


def collection_hashes(directory, cases):
    paths = [Path("experiment.json"), Path("lab/lab.json")]
    for case in cases:
        paths.extend(Path(case["id"]) / name for name in (
            "run.json", "packets.csv", "stats.csv"
        ))
    return {str(path): digest(directory / path) for path in paths}


def render_cached(args, directory, data, render, temporal_rates, *, with_origins=False, prepare=None):
    preflight(args.out, args.cmap)
    rows, origins, runs = data
    write_csv(directory / "runs.csv", rows)
    write_csv(directory / "summary.csv", aggregate(rows))
    write_csv(directory / "origins.csv", origins)
    output = args.out.resolve() if args.out else directory / "figure.png"
    report(f"Rendering cached collection: {output}")
    if prepare is not None:
        derived = prepare(args, rows, runs, directory)
        render(args, rows, derived, output)
    elif with_origins:
        render(args, rows, origins, output)
    elif temporal_rates is None:
        render(args, rows, output)
    else:
        run_dir, metadata = runs[-1]
        temporal = temporal_rates(run_dir, metadata, args.bin_seconds)
        write_csv(directory / "timeseries.csv", temporal)
        render(args, rows, temporal, metadata, output)
    return output


def execute_cached(kind, args, cases, collect, render, temporal_rates=None, *, with_origins=False, prepare=None):
    if args.dry_run:
        return
    root = CACHE_ROOT / kind
    root.mkdir(parents=True, exist_ok=True)
    # Keep the lock outside attempt directories so publication never replaces it.
    with (root / ".lock").open("a") as lock:
        report(f"Waiting for analysis cache: {root}")
        fcntl.flock(lock, fcntl.LOCK_EX)
        record_path = root / "cache.json"
        data = None
        reason = "cache absent"
        if record_path.exists():
            try:
                record = json.loads(record_path.read_text())
                # Older records include the absolute PNG path from the source machine.
                arguments = dict(record["arguments"])
                arguments.pop("out", None)
                if record["version"] != CACHE_VERSION:
                    reason = "cache format changed"
                elif arguments != args._cache_arguments:
                    reason = "arguments changed"
                else:
                    directory = root / "attempts" / record["attempt"]
                    if directory.parent != root / "attempts":
                        raise ValueError("invalid cache location")
                    if collection_hashes(directory, cases) != record["sha256"]:
                        raise ValueError("collection files changed")
                    data = inspect_collection(directory, cases)
            except (OSError, ValueError, KeyError, TypeError, csv.Error) as error:
                reason = f"cache invalid: {error}"
        if data is not None:
            report(f"Cache reused: {directory}; no labs required")
            output = render_cached(
                args, directory, data, render, temporal_rates,
                with_origins=with_origins, prepare=prepare,
            )
        else:
            report(f"{reason}; collecting all {len(cases)} runs")
            directory = root / "attempts" / uuid.uuid4().hex
            # collect preserves failed attempts and only returns after cleanup/rendering.
            collect(args, cases, directory)
            output = args.out.resolve() if args.out else directory / "figure.png"
            try:
                inspect_collection(directory, cases)
                hashes = collection_hashes(directory, cases)
            except (OSError, ValueError, KeyError, TypeError, csv.Error) as error:
                report(f"Collection not cached: {error}; evidence: {directory}")
            else:
                save(record_path, dict(
                    version=CACHE_VERSION,
                    arguments=args._cache_arguments,
                    attempt=directory.name,
                    sha256=hashes,
                ))
                report(f"Cache published: {root}")
        print(f"PNG: {output}\nData: {directory}", flush=True)
    if args.out is None:
        report("Opening PNG window; close the window to finish")
        show_png(output)
