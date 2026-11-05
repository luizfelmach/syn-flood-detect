#!/usr/bin/env python3
"""Save timestamped analyses and their cache to the project's fixed S3 bucket."""

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
BUCKET = "syn-flood-detect-tcc-luiz"
PREFIX = "analysis/"
TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{6}Z"
SNAPSHOT_ID = TIMESTAMP + r"(?:--[a-z0-9][a-z0-9_-]{0,79})?"


def aws(*args, capture=False):
    return subprocess.run(
        ["aws", "--no-cli-pager", *args], check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


@contextmanager
def cache_locks(analysis, kinds=()):
    """Share the collector's locks without replacing its lock files on restore."""
    cache = analysis / "cache"
    directories = {p for p in cache.glob("*") if p.is_dir()}
    directories.update(cache / kind for kind in kinds)
    with ExitStack() as stack:
        for directory in sorted(directories):
            directory.mkdir(parents=True, exist_ok=True)
            lock = stack.enter_context((directory / ".lock").open("a"))
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def archive_member(member):
    if Path(member.name).name == ".lock":
        return None
    if not (member.isfile() or member.isdir()):
        raise ValueError(f"Unsupported analysis file: {member.name}")
    return member


def snapshot_id(name=None, skip_prompt=False):
    if name is None and not skip_prompt:
        try:
            name = input("Analysis name (Enter to use date and time): ")
        except EOFError:
            name = ""
    suffix = ""
    if name and name.strip():
        normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
        normalized = re.sub(r"[^a-z0-9_-]+", "-", normalized.lower()).strip("-_")
        if not normalized or len(normalized) > 80:
            raise ValueError("Use a name with letters or numbers, up to 80 characters after normalization.")
        suffix = "--" + normalized
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%fZ") + suffix


def save(name=None, skip_prompt=False):
    analysis = ROOT / "results" / "analysis"
    if not analysis.is_dir() or not any(analysis.iterdir()):
        raise ValueError("No analysis to save. Run make analysis first.")
    snapshot = snapshot_id(name, skip_prompt)
    uri = f"s3://{BUCKET}/{PREFIX}{snapshot}.tar.gz"
    print("Packing analysis and cache; waiting for active analyses to finish...", flush=True)
    with TemporaryDirectory(prefix="analysis-save-") as temporary:
        archive = Path(temporary) / "analysis.tar.gz"
        with cache_locks(analysis):
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(analysis, arcname="analysis", filter=archive_member)
        print(f"Uploading {uri}", flush=True)
        aws("s3", "cp", str(archive), uri)
    print(f"Saved: {uri}\nRestore: make download SNAPSHOT={snapshot}", flush=True)


def snapshot_key(snapshot):
    if snapshot == "select" and shutil.which("fzf") is None:
        raise ValueError("fzf is required to select a saved analysis. Install fzf first.")
    if snapshot not in ("latest", "select"):
        if not re.fullmatch(SNAPSHOT_ID, snapshot):
            raise ValueError("SNAPSHOT must be select, latest or a snapshot ID printed by make save.")
        return f"{PREFIX}{snapshot}.tar.gz"
    listing = json.loads(aws(
        "s3api", "list-objects-v2", "--bucket", BUCKET,
        "--prefix", PREFIX, "--output", "json", capture=True,
    ))
    keys = [obj["Key"] for obj in listing.get("Contents", [])
            if re.fullmatch(re.escape(PREFIX) + SNAPSHOT_ID + r"\.tar\.gz", obj["Key"])]
    if not keys:
        raise ValueError(f"No saved analyses in s3://{BUCKET}/{PREFIX}")
    if snapshot == "latest":
        return max(keys)
    snapshots = [key.removeprefix(PREFIX).removesuffix(".tar.gz")
                 for key in sorted(keys, reverse=True)]
    selection = subprocess.run(
        ["fzf", "--no-multi", "--no-sort", "--height=40%", "--reverse",
         "--prompt=Snapshot> ", "--header=Saved analyses (UTC) | Enter: download | Esc: cancel"],
        input="\n".join(snapshots) + "\n", stdout=subprocess.PIPE, text=True,
    )
    if selection.returncode in (1, 130):
        return None
    selection.check_returncode()
    selected = selection.stdout.strip()
    if selected not in snapshots:
        raise ValueError("fzf returned an unknown snapshot.")
    return f"{PREFIX}{selected}.tar.gz"


def download(snapshot="select"):
    key = snapshot_key(snapshot)
    if key is None:
        print("Download cancelled.", flush=True)
        return
    uri = f"s3://{BUCKET}/{key}"
    print(f"Downloading {uri}", flush=True)
    with TemporaryDirectory(prefix="analysis-download-") as temporary:
        staging = Path(temporary)
        archive = staging / "analysis.tar.gz"
        aws("s3", "cp", uri, str(archive))
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if (not path.parts or path.parts[0] != "analysis" or ".." in path.parts
                        or not (member.isfile() or member.isdir()) or path.name == ".lock"):
                    raise ValueError(f"Invalid snapshot member: {member.name}")
            stream.extractall(staging, members=members, filter="data")
        source = staging / "analysis"
        if not source.is_dir():
            raise ValueError("Snapshot does not contain an analysis directory.")
        destination = ROOT / "results" / "analysis"
        kinds = [p.name for p in (source / "cache").glob("*") if p.is_dir()]
        print("Restoring analysis and cache; waiting for active analyses to finish...", flush=True)
        with cache_locks(destination, kinds):
            shutil.copytree(source, destination, dirs_exist_ok=True)
    print(f"Restored: {destination}\nSource: {uri}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("save", "download"))
    parser.add_argument("--snapshot", default="select",
                        help="select with fzf (default), latest, or a saved snapshot ID")
    parser.add_argument("--name", help="save with this name, bypassing the name prompt")
    parser.add_argument("--skip-prompt", action="store_true",
                        help="save without prompting; use date and time when no name is given")
    args = parser.parse_args()
    if shutil.which("aws") is None:
        parser.error("AWS CLI is required. Install aws and configure its credentials first.")
    try:
        if args.command == "save":
            save(args.name, args.skip_prompt)
        else:
            download(args.snapshot)
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
