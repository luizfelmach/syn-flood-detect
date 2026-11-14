#!/usr/bin/env python3
"""Read-only campaign/log monitor, suitable for a second tmux pane."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import time


def show(root, offsets):
    path = root / 'campaign.json'
    if not path.exists():
        print(f'{root}: waiting for campaign manifest', flush=True)
        return
    manifest = json.loads(path.read_text())
    blocks = manifest['blocks']
    done = sum(any(r['status'] == 'complete' for r in records) for records in blocks.values())
    print(f"{datetime.now().astimezone().isoformat()} {root.name}: {manifest['status']}; "
          f"{done} blocks complete; disk free {shutil.disk_usage(root).free / 1024**3:.1f} GiB", flush=True)
    for key, records in blocks.items():
        for record in records:
            directory = root / record['directory']
            log = (directory.parent if directory.name == 'evidence' else directory) / 'execution.log'
            if not log.exists():
                continue
            with log.open() as stream:
                stream.seek(offsets.get(str(log), 0))
                chunk = stream.read()
                offsets[str(log)] = stream.tell()
            if chunk:
                print(f"--- {key}: {record['status']} ---\n{chunk}", end='', flush=True)
            if record.get('error'):
                print(f"ERROR {key}: {record['error']}", flush=True)
    if manifest['status'] != 'running' and manifest['sessions'][-1].get('stop_reason'):
        print(manifest['sessions'][-1]['stop_reason'], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('campaigns', nargs='+', type=Path)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    offsets = {}
    # On attachment show only the recent tail; thereafter print every new line.
    for root in args.campaigns:
        for log in root.glob('attempts/*/execution.log'):
            offsets[str(log)] = max(0, log.stat().st_size - 6000)
    while True:
        for root in args.campaigns:
            try:
                show(root, offsets)
            except (OSError, ValueError) as error:
                print(f'{root}: monitor read failed: {error}', flush=True)
        if args.once:
            return
        time.sleep(5)


if __name__ == '__main__':
    main()
