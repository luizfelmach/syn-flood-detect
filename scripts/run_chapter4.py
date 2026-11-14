#!/usr/bin/env python3
"""Preview or run the versioned chapter-4 campaign; never builds the image.

Only --execute creates labs/traffic. Resume with --campaign PATH. A block is
one family/seed; interrupted blocks are preserved and recollected in full.
"""
import argparse
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ('threshold_attack_drop', 'idle_timeout_boundary', 'heatmap_ubf_legitimate',
            'syn_queue_time_series', 'conntrack_time_series', 'syn_backlog_expiration')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
    temporary.replace(path)


def read_profile(path):
    profile = json.loads(path.read_text())
    if profile['version'] != 1 or set(profile['families']) != set(FAMILIES):
        raise ValueError('Unsupported profile version or families')
    seeds = profile['seeds']
    if not seeds or len(set(seeds)) != len(seeds) or any(type(s) is not int for s in seeds):
        raise ValueError('Seeds must be distinct integers')
    for key in ('budget_hours', 'cleanup_margin_seconds', 'minimum_free_gib'):
        if not math.isfinite(profile[key]) or profile[key] <= 0:
            raise ValueError(f'{key} must be finite and positive')
    if profile['sweep']['repetitions'] != 1:
        raise ValueError('Repetitions are the outer seeds, not an additional multiplier')
    return profile


def options_for(profile, family):
    spec = profile['families'][family]
    expected = 'sweep' if family in FAMILIES[:3] else 'ramp'
    if spec['group'] != expected:
        raise ValueError(f'Wrong group for {family}')
    options = {**profile['common'], **profile[expected], **spec['options']}
    if family == 'heatmap_ubf_legitimate':
        options.pop('clients', None)
        options.pop('attackers', None)
    return options


def cli_options(options):
    args = []
    for key, value in options.items():
        args.extend(['--' + key, ','.join(map(str, value)) if isinstance(value, list) else str(value)])
    return args


def jobs_for(profile, root, out, only=None, seed=None, smoke=False):
    jobs = []
    for current_seed in profile['seeds']:
        if seed is not None and current_seed != seed:
            continue
        for family in profile['families']:
            if only and family != only:
                continue
            options = options_for(profile, family)
            if smoke:
                # A diagnostic profile, never eligible as publication evidence.
                if family in FAMILIES[:3]:
                    options = {key: value[:1] if isinstance(value, list) else value
                               for key, value in options.items()}
                    options['duration'] = 2
                else:
                    options.update(attackers=[1, 2], duration=2, before=1, after=2)
            def count(key):
                value = options[key]
                return len(value) if isinstance(value, list) else 1
            if family == 'threshold_attack_drop':
                runs = count('syn-count-block-threshold')
            elif family == 'idle_timeout_boundary':
                runs = count('idle-timeout-ms') * count('attack-interval')
            elif family == 'heatmap_ubf_legitimate':
                runs = count('sources') * count('ubf-size')
            else:
                runs = count('synack-retries') if family == 'syn_backlog_expiration' else 2
            duration = options['duration']
            if family in FAMILIES[3:]:
                duration = duration * len(options['attackers']) + options['before'] + options['after']
            key = f'{family}-{current_seed}'
            command = [sys.executable, str(root / 'analysis' / (family + '.py')),
                       *cli_options(options), '--seed', str(current_seed), '--out', str(out / (key + '.png'))]
            jobs.append(dict(key=key, family=family, seed=current_seed, runs=runs,
                             nominal_seconds=runs * duration, command=command))
    if not jobs:
        raise ValueError('Selection contains no jobs; seed must belong to profile')
    return jobs


def validate_jobs(jobs, root):
    # Use the real parsers and case generators, without collecting any traffic.
    sys.path.insert(0, str(root / 'analysis'))
    for job in jobs:
        module = importlib.import_module(job['family'])
        args = module.parse(job['command'][2:] + ['--dry-run'])
        cases = module.cases_for(args)
        if len(cases) != job['runs']:
            raise ValueError(f"Unexpected run count: {job['key']}")
        job['cases'] = cases
        job['arguments'] = args._cache_arguments


def source_identity(root):
    files = [root / name for name in ('Makefile', 'Dockerfile', 'topo.clab.yml', 'Cargo.lock', 'Cargo.toml')]
    for folder in ('analysis', 'scripts', 'syn-flood-detect', 'syn-flood-detect-common', 'syn-flood-detect-ebpf'):
        files += [p for p in (root / folder).rglob('*') if p.suffix in ('.py', '.rs', '.json', '.toml', '.sh', '.nix')]
    return {str(p.relative_to(root)): digest(p) for p in sorted(set(files)) if p.is_file()}


def capture(command, root, required=True):
    result = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=30)
    record = dict(command=command, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if required and result.returncode:
        raise RuntimeError(f'Preflight failed: {shlex.join(command)}: {result.stderr.strip()}')
    return record


def preflight(root, profile):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('The lab requires Linux x86_64')
    for tool in ('docker', 'containerlab'):
        if not shutil.which(tool):
            raise RuntimeError(f'Missing tool: {tool}')
    import matplotlib
    import numpy
    records = {}
    for name, cmd in [('kernel', ['uname', '-a']), ('cpu', ['lscpu']), ('memory', ['free', '-b']),
                      ('docker', ['docker', 'version']), ('docker_info', ['docker', 'info', '--format', '{{json .}}']),
                      ('containerlab', ['containerlab', 'version']),
                      ('image', ['docker', 'image', 'inspect', profile['common']['image']]),
                      ('revision', ['git', 'rev-parse', 'HEAD']), ('working_tree', ['git', 'status', '--short'])]:
        records[name] = capture(cmd, root)
    docker_info = json.loads(records['docker_info']['stdout'])
    image = json.loads(records['image']['stdout'])[0]
    # Include Docker's server ID: two hosts with similar hardware cannot share repeats.
    identity = dict(sources=source_identity(root), image_id=image['Id'],
                    docker_id=docker_info['ID'], kernel=platform.release(), machine=platform.node(),
                    python=sys.version, matplotlib=matplotlib.__version__, numpy=numpy.__version__)
    records['identity'] = identity
    records['disk_free_bytes'] = shutil.disk_usage(root).free
    return records


def check_space(path, profile):
    free = shutil.disk_usage(path).free
    if free < profile['minimum_free_gib'] * 1024**3:
        raise RuntimeError(f'Less than {profile["minimum_free_gib"]} GiB free; preserve results and free space before resuming')


@contextmanager
def campaign_lock(root):
    directory = root / 'results'
    directory.mkdir(exist_ok=True)
    with (directory / '.chapter4.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another chapter-4 campaign is running') from None
        yield


def verify_archive(directory, receipt, job):
    if receipt['arguments'] != job['arguments'] or receipt['cases'] != job['cases']:
        raise ValueError('Archived arguments/cases differ from requested block')
    for name, expected in receipt['sha256'].items():
        path = directory / name
        if not path.resolve().is_relative_to(directory.resolve()) or digest(path) != expected:
            raise ValueError(f'Archived evidence changed: {name}')


def archive_block(cache_root, directory, job):
    cache = cache_root / job['family']
    record = json.loads((cache / 'cache.json').read_text())
    if record['arguments'] != job['arguments']:
        raise ValueError('Cache did not publish requested arguments')
    source = cache / 'attempts' / record['attempt']
    if not source.resolve().is_relative_to((cache / 'attempts').resolve()):
        raise ValueError('Invalid attempt path')
    exp = json.loads((source / 'experiment.json').read_text())
    if exp['status'] != 'complete' or exp['cases'] != job['cases']:
        raise ValueError('Incomplete or incompatible collection')
    for name, expected in record['sha256'].items():
        if not (source / name).resolve().is_relative_to(source.resolve()) or digest(source / name) != expected:
            raise ValueError(f'Cache evidence changed: {name}')
    with (source / 'runs.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != job['runs'] or any(r['quality'] != 'ok' or int(r['events_lost']) or int(r['aborted']) for r in rows):
        raise ValueError('Collection has invalid or missing runs')
    for case in job['cases']:
        run_dir = source / case['id']
        kernel = json.loads((run_dir / 'kernel_config.json').read_text())
        if kernel['server']['net.ipv4.tcp_syncookies'] != 0:
            raise ValueError('SYN cookies must be disabled')
        if job['family'] == 'conntrack_time_series':
            state = json.loads((run_dir / 'conntrack_limit.json').read_text())
            if not state['restored'] or state['requested'] != kernel['firewall']['net.netfilter.nf_conntrack_max']:
                raise ValueError('Conntrack limit/restoration mismatch')
        if job['family'] == 'syn_backlog_expiration' and kernel['server']['net.ipv4.tcp_synack_retries'] != case['tcp_synack_retries']:
            raise ValueError('SYN-ACK retry mismatch')
    shutil.copytree(source, directory)
    save(directory / 'cache.json', record)
    save(directory / 'invocation.json', job['command'])
    hashes = {str(p.relative_to(directory)): digest(p) for p in directory.rglob('*') if p.is_file()}
    receipt = dict(attempt=record['attempt'], arguments=job['arguments'], cases=job['cases'], sha256=hashes)
    save(directory / 'receipt.json', receipt)
    return receipt


def estimated_seconds(job, history):
    previous = [r['elapsed_seconds'] for r in history if r.get('status') == 'complete' and r['family'] == job['family']]
    return max(job['nominal_seconds'] * 1.25 + job['runs'] * 10 + 120,
               max(previous, default=0) * 1.2)


def run_child(command, root, env, log, timeout):
    with log.open('w') as stream:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
        try:
            return process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            process.send_signal(signal.SIGTERM)
            # Existing collectors handle TERM and restore limits/destroy labs.
            # Never SIGKILL them during cleanup.
            process.wait()
            raise


def execute(root, profile, jobs, out, smoke):
    started = time.monotonic()
    deadline = started + profile['budget_hours'] * 3600
    with campaign_lock(root):
        records = preflight(root, profile)
        check_space(root, profile)
        identity = dict(profile=profile, environment=records['identity'], smoke=smoke)
        manifest_path = out / 'campaign.json'
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if manifest['identity'] != identity:
                raise ValueError('Profile, source, image or host changed; use a new campaign directory')
        else:
            if out.exists():
                raise ValueError('Output exists without a campaign manifest; use a new directory')
            out.mkdir(parents=True)
            manifest = dict(version=1, identity=identity, profile_sha256=fingerprint(profile),
                            status='running', sessions=[], blocks={}, publication_eligible=not smoke)
            save(out / 'profile.json', profile)
            shutil.copyfile(root / 'topo.clab.yml', out / 'topology.clab.yml')
        session = dict(started_utc=datetime.now(timezone.utc).isoformat(), host=records, selected=[j['key'] for j in jobs])
        manifest['sessions'].append(session)
        manifest['status'] = 'running'
        save(manifest_path, manifest)
        def terminated(signum, frame):
            raise KeyboardInterrupt(f'Signal {signum}')
        old = signal.signal(signal.SIGTERM, terminated)
        try:
            for job in jobs:
                history = manifest['blocks'].setdefault(job['key'], [])
                completed = next((r for r in reversed(history) if r['status'] == 'complete'), None)
                if completed:
                    directory = out / completed['directory']
                    verify_archive(directory, json.loads((directory / 'receipt.json').read_text()), job)
                    print(f"Reusing verified block: {job['key']}", flush=True)
                    continue
                all_history = [r for attempts in manifest['blocks'].values() for r in attempts]
                required = estimated_seconds(job, all_history) + profile['cleanup_margin_seconds']
                if deadline - time.monotonic() < required:
                    session['stop_reason'] = 'Insufficient budget for next full block and cleanup'
                    break
                check_space(out, profile)
                if source_identity(root) != records['identity']['sources']:
                    raise ValueError('Source changed during campaign')
                image = capture(['docker', 'image', 'inspect', '--format', '{{.Id}}', profile['common']['image']], root)
                if image['stdout'].strip() != records['identity']['image_id']:
                    raise ValueError('Image changed during campaign')
                token = job['key'] + '-' + uuid.uuid4().hex[:8]
                attempt_root = out / 'attempts' / token
                attempt_root.mkdir(parents=True)
                record = dict(family=job['family'], seed=job['seed'], status='running',
                              directory=str(attempt_root.relative_to(out)), command=job['command'])
                history.append(record)
                save(manifest_path, manifest)
                env = {**os.environ, 'SYN_FLOOD_CACHE_ROOT': str(attempt_root / 'cache'),
                       'SYN_FLOOD_RECORD_KERNEL': '1', 'PYTHONUNBUFFERED': '1'}
                block_start = time.monotonic()
                print(f"Running {job['key']} ({job['runs']} runs); log: {attempt_root / 'execution.log'}", flush=True)
                try:
                    code = run_child(job['command'], root, env, attempt_root / 'execution.log',
                                     max(1, deadline - time.monotonic() - profile['cleanup_margin_seconds']))
                    record['exit_code'] = code
                    if code:
                        raise RuntimeError(f'Collector exited with status {code}; inspect {attempt_root}')
                    archive = attempt_root / 'evidence'
                    receipt = archive_block(attempt_root / 'cache', archive, job)
                    record.update(status='complete', directory=str(archive.relative_to(out)), attempt=receipt['attempt'])
                except BaseException as error:
                    record.update(status='failed', error=str(error) or type(error).__name__)
                    raise
                finally:
                    record['elapsed_seconds'] = time.monotonic() - block_start
                    save(manifest_path, manifest)
            expected = jobs_for(profile, root, out, seed=profile['seeds'][0] if smoke else None, smoke=smoke)
            complete = all(any(r['status'] == 'complete' for r in manifest['blocks'].get(j['key'], [])) for j in expected)
            manifest['status'] = 'complete' if complete else 'incomplete'
        except BaseException as error:
            manifest['status'] = 'incomplete'
            session['stop_reason'] = str(error) or type(error).__name__
            raise
        finally:
            signal.signal(signal.SIGTERM, old)
            session['elapsed_seconds'] = time.monotonic() - started
            save(manifest_path, manifest)
            print(f"Campaign {manifest['status']}: {out}", flush=True)
    return 0 if manifest['status'] == 'complete' else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--campaign', type=Path, help='Existing campaign to resume, or new output directory')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--only', choices=FAMILIES)
    parser.add_argument('--seed', type=int)
    parser.add_argument('--smoke', action='store_true', help='Short diagnostic run, ineligible for article')
    args = parser.parse_args(argv)
    root = args.repo.resolve()
    profile = read_profile(args.profile or root / 'analysis/profiles/chapter4.json')
    out = (args.campaign or root / 'results' / ('chapter4-' + ('smoke-' if args.smoke else '') + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))).resolve()
    seed = args.seed if args.seed is not None else profile['seeds'][0] if args.smoke else None
    jobs = jobs_for(profile, root, out, args.only, seed, args.smoke)
    validate_jobs(jobs, root)
    print(f"{len(jobs)} blocks; {sum(j['runs'] for j in jobs)} runs; nominal observation {sum(j['nominal_seconds'] for j in jobs)/3600:.2f} h; budget {profile['budget_hours']} h", flush=True)
    if not args.execute:
        for job in jobs:
            print(shlex.join(job['command'] + ['--dry-run']))
        print('Validated real parsers/cases; no labs, traffic or output directories created.')
        return 0
    return execute(root, profile, jobs, out, args.smoke)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('Interrupted; evidence preserved. Inspect cleanup logs before resuming.', file=sys.stderr)
        raise SystemExit(130)
    except Exception as error:
        print(f'Error: {error}', file=sys.stderr)
        raise SystemExit(1)
