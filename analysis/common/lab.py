"""Create and destroy only the resources shared by the measurements of one analysis."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

from .collection import ROOT, command, control, save
from .progress import report


def clab(action, topology, log):
    # Containerlab puts topology backups under $TMPDIR/.clab/bak. An inherited
    # nix-shell TMPDIR leaves root-owned directories that its exit hook cannot
    # remove. Keep these artifacts with the run, and create their directories
    # as the caller before Containerlab gains privileges.
    temporary = topology.parent.resolve() / "containerlab-tmp"
    (temporary / ".clab" / "bak").mkdir(parents=True, exist_ok=True)
    args = ["containerlab", action, "-t", str(topology)]
    args += ["--skip-labdir-acl"] if action == "deploy" else ["--cleanup"]
    report(f"Containerlab {action}; log: {log}")
    with log.open("w") as stream:
        subprocess.run(
            args,
            cwd=ROOT,
            env={**os.environ, "CLAB_LABDIR_BASE": "/tmp", "TMPDIR": str(temporary)},
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=180,
        )


@contextmanager
def fresh_lab(directory, image_id, timeout):
    directory.mkdir(parents=True, exist_ok=True)
    name = "sf-" + uuid.uuid4().hex[:10]
    prefix = f"clab-{name}-"
    packets = directory / "collector"
    packets.mkdir()
    topology = directory / "topology.clab.yml"
    source = (ROOT / "topo.clab.yml").read_text()
    replacements = {
        "name: topo\n": f"name: {name}\n",
        "network: topo-mgmt": f"network: {name}-mgmt",
        "image: node:local": f"image: {name}:local",
        "./results/packets:/var/log/syn-flood-detect": json.dumps(
            str(packets) + ":/var/log/syn-flood-detect"
        ),
    }
    for old, new in replacements.items():
        if source.count(old) != 1:
            raise RuntimeError(
                f"Incompatible topology: expected exactly one occurrence of {old!r}"
            )
        source = source.replace(old, new)
    topology.write_text(source)
    state = dict(name=name, image_id=image_id, status="deploying")
    save(directory / "lab.json", state)
    tagged = False
    try:
        report(f"Creating isolated lab: {name}")
        command("docker", "image", "tag", image_id, name + ":local")
        tagged = True
        clab("deploy", topology, directory / "deploy.log")
        report(f"Waiting for detector and telemetry (timeout: {timeout:g} s)")
        deadline = time.monotonic() + timeout
        while True:
            try:
                control(prefix, "show")
                if list(packets.glob("stats-*.csv")):
                    break
            except subprocess.CalledProcessError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Detector did not become ready: {name}")
            time.sleep(0.25)
        report(f"Detector ready: {name}")
        state["status"] = "running"
        save(directory / "lab.json", state)
        yield prefix, packets
    except BaseException as error:
        report(
            f"Lab {name} failed: {str(error) or type(error).__name__}; logs: {directory}"
        )
        raise
    finally:
        # A second Ctrl+C must not interrupt destruction of a partially deployed lab.
        previous = {
            sig: signal.signal(sig, signal.SIG_IGN)
            for sig in (signal.SIGINT, signal.SIGTERM)
        }
        try:
            clab("destroy", topology, directory / "destroy.log")
            remaining = command(
                "docker", "ps", "-a", "--format", "{{.Names}}"
            ).splitlines()
            if any(n.startswith(prefix) for n in remaining):
                raise RuntimeError(f"Containers still present: {name}")
            if tagged:
                command("docker", "image", "rm", name + ":local")
            for node in ("client", "attacker"):
                Path(f"/tmp/{prefix}{node}-simulation.lock").unlink(missing_ok=True)
            state["status"] = "destroyed"
            report(
                f"Cleanup complete: {name}; containers and temporary image tag removed"
            )
        except BaseException as error:
            state.update(status="cleanup_failed", error=str(error))
            raise RuntimeError(
                f"Failed to clean up {name}; see {directory / 'destroy.log'}. "
                f"Manual cleanup: containerlab destroy -t {topology} --cleanup"
            ) from error
        finally:
            save(directory / "lab.json", state)
            for sig, handler in previous.items():
                signal.signal(sig, handler)
