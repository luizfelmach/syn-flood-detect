"""Verify resource units, interval alignment, and shared cache integrity.

Run from the repository root: python3 -m unittest discover -s analysis/tests
"""

import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.cache import collection_hashes, inspect_collection
from common.resource_series import cache_kind, cases_for, parse, render, smooth
from common.resources import cpu_capacity, resource_bins


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # Observation starts between samples and ends with a partial final bin.
        self.metadata = dict(id="0001-r1", attackers=3, start_ns=250_000_000,
                             end_ns=1_500_000_000)
        self.rates = [dict(second=0, attack_PASS=2, attack_DROP=8),
                      dict(second=1, attack_PASS=0, attack_DROP=4)]
        self.samples = []
        for node, multiplier in (("server", 1), ("firewall", 2)):
            for second, memory, usage in ((0, 64, 0), (1, 128, 1_000_000), (2, 256, 3_000_000)):
                self.samples.append(dict(node=node, timestamp_monotonic_ns=second * 10**9,
                                         memory_bytes=memory * 2**20,
                                         cpu_usage_usec=usage * multiplier,
                                         cpu_capacity=4 * multiplier))

    def write_samples(self):
        with (self.directory / "resources.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.samples[0].keys())
            writer.writeheader()
            writer.writerows(self.samples)

    def bins(self):
        self.write_samples()
        return resource_bins(self.directory, self.metadata, self.rates, 1)

    def test_weighted_cpu_and_memory_and_partial_bin(self):
        first, last = self.bins()
        self.assertEqual(first["server_memory_mib"], 80)
        self.assertEqual(first["server_cpu_pct"], 31.25)
        self.assertEqual(first["firewall_cpu_pct"], 31.25)
        self.assertEqual(first["attack_syn_per_s"], 10)
        self.assertEqual(last["server_memory_mib"], 128)
        self.assertEqual(last["server_cpu_pct"], 50)
        self.assertEqual(last["attack_syn_per_s"], 4)

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"), "requires the project's Nix plotting environment")
    def test_cpu_plot_uses_percent_values_without_multiplying_by_100(self):
        args = SimpleNamespace(metric="cpu", packet_handling_mode="filter", dpi=72)
        panel = dict(quality="ok", metadata=dict(start_ns=0, end_ns=1_000_000_000), temporal=[
            dict(second=0, server_cpu_pct=.25, firewall_cpu_pct=.5, attack_syn_per_s=100),
            dict(second=.5, server_cpu_pct=.25, firewall_cpu_pct=.5, attack_syn_per_s=100),
        ])
        with patch("matplotlib.figure.Figure.savefig", autospec=True) as saved:
            render(args, [], [panel], self.directory / "cpu.png")
        figure = saved.call_args.args[0]
        server, firewall = figure.axes[0].lines
        self.assertTrue(all(value == .25 for value in server.get_ydata()))
        self.assertTrue(all(value == .5 for value in firewall.get_ydata()))
        self.assertEqual(figure.axes[0].get_ylabel(), "CPU (%)")

    def test_missing_node_is_rejected(self):
        self.samples = [row for row in self.samples if row["node"] == "server"]
        with self.assertRaisesRegex(ValueError, "Missing resource coverage"):
            self.bins()

    def test_missing_start_coverage_is_rejected(self):
        self.samples = [row for row in self.samples if row["timestamp_monotonic_ns"] > 0]
        with self.assertRaisesRegex(ValueError, "Missing resource coverage"):
            self.bins()

    def test_counter_reset_is_rejected(self):
        self.samples[2]["cpu_usage_usec"] = 0
        with self.assertRaisesRegex(ValueError, "Invalid resource counters"):
            self.bins()

    def test_missing_samples_are_rejected(self):
        self.samples[1]["timestamp_monotonic_ns"] = 5_000_000_000
        self.samples[2]["timestamp_monotonic_ns"] = 6_000_000_000
        with self.assertRaisesRegex(ValueError, "Resource sampling gap"):
            self.bins()

    def test_cpu_and_memory_share_cases_and_cache_arguments(self):
        argv = ["--epoch-time-ms", "500", "--syn-count-block-threshold", "3",
                "--ubf-size", "2048", "--clients", "2", "--attackers", "30,10,0,10,20",
                "--duration", "10", "--client-interval", ".5", "--attack-interval", ".1",
                "--bin-seconds", ".5", "--before", "2", "--after", "2"]
        memory = parse("memory", [*argv, "--out", "memory.png"])
        cpu = parse("cpu", [*argv, "--out", "cpu.png"])
        self.assertEqual(memory._cache_arguments, cpu._cache_arguments)
        self.assertEqual(cases_for(memory), cases_for(cpu))
        self.assertEqual(memory.attackers, [30, 10, 0, 10, 20])
        self.assertEqual(len(cases_for(memory)), 1)
        self.assertEqual(cases_for(memory)[0]["attack_steps"], [30, 10, 0, 10, 20])
        self.assertEqual(cases_for(memory)[0]["attackers"], 30)
        allowed = parse("memory", argv, mode="allow")
        allowed_cpu = parse("cpu", argv, mode="allow")
        self.assertEqual(cases_for(allowed)[0]["mode"], "allow")
        self.assertEqual(cases_for(memory)[0]["mode"], "filter")
        self.assertEqual({**cases_for(memory)[0], "mode": "allow"}, cases_for(allowed)[0])
        self.assertEqual(allowed._cache_arguments, allowed_cpu._cache_arguments)
        self.assertNotEqual(memory._cache_arguments, allowed._cache_arguments)
        self.assertNotEqual(cache_kind(memory), cache_kind(allowed))

    def test_smoothing_preserves_flat_values_and_a_zero_plateau(self):
        values = [30, 30, 0, 0, 0, 30, 30]
        self.assertEqual(smooth(values), [30, 20, 10, 0, 10, 20, 30])
        self.assertEqual(values, [30, 30, 0, 0, 0, 30, 30])
        self.assertEqual(smooth([2, 2, 2]), [2, 2, 2])

    def test_smoothing_weights_a_short_final_bin_by_its_duration(self):
        values = smooth([300, 300, 450], [.5, .5, .01])
        self.assertEqual(values[0], 300)
        self.assertAlmostEqual(values[-1], (300 * .5 + 450 * .01) / .51)
        self.assertLess(values[-1], 303)

    def test_five_bin_smoothing_averages_a_wider_window(self):
        self.assertEqual(smooth([0, 0, 10, 0, 0], window=5), [10 / 3, 2.5, 2, 2.5, 10 / 3])

    def test_cpuset_and_ancestor_cpu_quotas(self):
        parent = self.directory / "parent"
        child = parent / "container"
        child.mkdir(parents=True)
        (child / "cpuset.cpus.effective").write_text("0-3,6,8-10\n")
        self.assertEqual(cpu_capacity(child, self.directory), 8)
        (child / "cpu.max").write_text("250000 100000\n")
        self.assertEqual(cpu_capacity(child, self.directory), 2.5)
        (parent / "cpu.max").write_text("150000 100000\n")
        self.assertEqual(cpu_capacity(child, self.directory), 1.5)

    def test_resource_samples_are_part_of_cache_hashes(self):
        (self.directory / "lab").mkdir()
        (self.directory / "0001-r1").mkdir()
        paths = ["experiment.json", "lab/lab.json", "0001-r1/run.json",
                 "0001-r1/packets.csv", "0001-r1/stats.csv", "0001-r1/resources.csv"]
        for path in paths:
            (self.directory / path).write_text("original")
        cases = [dict(id="0001-r1")]
        original = collection_hashes(self.directory, cases, ("resources.csv",))
        (self.directory / "0001-r1/resources.csv").write_text("changed")
        changed = collection_hashes(self.directory, cases, ("resources.csv",))
        self.assertNotEqual(original, changed)

    def test_topology_changes_invalidate_cached_collections(self):
        topology = self.directory / "topo.clab.yml"
        topology.write_text('tcp_syncookies: "1"\n')
        (self.directory / "experiment.json").write_text(json.dumps(dict(
            status="complete", cases=[], topology_sha256=hashlib.sha256(topology.read_bytes()).hexdigest(),
        )))
        (self.directory / "lab").mkdir()
        (self.directory / "lab/lab.json").write_text(json.dumps(dict(status="destroyed")))
        with patch("common.cache.ROOT", self.directory):
            self.assertEqual(inspect_collection(self.directory, []), ([], [], []))
            topology.write_text('tcp_syncookies: "0"\n')
            with self.assertRaisesRegex(ValueError, "topology changed"):
                inspect_collection(self.directory, [])


if __name__ == "__main__":
    unittest.main()
