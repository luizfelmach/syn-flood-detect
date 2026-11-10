"""SYN_RECV filtering, time alignment, paired experiments and isolated lab caches."""

import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.cache import collection_hashes, inspect_collection
from common.syn_queue import QUEUE_STATS_AWK, SYN_RECV_AWK, queue_series
from syn_queue_time_series import cases_for, parse, render


class SynQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.metadata = dict(id="0001-r1", mode="filter", start_ns=250_000_000, end_ns=1_500_000_000)
        self.samples = [(0, 0, 100), (500_000_000, 10, 150), (1_000_000_000, 20, 200),
                        (1_500_000_000, 512, 250), (2_000_000_000, 0, 300)]

    def series(self):
        with (self.directory / "syn_queue.csv").open("w", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("timestamp_monotonic_ns", "syn_recv", "tcp_req_q_full_drop"))
            writer.writerows(self.samples)
        return queue_series(self.directory, self.metadata, .5)

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_counts_only_port_80_half_open_connections(self):
        data = """  sl local_address rem_address st
0: 020010AC:0050 C49D7825:1234 03
1: 020010AC:0050 C49D7825:1235 01
2: 020010AC:01BB C49D7825:1236 03
3: 020010AC:0050 C49D7825:1237 03
4: 00000000:0050 00000000:0000 0A
"""
        result = subprocess.run(["awk", SYN_RECV_AWK], input=data, text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.strip(), "2")

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_queue_counter_is_extracted_by_header_name(self):
        tcp = self.directory / "tcp"
        tcp.write_text('0: 020010AC:0050 C49D7825:1234 03\n')
        netstat = self.directory / "netstat"
        for header, values in (("Other TCPReqQFullDrop Last", "123 456 789"),
                               ("TCPReqQFullDrop Last Other", "456 789 123")):
            netstat.write_text(f"TcpExt: {header}\nTcpExt: {values}\n")
            result = subprocess.run(["awk", QUEUE_STATS_AWK, str(tcp), str(netstat)],
                                    text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), "1 456")
        for content in ("TcpExt: Other\nTcpExt: 123\n",
                        "TcpExt: TCPReqQFullDrop\nTcpExt: invalid\n"):
            netstat.write_text(content)
            result = subprocess.run(["awk", QUEUE_STATS_AWK, str(tcp), str(netstat)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_snapshot_alignment_preserves_zero_and_partial_endpoint(self):
        rows = self.series()
        self.assertEqual([row["second"] for row in rows], [0, .5, 1, 1.25])
        self.assertEqual([row["syn_recv"] for row in rows], [0, 10, 20, 512])
        self.assertEqual([row["queue_drop_per_s"] for row in rows], [100] * 4)
        self.assertEqual([row["interval_s"] for row in rows], [.5, .5, .25, 0])

    def test_unchanged_counter_means_zero_drops(self):
        self.samples = [(timestamp, count, 12345) for timestamp, count, _ in self.samples]
        self.assertTrue(all(row["queue_drop_per_s"] == 0 for row in self.series()))

    def test_irregular_intervals_use_elapsed_time_and_preserve_total(self):
        self.samples = [(0, 0, 100), (400_000_000, 10, 140),
                        (1_000_000_000, 20, 260), (2_000_000_000, 0, 460)]
        rows = self.series()
        self.assertEqual([row["queue_drop_per_s"] for row in rows], [170, 200, 200, 200])
        self.assertEqual(sum(row["queue_drop_per_s"] * row["interval_s"] for row in rows), 235)
        self.assertEqual(rows[0]["tcp_req_q_full_drop"], 100)

    def test_regressing_counter_is_rejected(self):
        self.samples[2] = (1_000_000_000, 20, 149)
        with self.assertRaisesRegex(ValueError, "counter regressed"):
            self.series()

    def test_missing_counter_is_rejected(self):
        (self.directory / "syn_queue.csv").write_text("timestamp_monotonic_ns,syn_recv\n0,0\n")
        with self.assertRaisesRegex(ValueError, "Missing queue counters"):
            queue_series(self.directory, self.metadata, .5)

    def test_missing_start_coverage_is_rejected(self):
        self.samples = self.samples[1:]
        with self.assertRaisesRegex(ValueError, "Missing SYN_RECV coverage"):
            self.series()

    def test_sampling_gap_is_rejected(self):
        self.samples = [(0, 0, 0), (5_000_000_000, 512, 100)]
        with self.assertRaisesRegex(ValueError, "sampling gap"):
            self.series()

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"), "requires matplotlib")
    def test_plot_preserves_occupancy_and_distinguishes_drop_rates(self):
        from matplotlib.figure import Figure
        from types import SimpleNamespace

        panels = [dict(mode=mode, quality="ok", temporal=[
            dict(second=index * .5, syn_recv=count, queue_drop_per_s=rate,
                 interval_s=.5 if index < 3 else 0) for index in range(4)
        ]) for mode, count, rate in (("filter", 10, 0), ("allow", 512, 100))]
        with patch.object(Figure, "savefig", autospec=True) as save:
            render(SimpleNamespace(dpi=100), [], panels, self.directory / "plot.png")
        fig = save.call_args.args[0]
        self.assertEqual(len(fig.axes), 2)
        left, right = fig.axes
        self.assertEqual([line.get_linestyle() for line in left.lines], ["-", "-", "--"])
        self.assertEqual([line.get_linestyle() for line in right.lines], [":", ":"])
        self.assertEqual([line.get_color() for line in left.lines[:2]],
                         [line.get_color() for line in right.lines])
        self.assertTrue(all(value == 100 for value in right.lines[1].get_ydata()))
        self.assertEqual(right.get_ylabel(), "Descartes por fila cheia (SYN/s)")
        self.assertEqual(right.get_ylim()[0], 0)
        self.assertEqual(len(fig.legends[0].get_texts()), 4)
        self.assertIn("512", left.texts[0].get_text())

    def test_filter_and_allow_have_identical_traffic_and_seeds(self):
        args = parse(["--epoch-time-ms", "500", "--syn-count-block-threshold", "3",
                      "--ubf-size", "2048", "--clients", "2", "--attackers", "1,2,3",
                      "--duration", ".325", "--client-interval", ".5", "--attack-interval", ".01",
                      "--bin-seconds", ".25", "--before", "0", "--after", "6.5"])
        filtered, allowed = cases_for(args)
        self.assertEqual(args._cache_arguments["syn_queue_version"], 2)
        self.assertEqual(filtered["mode"], "filter")
        self.assertEqual(allowed["mode"], "allow")
        self.assertEqual({**filtered, "mode": "allow", "id": allowed["id"]}, allowed)

    def test_cache_requires_cleanup_of_both_isolated_labs(self):
        topology = self.directory / "topo.clab.yml"
        topology.write_text("topology")
        cases = [dict(id="0001-r1"), dict(id="0002-r1")]
        (self.directory / "experiment.json").write_text(json.dumps(dict(
            status="complete", cases=cases, topology_sha256=hashlib.sha256(topology.read_bytes()).hexdigest(),
        )))
        for case in cases:
            run = self.directory / case["id"]
            (run / "lab").mkdir(parents=True)
            (run / "lab/lab.json").write_text(json.dumps(dict(status="destroyed")))
            for name in ("run.json", "packets.csv", "stats.csv", "syn_queue.csv"):
                (run / name).write_text("evidence")
        hashes = collection_hashes(self.directory, cases, ("syn_queue.csv",), isolated_runs=True)
        self.assertIn("0001-r1/lab/lab.json", hashes)
        self.assertIn("0002-r1/lab/lab.json", hashes)
        self.assertNotIn("lab/lab.json", hashes)
        results = [(dict(quality="ok"), [], case) for case in cases]
        with patch("common.cache.ROOT", self.directory), patch("common.cache.analyze_run", side_effect=results):
            self.assertEqual(len(inspect_collection(self.directory, cases, isolated_runs=True)[0]), 2)
        (self.directory / "0002-r1/lab/lab.json").write_text(json.dumps(dict(status="running")))
        with patch("common.cache.ROOT", self.directory):
            with self.assertRaisesRegex(ValueError, "lab cleanup incomplete"):
                inspect_collection(self.directory, cases, isolated_runs=True)


if __name__ == "__main__":
    unittest.main()
