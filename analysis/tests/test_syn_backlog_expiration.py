"""Retry sweep configuration, evidence, time alignment and chart semantics."""

import argparse
import csv
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from syn_backlog_expiration import cases_for, configure_server, parse, prepare, render, retry_values
from common.metrics import METRICS


class ExpirationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.argv = ["--idle-timeout-ms", "500", "--syn-count-block-threshold", "3", "--ubf-size", "2048",
                     "--clients", "2", "--attackers", ",".join(map(str, range(1, 101))),
                     "--duration", ".325", "--client-interval", ".5", "--attack-interval", ".01",
                     "--bin-seconds", ".25", "--before", "0", "--after", "90"]

    def test_cases_change_only_retries_and_id(self):
        args = parse(self.argv)
        cases = cases_for(args)
        self.assertEqual([case["tcp_synack_retries"] for case in cases], [1, 3, 5])
        self.assertEqual(args.after, 90)
        self.assertEqual(cases[0]["mode"], "allow")
        self.assertEqual(cases[0]["step_duration_s"] * len(cases[0]["attack_steps"]), 32.5)
        for case in cases:
            self.assertEqual({**case, "id": cases[0]["id"], "tcp_synack_retries": 1}, cases[0])
        changed = parse([*self.argv, "--synack-retries", "2,4"])
        self.assertNotEqual(args._cache_arguments, changed._cache_arguments)

    def test_invalid_retry_lists_are_rejected(self):
        for value in ("", "-1", "256", "1,1", "1,", "abc"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                retry_values(value)

    def test_server_settings_are_verified_and_recorded(self):
        with patch("syn_backlog_expiration.command", side_effect=["configured", "3\n0"]) as command:
            configure_server("clab-test-", self.directory, 3)
        self.assertIn("clab-test-server", command.call_args_list[0].args)
        self.assertEqual(json.loads((self.directory / "server_config.json").read_text()),
                         {"net.ipv4.tcp_synack_retries": 3, "net.ipv4.tcp_syncookies": 0})
        with patch("syn_backlog_expiration.command", side_effect=["configured", "5\n0"]):
            with self.assertRaisesRegex(ValueError, "configuration"):
                configure_server("clab-test-", self.directory, 3)

    def test_prepare_preserves_full_tail_and_retry_labels(self):
        metadata = dict(id="0001-r1", mode="allow", tcp_synack_retries=3,
                        start_ns=0, end_ns=122_500_000_000,
                        phases=dict(measure_start_ns=250_000_000, measure_end_ns=32_500_000_000))
        config = self.directory / "server_config.json"
        config.write_text(json.dumps({"net.ipv4.tcp_synack_retries": 3, "net.ipv4.tcp_syncookies": 0}))
        points = [dict(second=0, syn_recv=1), dict(second=122.25, syn_recv=0)]
        row = dict(cases_for(parse(self.argv))[1], quality="ok", **{metric: 0 for metric in METRICS})
        with patch("syn_backlog_expiration.queue_series", return_value=points) as series:
            panels = prepare(parse(self.argv), [row], [(self.directory, metadata)], self.directory)
        view = series.call_args.args[1]
        self.assertEqual(view["start_ns"], metadata["phases"]["measure_start_ns"])
        self.assertEqual(view["end_ns"], metadata["end_ns"])
        self.assertTrue(all(point["tcp_synack_retries"] == 3 for point in panels[0]["temporal"]))
        summary = list(csv.DictReader((self.directory / "summary.csv").open()))
        self.assertEqual(summary[0]["tcp_synack_retries"], "3")
        self.assertEqual(summary[0]["n"], "1")
        config.write_text("{}")
        with self.assertRaisesRegex(ValueError, "configuration evidence"):
            prepare(parse(self.argv), [dict(quality="ok")], [(self.directory, metadata)], self.directory)

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"), "requires matplotlib")
    def test_plot_has_three_distinct_curves_and_one_axis(self):
        from matplotlib.figure import Figure
        panels = [dict(retries=retries, quality="ok", temporal=[
            dict(second=index * 30, syn_recv=count) for index, count in enumerate((100, 512, 50, 0, 0))
        ]) for retries in (1, 3, 5)]
        with patch.object(Figure, "savefig", autospec=True) as save:
            render(SimpleNamespace(dpi=100), [], panels, self.directory / "chart.png")
        fig = save.call_args.args[0]
        self.assertEqual(len(fig.axes), 1)
        ax = fig.axes[0]
        self.assertEqual(len(ax.lines), 3)
        self.assertEqual(len({line.get_color() for line in ax.lines}), 3)
        self.assertEqual(len({line.get_linestyle() for line in ax.lines}), 3)
        self.assertEqual(ax.get_xlim(), (0, 120))
        self.assertEqual(ax.get_ylabel(), "Conexões em SYN_RECV")
        self.assertEqual(len(fig.legends[0].get_texts()), 3)


if __name__ == "__main__":
    unittest.main()
