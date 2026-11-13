"""Conntrack per-CPU parsing, counter rates and paired firewall plots."""

import csv
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.conntrack import (
    CONNTRACK_STATS_AWK, CONNTRACK_NETLINK_AWK, FIELDS,
    conntrack_sampler_script, conntrack_series, sample_conntrack, temporary_conntrack_limit,
)
from conntrack_time_series import cases_for, parse, render
from syn_queue_time_series import cases_for as server_cases, parse as server_parse


class ConntrackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.metadata = dict(id="0001-r1", mode="filter", start_ns=250_000_000, end_ns=1_500_000_000)
        self.samples = [dict(timestamp_monotonic_ns=timestamp, conntrack_count=count,
                             conntrack_max=1000, drop=drops, early_drop=200, insert_failed=300)
                        for timestamp, count, drops in ((0, 0, 100), (400_000_000, 10, 140),
                                                        (1_000_000_000, 20, 260), (2_000_000_000, 5, 460))]

    def series(self):
        with (self.directory / "conntrack.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("timestamp_monotonic_ns", *FIELDS))
            writer.writeheader()
            writer.writerows(self.samples)
        return conntrack_series(self.directory, self.metadata, .5)

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_hex_counters_sum_cpus_by_name_without_summing_entries(self):
        for data in (
            "entries drop early_drop insert_failed\n00001000 0000000a 00000002 00000001\n00001000 000000FF 00000003 00000002\n",
            "insert_failed early_drop entries drop\n00000001 00000002 00001000 0000000a\n00000002 00000003 00001000 000000FF\n",
        ):
            result = subprocess.run(["awk", "-v", "count=4096", "-v", "maximum=8192", CONNTRACK_STATS_AWK],
                                    input=data, text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), "4096 8192 265 5 3")

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_occupancy_and_capacity_are_read_from_separate_proc_files(self):
        count, capacity, stats = [self.directory / name for name in ("nf_conntrack_count", "nf_conntrack_max", "stats")]
        count.write_text("12345\n")
        capacity.write_text("262144\n")
        stats.write_text("entries drop early_drop insert_failed\n00003039 0a 02 01\n00003039 ff 03 02\n")
        result = subprocess.run(["awk", CONNTRACK_STATS_AWK, str(count), str(capacity), str(stats)],
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.strip(), "12345 262144 265 5 3")

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_missing_malformed_or_empty_cpu_statistics_are_rejected(self):
        for data in ("entries drop\n00000000 00000000\n", "drop early_drop insert_failed\n",
                     "drop early_drop insert_failed\nzz 00 00\n",
                     "drop early_drop insert_failed\n01 00\n", ""):
            result = subprocess.run(["awk", CONNTRACK_STATS_AWK], input=data, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_netlink_decimal_counters_sum_cpus_in_any_field_order(self):
        result = subprocess.run(
            ["awk", "-v", "count=4096", "-v", "maximum=8192", CONNTRACK_NETLINK_AWK],
            input="cpu=0 found=10 drop=10 early_drop=2 insert_failed=1\n"
                  "insert_failed=2 early_drop=3 drop=255 found=900 cpu=7\n",
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), "4096 8192 265 5 3")

    @unittest.skipUnless(shutil.which("awk"), "requires awk")
    def test_netlink_incomplete_malformed_or_duplicate_statistics_are_rejected(self):
        valid = "cpu=0 drop=10 early_drop=2 insert_failed=1\n"
        for data in ("", "\n", "cpu=0 drop=10\n", valid.replace("drop=10", "drop=-1"),
                     valid.replace("drop=10", "drop=0a"), valid.replace("cpu=0", "cpu=x"),
                     valid + valid, valid.replace("drop=10", "drop=10 drop=20"),
                     valid + "conntrack: error\n"):
            with self.subTest(data=data):
                result = subprocess.run(
                    ["awk", "-v", "count=4096", "-v", "maximum=8192", CONNTRACK_NETLINK_AWK],
                    input=data, text=True, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def sampler_fixture(self, *, procfs=None, netlink=None):
        """Exercise the actual POSIX shell sampler against simulated kernel/tool I/O."""
        bindir = self.directory / "bin"
        bindir.mkdir()
        (bindir / "awk").symlink_to(shutil.which("awk"))
        sleep = bindir / "sleep"
        sleep.write_text('#!/bin/sh\nkill -TERM "$PPID"\n')
        sleep.chmod(0o755)
        if netlink is not None:
            tool = bindir / "conntrack"
            tool.write_text('#!/bin/sh\n[ "$1" = -S ] || exit 90\n' + netlink)
            tool.chmod(0o755)
        script = conntrack_sampler_script(.25)
        for original, name, content in (
            ("/proc/sys/net/netfilter/nf_conntrack_count", "nf_conntrack_count", "12345\n"),
            ("/proc/sys/net/netfilter/nf_conntrack_max", "nf_conntrack_max", "65536\n"),
            ("/proc/net/stat/nf_conntrack", "stats", procfs),
        ):
            target = self.directory / name
            if content is not None:
                target.write_text(content)
            script = script.replace(original, str(target))
        return script, {**os.environ, "PATH": str(bindir)}

    @unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "requires awk and sh")
    def test_shell_prefers_procfs_and_does_not_invoke_netlink(self):
        script, env = self.sampler_fixture(
            procfs="entries drop early_drop insert_failed\n00003039 0a 02 01\n00003039 ff 03 02\n",
            netlink="echo 'must not run' >&2\nexit 91\n",
        )
        result = subprocess.run([shutil.which("sh"), "-c", script], env=env,
                                text=True, capture_output=True, timeout=5, check=True)
        self.assertEqual(result.stdout.splitlines()[1:], ["12345 65536 265 5 3"])
        self.assertIn("source: procfs", result.stderr)
        self.assertNotIn("must not run", result.stderr)

    @unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "requires awk and sh")
    def test_shell_netlink_fallback_preserves_zero_counters(self):
        script, env = self.sampler_fixture(
            netlink="echo 'cpu=0 found=3 drop=0 early_drop=0 insert_failed=0'\n"
                    "echo 'cpu=1 found=7 drop=0 early_drop=0 insert_failed=0'\n",
        )
        result = subprocess.run([shutil.which("sh"), "-c", script], env=env,
                                text=True, capture_output=True, timeout=5, check=True)
        self.assertEqual(result.stdout.splitlines()[1:], ["12345 65536 0 0 0"])
        self.assertIn("source: netlink", result.stderr)

    @unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "requires awk and sh")
    def test_shell_missing_tool_has_rebuild_instruction_and_no_sample(self):
        script, env = self.sampler_fixture()
        result = subprocess.run([shutil.which("sh"), "-c", script], env=env,
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)  # PID handshake only
        self.assertIn("make build", result.stderr)

    @unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "requires awk and sh")
    def test_failed_netlink_query_never_publishes_partial_output(self):
        script, env = self.sampler_fixture(
            netlink="echo 'cpu=0 drop=1 early_drop=2 insert_failed=3'\n"
                    "echo 'Operation not permitted' >&2\nexit 1\n",
        )
        result = subprocess.run([shutil.which("sh"), "-c", script], env=env,
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIn("conntrack -S failed", result.stderr)

    @unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "requires awk and sh")
    def test_sampler_reports_underlying_error_and_log_path(self):
        script, env = self.sampler_fixture(netlink="echo 'Operation not permitted' >&2\nexit 1\n")
        popen = subprocess.Popen

        def launch(command, **kwargs):
            # Substitute only Docker transport; run the real failing shell collector.
            return popen([shutil.which("sh"), "-c", script], env=env, **kwargs)

        with patch("common.conntrack.subprocess.Popen", side_effect=launch):
            with self.assertRaisesRegex(RuntimeError, "Operation not permitted") as error:
                with sample_conntrack("test-", self.directory, .25):
                    self.fail("The collector must not become ready without a sample")
        self.assertIn(str(self.directory / "conntrack.log"), str(error.exception))

    def test_sampler_rejects_invalid_interval(self):
        for interval in (0, -1, float('inf'), float('nan')):
            with self.assertRaises(ValueError):
                conntrack_sampler_script(interval)

    def test_time_weighted_rates_preserve_totals_and_occupancy_snapshots(self):
        rows = self.series()
        self.assertEqual([row["second"] for row in rows], [0, .5, 1, 1.25])
        self.assertEqual([row["conntrack_count"] for row in rows], [0, 10, 20, 20])
        self.assertEqual([row["drop_per_s"] for row in rows], [170, 200, 200, 200])
        self.assertEqual(sum(row["drop_per_s"] * row["interval_s"] for row in rows), 235)
        self.assertTrue(all(row["early_drop_per_s"] == row["insert_failed_per_s"] == 0 for row in rows))

    def test_evicted_entries_are_not_added_to_packet_drops(self):
        for index, row in enumerate(self.samples):
            row.update(drop=100, early_drop=200 + index * 50)
        rows = self.series()
        self.assertTrue(all(row["drop_per_s"] == 0 for row in rows))
        self.assertGreater(rows[0]["early_drop_per_s"], 0)

    def test_missing_or_unordered_coverage_and_long_gaps_are_rejected(self):
        original = self.samples
        for samples, error in ((original[1:], "coverage"), (original[:-1], "coverage"),
                               ([original[0], original[0], *original[1:]], "Unordered"),
                               ([original[0], dict(original[-1], timestamp_monotonic_ns=5_000_000_000)], "gap")):
            self.samples = samples
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.series()

    def test_invalid_or_regressing_counters_and_changing_capacity_are_rejected(self):
        for field, value, error in (("drop", 99, "regressed"), ("early_drop", 199, "regressed"),
                                    ("insert_failed", 299, "regressed"), ("conntrack_count", -1, "Invalid"),
                                    ("conntrack_max", 0, "Invalid"), ("conntrack_max", 2000, "capacity changed")):
            original = self.samples[1][field]
            self.samples[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, error):
                self.series()
            self.samples[1][field] = original

    def test_missing_raw_counter_is_rejected(self):
        (self.directory / "conntrack.csv").write_text("timestamp_monotonic_ns,conntrack_count\n0,0\n")
        with self.assertRaisesRegex(ValueError, "Missing conntrack counters"):
            conntrack_series(self.directory, self.metadata, .5)

    def test_experiments_match_server_ramp_and_have_a_separate_cache(self):
        argv = ["--idle-timeout-ms", "500", "--syn-count-block-threshold", "3", "--ubf-size", "2048",
                "--clients", "2", "--attackers", "1,2,3", "--duration", ".325", "--client-interval", ".5",
                "--attack-interval", ".01", "--bin-seconds", ".25", "--before", "0", "--after", "6.5"]
        args = parse(argv)
        self.assertEqual(cases_for(args), server_cases(server_parse(argv)))
        self.assertEqual(args._cache_arguments["conntrack_version"], 3)
        self.assertNotIn("syn_queue_version", args._cache_arguments)
        limited = parse([*argv, "--conntrack-max", "65536"])
        self.assertEqual(limited.conntrack_max, 65536)
        self.assertNotEqual(limited._cache_arguments, args._cache_arguments)
        self.assertEqual(cases_for(limited), cases_for(args))

    def test_host_limit_is_restored_on_success_failure_and_interrupt(self):
        limit = self.directory / "host_limit"
        for error in (None, RuntimeError("experiment failed"), KeyboardInterrupt()):
            limit.write_text("262144\n")
            with patch("common.conntrack.LIMIT_PATH", limit), \
                 patch("common.conntrack.set_host_limit", side_effect=lambda value, image: limit.write_text(str(value))):
                def experiment():
                    with temporary_conntrack_limit(65536, self.directory):
                        self.assertEqual(int(limit.read_text()), 65536)
                        if error is not None:
                            raise error
                if error is None:
                    experiment()
                else:
                    with self.assertRaises(type(error)):
                        experiment()
            self.assertEqual(int(limit.read_text()), 262144)
            state = json.loads((self.directory / "conntrack_limit.json").read_text())
            self.assertEqual(state, dict(original=262144, requested=65536, restored=True))

    def test_failed_host_limit_restoration_is_recorded_and_rejected(self):
        limit = self.directory / "host_limit"
        limit.write_text("262144\n")
        def write(value, image):
            if value == 262144:
                raise RuntimeError("restoration failed")
            limit.write_text(str(value))
        with patch("common.conntrack.LIMIT_PATH", limit), patch("common.conntrack.set_host_limit", side_effect=write):
            with self.assertRaisesRegex(RuntimeError, "restoration failed"):
                with temporary_conntrack_limit(65536, self.directory):
                    pass
        state = json.loads((self.directory / "conntrack_limit.json").read_text())
        self.assertFalse(state["restored"])
        self.assertEqual(state["restore_error"], "restoration failed")

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"), "requires matplotlib")
    def test_plot_axes_styles_capacity_and_zero_drops(self):
        from matplotlib.figure import Figure

        panels = [dict(mode=mode, quality="ok", temporal=[
            dict(second=index * .5, conntrack_count=count, conntrack_max=1000,
                 drop_per_s=0, interval_s=.5 if index < 3 else 0) for index in range(4)
        ]) for mode, count in (("filter", 10), ("allow", 800))]
        with patch.object(Figure, "savefig", autospec=True) as save:
            render(SimpleNamespace(dpi=100), [], panels, self.directory / "plot.png")
        left, right = save.call_args.args[0].axes
        self.assertEqual(left.get_ylabel(), "Entradas no conntrack")
        self.assertEqual(right.get_ylabel(), "Descartes do conntrack (pacotes/s)")
        self.assertEqual([line.get_linestyle() for line in left.lines], ["-", "-", "--"])
        self.assertEqual([line.get_linestyle() for line in right.lines], [":", ":"])
        self.assertEqual([line.get_color() for line in left.lines[:2]],
                         [line.get_color() for line in right.lines])
        self.assertIn("1.000", left.texts[0].get_text())
        self.assertEqual(list(left.lines[-1].get_ydata()), [1000, 1000])
        self.assertTrue(all(value == 0 for line in right.lines for value in line.get_ydata()))
        self.assertEqual(len(save.call_args.args[0].legends[0].get_texts()), 4)


if __name__ == "__main__":
    unittest.main()
