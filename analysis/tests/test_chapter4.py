"""Campaign selection, provenance, failure preservation and budget without Docker."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'analysis'))
import run_chapter4 as campaign
from common.collection import record_kernel_config


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.profile = campaign.read_profile(ROOT / 'analysis/profiles/chapter4.json')

    def jobs(self, out=Path('/tmp/chapter4-preview'), **kwargs):
        jobs = campaign.jobs_for(self.profile, ROOT, out, **kwargs)
        campaign.validate_jobs(jobs, ROOT)
        return jobs

    def test_full_matrix_and_pairing(self):
        jobs = self.jobs()
        self.assertEqual(len(jobs), 30)
        self.assertEqual(sum(j['runs'] for j in jobs), 350)
        self.assertEqual(sum(j['nominal_seconds'] for j in jobs), 13825)
        for job in jobs:
            self.assertEqual(len({c['client_seed'] for c in job['cases']}), 1)
            self.assertEqual(len({c['attack_seed'] for c in job['cases']}), 1)
            self.assertTrue(all(c['client_interval'] == .5 for c in job['cases']))
            self.assertTrue(all(c['repetition'] == 1 for c in job['cases']))
        first = [j for j in jobs if j['seed'] == self.profile['seeds'][0]]
        self.assertEqual([j['runs'] for j in first], [5, 30, 28, 2, 2, 3])
        ramps = first[3:]
        self.assertEqual(len({c['attack_seed'] for j in ramps for c in j['cases']}), 1)
        self.assertEqual(ramps[1]['arguments']['conntrack_max'], 65536)

    def test_preview_creates_no_campaign_or_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'preview'
            with patch.object(campaign, 'execute') as execute, redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(['--repo', str(ROOT), '--campaign', str(out)]), 0)
            execute.assert_not_called()
            self.assertFalse(out.exists())

    def test_selection_and_smoke(self):
        jobs = self.jobs(only='syn_backlog_expiration', seed=self.profile['seeds'][2])
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]['runs'], 3)
        smoke = self.jobs(seed=self.profile['seeds'][0], smoke=True)
        self.assertEqual(sum(j['runs'] for j in smoke), 10)
        self.assertLess(sum(j['nominal_seconds'] for j in smoke), 60)
        with self.assertRaises(ValueError):
            self.jobs(seed=-1)

    def test_profile_changes_invalidate_arguments(self):
        old = self.jobs()[0]
        self.profile['common']['ubf-size'] = 4096
        new = self.jobs()[0]
        self.assertNotEqual(old['arguments'], new['arguments'])
        self.assertNotEqual(old['cases'], new['cases'])

    def test_kernel_evidence_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch('common.collection.command', side_effect=['0\n5\n512\n4096', '0\n65536\n120\n60\n432000']):
                record_kernel_config('lab-', directory)
            observed = json.loads((directory / 'kernel_config.json').read_text())
            self.assertEqual(observed['server']['net.ipv4.tcp_synack_retries'], 5)
            with patch('common.collection.command', side_effect=['1\n5\n512\n4096', '0\n65536\n120\n60\n432000']):
                with self.assertRaises(ValueError):
                    record_kernel_config('lab-', directory)

    def test_archive_tampering_and_argument_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / 'packets.csv'
            file.write_text('original')
            job = self.jobs()[0]
            receipt = dict(arguments=job['arguments'], cases=job['cases'], sha256={'packets.csv': campaign.digest(file)})
            campaign.verify_archive(root, receipt, job)
            file.write_text('changed')
            with self.assertRaises(ValueError):
                campaign.verify_archive(root, receipt, job)
            receipt['arguments'] = {}
            with self.assertRaises(ValueError):
                campaign.verify_archive(root, receipt, job)

    def test_budget_uses_observed_runtime(self):
        job = self.jobs()[0]
        expected = campaign.estimated_seconds(job, [])
        self.assertGreater(expected, job['nominal_seconds'])
        self.assertEqual(campaign.estimated_seconds(job, [dict(status='complete', family=job['family'], elapsed_seconds=2000)]), 2400)

    def test_absolute_deadline_timezone_and_resume(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            campaign.parse_deadline('2026-11-14T07:00:00')
        deadline = campaign.parse_deadline('2026-11-14T07:00:00-03:00')
        self.assertEqual(deadline, '2026-11-14T10:00:00+00:00')
        self.assertEqual(campaign.resolve_deadline(deadline, None), deadline)
        self.assertEqual(campaign.resolve_deadline(deadline, '2026-11-15T10:00:00+00:00'), deadline)
        with patch.object(campaign.time, 'time', return_value=1794650400):
            self.assertEqual(campaign.deadline_remaining(deadline), 0)

    def test_expired_absolute_deadline_survives_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'campaign'
            jobs = self.jobs(out)
            with patch.object(campaign, 'preflight', return_value=self.fake_preflight()), \
                 patch.object(campaign, 'campaign_lock'), patch.object(campaign, 'check_space'), \
                 patch.object(campaign, 'run_child') as run, redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.execute(ROOT, self.profile, jobs, out, False,
                                                 '2020-01-01T00:00:00+00:00'), 2)
                self.assertEqual(campaign.execute(ROOT, self.profile, jobs, out, False), 2)
            run.assert_not_called()
            self.assertEqual(json.loads((out / 'campaign.json').read_text())['deadline_utc'],
                             '2020-01-01T00:00:00+00:00')

    def test_timeout_requests_graceful_cleanup(self):
        import signal
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(campaign.subprocess, 'Popen') as popen:
                process = popen.return_value
                process.wait.side_effect = [subprocess.TimeoutExpired('collector', 10), 0]
                with self.assertRaises(subprocess.TimeoutExpired):
                    campaign.run_child(['collector'], ROOT, {}, Path(tmp) / 'log', 10)
                process.send_signal.assert_called_once_with(signal.SIGTERM)
                self.assertEqual(process.wait.call_count, 2)

    def fake_preflight(self):
        return dict(identity={'sources': campaign.source_identity(ROOT), 'image_id': 'test-image'})

    def test_insufficient_budget_starts_no_collector(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'campaign'
            jobs = self.jobs(out)
            self.profile['budget_hours'] = .001
            with patch.object(campaign, 'preflight', return_value=self.fake_preflight()), \
                 patch.object(campaign, 'campaign_lock'), patch.object(campaign, 'check_space'), \
                 patch.object(campaign, 'run_child') as run, redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.execute(ROOT, self.profile, jobs, out, False), 2)
            run.assert_not_called()
            manifest = json.loads((out / 'campaign.json').read_text())
            self.assertEqual(manifest['status'], 'incomplete')
            self.assertIn('budget', manifest['sessions'][0]['stop_reason'])

    def test_failure_retained_and_changed_profile_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'campaign'
            jobs = self.jobs(out, only='threshold_attack_drop', seed=self.profile['seeds'][0])
            with patch.object(campaign, 'preflight', return_value=self.fake_preflight()), \
                 patch.object(campaign, 'campaign_lock'), patch.object(campaign, 'check_space'), \
                 patch.object(campaign, 'capture', return_value={'stdout': 'test-image\n'}), \
                 patch.object(campaign, 'run_child', return_value=7), redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):
                    campaign.execute(ROOT, self.profile, jobs, out, False)
                manifest = json.loads((out / 'campaign.json').read_text())
                attempt = manifest['blocks'][jobs[0]['key']][0]
                self.assertEqual(attempt['status'], 'failed')
                self.assertEqual(attempt['exit_code'], 7)
                self.assertTrue((out / attempt['directory']).is_dir())
                self.profile['common']['ubf-size'] = 4096
                with self.assertRaises(ValueError):
                    campaign.execute(ROOT, self.profile, jobs, out, False)

    def test_resume_skips_verified_complete_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'campaign'
            out.mkdir()
            jobs = self.jobs(out, only='threshold_attack_drop', seed=self.profile['seeds'][0])
            job = jobs[0]
            evidence = out / 'evidence'
            evidence.mkdir()
            campaign.save(evidence / 'receipt.json', dict(arguments=job['arguments'], cases=job['cases'], sha256={}))
            identity = dict(profile=self.profile, environment=self.fake_preflight()['identity'], smoke=False)
            campaign.save(out / 'campaign.json', dict(identity=identity, sessions=[], blocks={job['key']: [dict(status='complete', directory='evidence')]}))
            with patch.object(campaign, 'preflight', return_value=self.fake_preflight()), \
                 patch.object(campaign, 'campaign_lock'), patch.object(campaign, 'check_space'), \
                 patch.object(campaign, 'run_child') as run, redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.execute(ROOT, self.profile, jobs, out, False), 2)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
