"""Keep privileged Containerlab backups out of nix-shell temporary directories."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.lab import clab


class LabTests(unittest.TestCase):
    def test_deploy_and_destroy_use_run_specific_backup_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            for run in ("first", "second"):
                lab = root / run
                lab.mkdir()
                topology = lab / "topology.clab.yml"
                topology.write_text("name: test\n")
                for action in ("deploy", "destroy"):
                    with patch.dict(os.environ, {"TMPDIR": "/tmp/nix-shell-test"}), \
                         patch("common.lab.subprocess.run") as command:
                        clab(action, topology, lab / (action + ".log"))
                    kwargs = command.call_args.kwargs
                    temporary = Path(kwargs["env"]["TMPDIR"])
                    self.assertEqual(temporary, lab.resolve() / "containerlab-tmp")
                    self.assertTrue((temporary / ".clab" / "bak").is_dir())
                    self.assertEqual((temporary / ".clab" / "bak").stat().st_uid, os.getuid())
                    self.assertEqual(kwargs["env"]["CLAB_LABDIR_BASE"], "/tmp")
                    self.assertIn("--skip-labdir-acl" if action == "deploy" else "--cleanup",
                                  command.call_args.args[0])
                    calls.append(temporary)
            self.assertEqual(calls[0], calls[1])
            self.assertEqual(calls[2], calls[3])
            self.assertNotEqual(calls[0], calls[2])


if __name__ == '__main__':
    unittest.main()
