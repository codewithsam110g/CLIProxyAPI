"""Exercise encrypted artifact rollback using temporary, synthetic data only."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("upgrade_native", Path(__file__).with_name("upgrade-native.py"))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class BackupTests(unittest.TestCase):
    def test_encrypted_backup_restores_artifacts_and_preserves_latest_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "opt/cliproxyapi"
            data = root / "var/lib/cliproxyapi"
            install.mkdir(parents=True)
            data.mkdir(parents=True)
            (install / "cli-proxy-api").write_text("old executable")
            (data / "synthetic-auth").write_text("synthetic credential before upgrade")
            key = root / "private/key"
            archive = root / "backups/state.enc"
            original_popen = subprocess.Popen
            original_run = subprocess.run

            def redirect_tar(args, *a, **kw):
                args = list(args)
                if args[:3] == ["tar", "-C", "/"]:
                    args[2] = str(root)
                return original_popen(args, *a, **kw)

            def redirect_run(args, *a, **kw):
                args = list(args)
                if args[:3] == ["tar", "-C", "/"]:
                    args[2] = str(root)
                return original_run(args, *a, **kw)

            with patch.object(upgrade, "BACKUPS", archive.parent), patch.object(upgrade, "BACKUP_KEY", key), patch.object(upgrade.subprocess, "Popen", side_effect=redirect_tar), patch.object(upgrade.subprocess, "run", side_effect=redirect_run):
                upgrade.encrypt_backup(archive)
                self.assertNotIn(b"synthetic credential", archive.read_bytes())
                self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                (install / "cli-proxy-api").write_text("new executable")
                (data / "synthetic-auth").write_text("newest refreshed credential")
                upgrade.restore_artifacts(archive)
                self.assertEqual((install / "cli-proxy-api").read_text(), "old executable")
                self.assertEqual((data / "synthetic-auth").read_text(), "newest refreshed credential")

    def test_incomplete_manifest_does_not_stop_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "manifest.json").write_text("{}")
            with patch("sys.argv", ["upgrade-native.py", str(bundle)]), patch.object(upgrade.os, "geteuid", return_value=0), patch.object(upgrade, "keys_from", return_value={}), patch.object(upgrade, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "incomplete bundle"):
                    upgrade.main()
                run.assert_not_called()

    def test_snapshot_verification_rejects_lost_binding(self):
        before = {"sessions": [{"id": "synthetic-binding", "auth_id": "a", "generation": 1, "expires_at": "2099-01-01T00:00:00Z"}]}
        after = {"accounts": [], "sessions": []}
        with patch.object(upgrade, "snapshot", return_value=after):
            with self.assertRaisesRegex(RuntimeError, "binding was lost"):
                upgrade.verify("http://127.0.0.1:18317", {}, before, require_upgrade=True)


if __name__ == "__main__":
    unittest.main()
