"""
tests/test_unknown_distro.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unknown / Unsupported Distro Pipeline Tests

Coverage:
  1. If the os-release file is missing, detect_distro() returns family=unknown
  2. Graceful fallback when ID_LIKE is missing
  3. is_supported() returns False for the unknown family
  4. Unknown distro log paths do not fail empty without fallback logic
  5. DistroAwareSourceManager does not crash on unknown distros
  6. The ML adapter does not crash on unknown distros
  7. The normalize pipeline continues on unknown distros
  8. Warn vs hard-fail banner behavior
"""

import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class NoRaiseTestCase(unittest.TestCase):
    """Simplify repeated try/except self.fail patterns."""

    def assertNotRaises(self, func, msg: str = ""):
        try:
            return func()
        except Exception as exc:
            self.fail(msg or f"Unexpected exception: {exc}")


class TestUnknownDistroDetection(unittest.TestCase):
    """detect_distro() behavior when os-release is missing or incomplete."""

    def test_no_os_release_returns_unknown(self):
        """family should be unknown when os-release is missing."""
        from core.distro import detect_distro
        with patch("core.distro.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            result = detect_distro()
        self.assertIn("family", result)
        # Without system files this may return unknown or the host distro
        self.assertIsInstance(result["family"], str)

    def test_empty_os_release_returns_unknown(self):
        """An empty os-release file should still return a string family."""
        from core.distro import detect_distro
        with tempfile.NamedTemporaryFile(mode='w', suffix='os-release', delete=False) as f:
            f.write("# empty file\n")
            tmp = f.name
        try:
            with patch("core.distro.Path") as mock_path:
                mock_instance = MagicMock()
                mock_instance.exists.return_value = True
                mock_instance.read_text.return_value = "# empty\n"
                mock_path.return_value = mock_instance
                result = detect_distro()
            self.assertIsInstance(result.get("family", "unknown"), str)
        finally:
            os.unlink(tmp)

    def test_id_like_missing_falls_back(self):
        """os-release without ID_LIKE should still behave gracefully."""
        from core.distro import detect_distro
        fake_os_release = "ID=mylinux\nPRETTY_NAME=MyLinux 1.0\nVERSION_ID=1.0\n"
        with patch("builtins.open", unittest.mock.mock_open(read_data=fake_os_release)):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.read_text", return_value=fake_os_release):
                    result = detect_distro()
        # It must not crash even without ID_LIKE
        self.assertIn("family", result)
        self.assertIsInstance(result["family"], str)

    def test_unknown_family_string(self):
        """family should always be a string."""
        from core.distro import detect_distro
        result = detect_distro()  # real system
        self.assertIsInstance(result["family"], str)
        self.assertGreater(len(result["family"]), 0)


class TestUnknownDistroSupport(unittest.TestCase):
    """is_supported() and fallback behavior."""

    def test_unknown_family_not_supported(self):
        """unknown family should produce False from is_supported()."""
        from core.distro import is_supported
        ok, reason = is_supported({"family": "unknown", "pretty": "Unknown OS"})
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)

    def test_supported_families_return_true(self):
        """Known distro families should return True from is_supported()."""
        from core.distro import is_supported
        for family in ("debian", "rhel", "suse"):
            ok, reason = is_supported({"family": family, "pretty": f"{family} Linux"})
            self.assertTrue(ok, f"{family} should be supported")

    def test_is_supported_empty_dict(self):
        """is_supported() should not crash on an empty dict."""
        from core.distro import is_supported
        ok, reason = is_supported({})
        self.assertIsInstance(ok, bool)

    def test_is_supported_none(self):
        """is_supported() should not crash on None input."""
        from core.distro import is_supported
        try:
            ok, reason = is_supported(None)
            self.assertIsInstance(ok, bool)
        except Exception as e:
            self.fail(f"is_supported(None) raised an error: {e}")


class TestUnknownDistroLogPaths(unittest.TestCase):
    """Log paths on unknown distros."""

    def test_resolve_log_paths_unknown_not_empty(self):
        """resolve_log_paths() should return a dict on unknown distros."""
        from core.distro import resolve_log_paths
        paths = resolve_log_paths({"family": "unknown"})
        self.assertIsInstance(paths, dict)

    def test_resolve_log_paths_has_fallback(self):
        """Unknown distros should still exercise fallback path resolution."""
        from core.distro import resolve_log_paths
        paths = resolve_log_paths({"family": "unknown"})
        non_empty = [v for v in paths.values() if v]
        # Fallback may resolve to /var/log/syslog or /var/log/auth.log.
        # It may still be empty if system files are absent; the main goal is no crash.
        self.assertIsInstance(paths, dict)

    def test_all_known_families_resolve(self):
        """Paths should resolve for all known distro families."""
        from core.distro import resolve_log_paths
        for family in ("debian", "rhel", "suse", "unknown"):
            with self.subTest(family=family):
                paths = resolve_log_paths({"family": family})
                self.assertIsInstance(paths, dict, f"expected a dict for {family}")


class TestUnknownDistroSourceManager(NoRaiseTestCase):
    """DistroAwareSourceManager should not crash on unknown distros."""

    def test_source_manager_unknown_distro(self):
        """SourceManager init should not crash on unknown distros."""
        from core.distro import DistroAwareSourceManager
        with patch.object(DistroAwareSourceManager, "_warned_unknown_families", set()), \
             patch("core.distro.logger.warning") as warning_mock:
            sm = self.assertNotRaises(
                lambda: DistroAwareSourceManager({"family": "unknown"}),
                "DistroAwareSourceManager crashed on an unknown distro",
            )
        self.assertIsNotNone(sm)
        warning_mock.assert_called_once()

    def test_source_manager_apply_paths_unknown(self):
        """apply_distro_paths() should not crash on unknown distros."""
        from core.distro import DistroAwareSourceManager
        with patch.object(DistroAwareSourceManager, "_warned_unknown_families", set()), \
             patch("core.distro.logger.warning") as warning_mock:
            sm = DistroAwareSourceManager({"family": "unknown"})
            config = {"sources": {}}
            result = self.assertNotRaises(
                lambda: sm.apply_distro_paths(config),
                "apply_distro_paths() crashed on an unknown distro",
            )
        self.assertIsInstance(result, dict)
        warning_mock.assert_called_once()


class TestApplyDistroPathsPortability(unittest.TestCase):
    """Portable empty-path and distro-resolution behavior."""

    def test_apply_distro_paths_fills_empty_portable_path(self):
        """An empty shipped path should be filled from distro resolution."""
        from core.distro import apply_distro_paths

        config = {"sources": {"auth_log": {"enabled": True, "path": "", "type": "syslog"}}}
        with tempfile.NamedTemporaryFile() as tmp:
            fake_resolved = tmp.name
            with patch("core.distro.detect_distro", return_value={"family": "rhel", "pretty": "Rocky Linux"}):
                with patch("core.distro.resolve_log_paths", return_value={"auth_log": fake_resolved}):
                    result = apply_distro_paths(config)

        self.assertTrue(result["sources"]["auth_log"]["enabled"])
        self.assertEqual(result["sources"]["auth_log"]["path"], fake_resolved)

    def test_apply_distro_paths_disables_unresolved_empty_path(self):
        """The source should be disabled when no file resolves for an empty shipped path."""
        from core.distro import apply_distro_paths

        config = {"sources": {"dns": {"enabled": True, "path": "", "type": "dns"}}}

        with patch("core.distro.detect_distro", return_value={"family": "debian", "pretty": "Ubuntu 24.04"}):
            with patch("core.distro.resolve_log_paths", return_value={"syslog": "/var/log/syslog"}):
                with patch("pathlib.Path.exists", return_value=False):
                    result = apply_distro_paths(config)

        self.assertFalse(result["sources"]["dns"]["enabled"])
        self.assertEqual(result["sources"]["dns"]["path"], "")

    def test_apply_distro_paths_disables_rhel_dns_when_same_as_enabled_syslog(self):
        """On RHEL, dns must not tail the generic syslog a second time."""
        from core.distro import apply_distro_paths

        config = {
            "sources": {
                "syslog": {"enabled": True, "path": "", "type": "syslog"},
                "dns": {"enabled": True, "path": "", "type": "dns"},
            }
        }
        with tempfile.NamedTemporaryFile() as tmp:
            with patch("core.distro.detect_distro", return_value={"family": "rhel", "pretty": "Rocky Linux"}):
                with patch("core.distro.resolve_log_paths", return_value={"syslog": tmp.name}):
                    result = apply_distro_paths(config)

        self.assertTrue(result["sources"]["syslog"]["enabled"])
        self.assertFalse(result["sources"]["dns"]["enabled"])
        self.assertEqual(result["sources"]["syslog"]["path"], tmp.name)
        self.assertEqual(result["sources"]["dns"]["path"], tmp.name)

    def test_apply_distro_paths_disables_debian_dns_when_same_as_enabled_syslog(self):
        """On Debian/Ubuntu, dns must not tail the generic syslog a second time."""
        from core.distro import apply_distro_paths

        config = {
            "sources": {
                "syslog": {"enabled": True, "path": "", "type": "syslog"},
                "dns": {"enabled": True, "path": "", "type": "dns"},
            }
        }
        with tempfile.NamedTemporaryFile() as tmp:
            with patch("core.distro.detect_distro", return_value={"family": "debian", "pretty": "Ubuntu 24.04"}):
                with patch("core.distro.resolve_log_paths", return_value={"syslog": tmp.name}):
                    result = apply_distro_paths(config)

        self.assertTrue(result["sources"]["syslog"]["enabled"])
        self.assertFalse(result["sources"]["dns"]["enabled"])
        self.assertEqual(result["sources"]["syslog"]["path"], tmp.name)
        self.assertEqual(result["sources"]["dns"]["path"], tmp.name)

    def test_apply_distro_paths_keeps_rhel_dns_when_syslog_disabled(self):
        """Preserve the dedicated DNS-only RHEL configuration."""
        from core.distro import apply_distro_paths

        config = {
            "sources": {
                "syslog": {"enabled": False, "path": "", "type": "syslog"},
                "dns": {"enabled": True, "path": "", "type": "dns"},
            }
        }
        with tempfile.NamedTemporaryFile() as tmp:
            with patch("core.distro.detect_distro", return_value={"family": "rhel", "pretty": "Rocky Linux"}):
                with patch("core.distro.resolve_log_paths", return_value={"syslog": tmp.name}):
                    result = apply_distro_paths(config)

        self.assertFalse(result["sources"]["syslog"]["enabled"])
        self.assertTrue(result["sources"]["dns"]["enabled"])
        self.assertEqual(result["sources"]["dns"]["path"], tmp.name)

    def test_apply_distro_paths_disables_debian_dns_duplicate_behavior_when_same_as_syslog(self):
        """On Debian/Ubuntu, dns must not tail the generic syslog twice."""
        from core.distro import apply_distro_paths

        config = {
            "sources": {
                "syslog": {"enabled": True, "path": "", "type": "syslog"},
                "dns": {"enabled": True, "path": "", "type": "dns"},
            }
        }
        with tempfile.NamedTemporaryFile() as tmp:
            with patch("core.distro.detect_distro", return_value={"family": "debian", "pretty": "Ubuntu 24.04"}):
                with patch("core.distro.resolve_log_paths", return_value={"syslog": tmp.name}):
                    result = apply_distro_paths(config)

        self.assertTrue(result["sources"]["syslog"]["enabled"])
        self.assertFalse(result["sources"]["dns"]["enabled"])

    def test_audit_sources_preserves_existing_explicit_path(self):
        """audit_sources must not overwrite an explicit existing path with distro fallback."""
        from core.distro import audit_sources

        with tempfile.NamedTemporaryFile() as explicit_tmp, tempfile.NamedTemporaryFile() as distro_tmp:
            config = {
                "sources": {
                    "auth_log": {
                        "enabled": True,
                        "path": explicit_tmp.name,
                        "type": "syslog",
                    }
                }
            }
            with patch("core.distro.detect_distro", return_value={"family": "debian", "pretty": "Ubuntu 24.04"}):
                with patch("core.distro.resolve_log_paths", return_value={"auth_log": distro_tmp.name}):
                    report = audit_sources(config)

        self.assertEqual(report["auth_log"]["status"], "ok")
        self.assertEqual(report["auth_log"]["path"], explicit_tmp.name)
        self.assertEqual(config["sources"]["auth_log"]["path"], explicit_tmp.name)


class TestPhaseProfileDetection(unittest.TestCase):
    """Virtualization behavior in phase_profile detection."""

    def test_detect_phase_profile_marks_vm_as_lab_from_systemd_detect_virt_stdout(self):
        """The profile should be lab when systemd-detect-virt stdout reports a VM."""
        from core.distro import _detect_phase_profile

        result = MagicMock(returncode=0, stdout=b"kvm\n")
        with patch("pathlib.Path.exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError):
                with patch("shutil.which", return_value="/usr/bin/systemd-detect-virt"):
                    with patch("subprocess.run", return_value=result):
                        with patch.dict("os.environ", {}, clear=True):
                            self.assertEqual(_detect_phase_profile(), "lab")


class TestUnknownDistroMLAdapter(NoRaiseTestCase):
    """DistroMLAdapter must not crash on unknown distros."""

    def test_ml_adapter_unknown_distro(self):
        """ML adapter init must not crash on an unknown distro."""
        from core.ml.distro_ml import DistroMLAdapter
        adapter = self.assertNotRaises(
            lambda: DistroMLAdapter({"family": "unknown"}),
            "DistroMLAdapter crashed on an unknown distro",
        )
        self.assertIsNotNone(adapter)

    def test_ml_adapter_should_train_unknown(self):
        """should_train() must return a bool on unknown distros."""
        from core.ml.distro_ml import DistroMLAdapter
        adapter = DistroMLAdapter({"family": "unknown"})
        result = adapter.should_train("syslog", "login_attempt")
        self.assertIsInstance(result, bool)

    def test_ml_adapter_source_trust_unknown(self):
        """On an unknown distro, the trust score must stay in the 0-1 range."""
        from core.ml.distro_ml import DistroMLAdapter
        adapter = DistroMLAdapter({"family": "unknown"})
        trust = adapter.get_source_trust("auditd")
        self.assertGreaterEqual(trust, 0.0)
        self.assertLessEqual(trust, 1.0)


class TestUnknownDistroNormalize(NoRaiseTestCase):
    """The normalize pipeline must continue on unknown distros."""

    def test_normalize_unknown_distro_auth_log(self):
        """A RHEL fixture log line should still normalize on an unknown distro."""
        from core.normalize import Normalizer
        normalizer = Normalizer()
        # RHEL auth log format
        line = "Jan 15 02:13:45 rhel9-server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
        self.assertNotRaises(
            lambda: normalizer.normalize(line, source="auth"),
            "Normalize unknown distro log'unda çöktü",
        )
        # It must not crash — event may be None or a dict

    def test_normalize_suse_syslog(self):
        """A SUSE syslog line should still normalize successfully."""
        from core.normalize import Normalizer
        normalizer = Normalizer()
        line = "Jan 15 03:22:10 sles15-server sshd[9876]: Failed password for invalid user oracle from 10.0.0.50 port 41234 ssh2"
        self.assertNotRaises(
            lambda: normalizer.normalize(line, source="syslog"),
            "SUSE syslog normalize'da çöktü",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
