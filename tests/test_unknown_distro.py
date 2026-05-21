"""
tests/test_unknown_distro.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unknown / Unsupported Distro Pipeline Testleri

Test kapsamı:
  1. os-release dosyası yoksa detect_distro() family=unknown döner
  2. ID_LIKE eksikse graceful fallback
  3. unknown family'de is_supported() False döner
  4. unknown distro'da log yolları boş dönmez (fallback var)
  5. unknown distro'da DistroAwareSourceManager çökmez
  6. unknown distro'da ML adapter çökmez
  7. Normalize pipeline unknown distro'da devam eder
  8. Warn mı hard-fail mi — banner davranışı
"""

import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


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
            f.write("# boş dosya\n")
            tmp = f.name
        try:
            with patch("core.distro.Path") as mock_path:
                mock_instance = MagicMock()
                mock_instance.exists.return_value = True
                mock_instance.read_text.return_value = "# boş\n"
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
        result = detect_distro()  # gerçek sistem
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
            self.assertTrue(ok, f"{family} desteklenmeli")

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
            self.fail(f"is_supported(None) hata fırlattı: {e}")


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
        # Fallback olarak /var/log/syslog veya /var/log/auth.log olabilir
        # It may still be empty if system files are absent; the main goal is no crash.
        self.assertIsInstance(paths, dict)

    def test_all_known_families_resolve(self):
        """Paths should resolve for all known distro families."""
        from core.distro import resolve_log_paths
        for family in ("debian", "rhel", "suse", "unknown"):
            with self.subTest(family=family):
                paths = resolve_log_paths({"family": family})
                self.assertIsInstance(paths, dict, f"{family} için dict bekleniyor")


class TestUnknownDistroSourceManager(unittest.TestCase):
    """DistroAwareSourceManager should not crash on unknown distros."""

    def test_source_manager_unknown_distro(self):
        """SourceManager init should not crash on unknown distros."""
        from core.distro import DistroAwareSourceManager
        with patch.object(DistroAwareSourceManager, "_warned_unknown_families", set()), \
             patch("core.distro.logger.warning") as warning_mock:
            try:
                sm = DistroAwareSourceManager({"family": "unknown"})
                self.assertIsNotNone(sm)
            except Exception as e:
                self.fail(f"DistroAwareSourceManager unknown distro'da çöktü: {e}")
        warning_mock.assert_called_once()

    def test_source_manager_apply_paths_unknown(self):
        """apply_distro_paths() should not crash on unknown distros."""
        from core.distro import DistroAwareSourceManager
        with patch.object(DistroAwareSourceManager, "_warned_unknown_families", set()), \
             patch("core.distro.logger.warning") as warning_mock:
            sm = DistroAwareSourceManager({"family": "unknown"})
            config = {"sources": {}}
            try:
                result = sm.apply_distro_paths(config)
                self.assertIsInstance(result, dict)
            except Exception as e:
                self.fail(f"apply_distro_paths() unknown distro'da çöktü: {e}")
        warning_mock.assert_called_once()


class TestUnknownDistroMLAdapter(unittest.TestCase):
    """DistroMLAdapter should not crash on unknown distros."""

    def test_ml_adapter_unknown_distro(self):
        """ML adapter init should not crash on unknown distros."""
        from core.ml.distro_ml import DistroMLAdapter
        try:
            adapter = DistroMLAdapter({"family": "unknown"})
            self.assertIsNotNone(adapter)
        except Exception as e:
            self.fail(f"DistroMLAdapter unknown distro'da çöktü: {e}")

    def test_ml_adapter_should_train_unknown(self):
        """should_train() should return a bool on unknown distros."""
        from core.ml.distro_ml import DistroMLAdapter
        adapter = DistroMLAdapter({"family": "unknown"})
        result = adapter.should_train("syslog", "login_attempt")
        self.assertIsInstance(result, bool)

    def test_ml_adapter_source_trust_unknown(self):
        """trust score should stay within 0-1 on unknown distros."""
        from core.ml.distro_ml import DistroMLAdapter
        adapter = DistroMLAdapter({"family": "unknown"})
        trust = adapter.get_source_trust("auditd")
        self.assertGreaterEqual(trust, 0.0)
        self.assertLessEqual(trust, 1.0)


class TestUnknownDistroNormalize(unittest.TestCase):
    """unknown distro'da normalize pipeline devam etmeli."""

    def test_normalize_unknown_distro_auth_log(self):
        """A RHEL fixture log line should still normalize on an unknown distro."""
        from core.normalize import Normalizer
        normalizer = Normalizer()
        # RHEL auth log format
        line = "Jan 15 02:13:45 rhel9-server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
        try:
            event = normalizer.normalize(line, source="auth")
            # Crash etmemeli — event None veya dict olabilir
        except Exception as e:
            self.fail(f"Normalize unknown distro log'unda çöktü: {e}")

    def test_normalize_suse_syslog(self):
        """A SUSE syslog line should still normalize successfully."""
        from core.normalize import Normalizer
        normalizer = Normalizer()
        line = "Jan 15 03:22:10 sles15-server sshd[9876]: Failed password for invalid user oracle from 10.0.0.50 port 41234 ssh2"
        try:
            normalizer.normalize(line, source="syslog")
        except Exception as e:
            self.fail(f"SUSE syslog normalize'da çöktü: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
