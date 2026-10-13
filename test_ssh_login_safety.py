"""Regression tests: ConectaSSH-PRO must never intercept interactive SSH logins."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


class SSHLoginSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = (ROOT / "install.sh").read_text()
        cls.update = (ROOT / "update.sh").read_text()
        cls.uninstall = (ROOT / "uninstall.sh").read_text()
        cls.cli = (ROOT / "conectassh_cli.py").read_text()
        cls.main_go = (ROOT / "main.go").read_text()
        cls.server_config_api = (ROOT / "server_config_api.go").read_text()

    def test_auto_menu_feature_is_removed(self):
        for name, source in (("install", self.install), ("update", self.update),
                             ("cli", self.cli), ("main.go", self.main_go),
                             ("server config API", self.server_config_api)):
            with self.subTest(source=name):
                self.assertNotIn('"auto_menu"', source.lower())
                self.assertNotIn("sync_auto_menu_hook", source.lower())
        self.assertFalse((ROOT / "auto-menu.sh").exists())
        options = self.cli[self.cli.index("def main_menu_options():"):self.cli.index("\ndef main():")]
        self.assertNotIn("AUTO MENU", options)
        self.assertNotIn("auto_menu_toggle", options)

    def test_installer_and_updater_never_install_login_hooks(self):
        self.assertNotIn('install -m 0644 "$SCRIPT_DIR/auto-menu.sh"', self.install)
        self.assertNotIn("sync_auto_menu_hook", self.update)
        self.assertNotIn('copy_optional_script "auto-menu.sh"', self.update)
        self.assertIn("remove_legacy_login_hook", self.update)

    def test_uninstaller_removes_only_recognized_legacy_auto_menu_hook(self):
        self.assertIn('local hook="/etc/profile.d/conecta-auto-menu.sh"', self.uninstall)
        self.assertIn("# Managed by ConectaSSH-PRO AUTO MENU; do not edit.", self.uninstall)
        self.assertIn("grep -Fq '/usr/local/bin/conecta'", self.uninstall)
        self.assertIn("grep -Fq 'CONECTA_AUTO_MENU_RUNNING'", self.uninstall)
        self.assertIn('rm -f -- "$hook"', self.uninstall)
        self.assertIn('Se conserva $hook: no se pudo confirmar', self.uninstall)
        self.assertGreaterEqual(self.uninstall.count('cleanup_auto_menu_hook'), 3)

    def _run_uninstaller_hook_cleanup(self, hook_path):
        import re, subprocess, tempfile
        match = re.search(r"(?ms)^cleanup_auto_menu_hook\(\) \{.*?^\}", self.uninstall)
        self.assertIsNotNone(match, "cleanup_auto_menu_hook function must exist")
        function = match.group(0).replace(
            'local hook="/etc/profile.d/conecta-auto-menu.sh"',
            f'local hook="{hook_path}"', 1)
        script = 'set -euo pipefail\nfail(){ echo "[x] $*" >&2; exit 1; }\ninfo(){ echo "[+] $*"; }\nwarn(){ echo "[!] $*" >&2; }\n' + function + '\ncleanup_auto_menu_hook\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)

    def test_uninstaller_runtime_removes_known_legacy_auto_menu_hook(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "conecta-auto-menu.sh"
            hook.write_text('#!/bin/sh\nexec /usr/local/bin/conecta\n')
            result = self._run_uninstaller_hook_cleanup(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(hook.exists())

    def test_uninstaller_runtime_preserves_unrelated_profile_hook(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "conecta-auto-menu.sh"
            content = 'export OTHER_PRODUCT_SETTING=1\n'
            hook.write_text(content)
            result = self._run_uninstaller_hook_cleanup(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(hook.exists())
            self.assertEqual(hook.read_text(), content)

    def test_updater_deploys_fixed_uninstaller(self):
        self.assertIn('copy_optional_script "uninstall.sh" 700', self.update)

    def test_uninstaller_unmounts_owned_log_tmpfs_before_payload_removal(self):
        self.assertLess(self.uninstall.index('umount "$INSTALL_DIR/logs"'),
                        self.uninstall.index("shutil.rmtree(p)"))
        self.assertIn("Ruta insegura; no se elimina el directorio", self.uninstall)

    def test_uninstaller_verifies_product_systemd_units_are_gone(self):
        self.assertIn("Quedó una unidad residual:", self.uninstall)
        self.assertIn('for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"', self.uninstall)

    def test_go_binary_exposes_embedded_uninstall_mode(self):
        installer_go = (ROOT / "installer.go").read_text()
        self.assertIn("//go:embed uninstall.sh", installer_go)
        self.assertIn("func runUninstallerMode() int", installer_go)
        self.assertIn('flag.Bool("uninstall"', self.main_go)
        self.assertIn("os.Exit(runUninstallerMode())", self.main_go)

    def test_scripts_do_not_restart_or_reload_sshd(self):
        for name, source in (("install.sh", self.install), ("update.sh", self.update),
                             ("uninstall.sh", self.uninstall)):
            with self.subTest(script=name):
                self.assertNotIn("systemctl restart sshd", source)
                self.assertNotIn("systemctl reload sshd", source)
                self.assertNotIn("systemctl restart ssh", source)


if __name__ == "__main__":
    unittest.main()
