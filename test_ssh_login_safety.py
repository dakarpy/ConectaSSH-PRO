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

    def test_uninstaller_still_cleans_known_legacy_hook(self):
        self.assertIn("cleanup_auto_menu_hook", self.uninstall)
        self.assertIn("grep -Fq '/usr/local/bin/conecta'", self.uninstall)
        self.assertIn('rm -f -- "$hook"', self.uninstall)

    def test_updater_deploys_fixed_uninstaller(self):
        self.assertIn('copy_optional_script "uninstall.sh" 700', self.update)

    def test_uninstaller_unmounts_owned_log_tmpfs_before_payload_removal(self):
        self.assertLess(self.uninstall.index('umount "$INSTALL_DIR/logs"'),
                        self.uninstall.index("shutil.rmtree(root)"))
        self.assertIn("ConectaSSH-PRO payload still exists after removal", self.uninstall)

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
