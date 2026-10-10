"""Regression tests for the opt-in, root-only SSH login menu hook."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
HOOK = "/etc/profile.d/conecta-auto-menu.sh"
MARKER = "# Managed by ConectaSSH-PRO AUTO MENU; do not edit."


class SSHLoginSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = (ROOT / "install.sh").read_text()
        cls.update = (ROOT / "update.sh").read_text()
        cls.uninstall = (ROOT / "uninstall.sh").read_text()
        cls.auto_menu = (ROOT / "auto-menu.sh").read_text()
        cls.cli = (ROOT / "conectassh_cli.py").read_text()

    def test_fresh_install_keeps_auto_menu_off_and_installs_helper_only(self):
        self.assertIn('"auto_menu": false', self.install)
        self.assertIn('install -m 0644 "$SCRIPT_DIR/auto-menu.sh" "$INSTALL_DIR/auto-menu.sh"', self.install)
        self.assertNotRegex(self.install, r"install\s+[^\n]*auto-menu\.sh[^\n]*/etc/profile\.d")

    def test_auto_menu_hook_is_opt_in_root_interactive_ssh_only(self):
        for source in (self.auto_menu, self.cli, self.update):
            self.assertIn('"$(id -u 2>/dev/null)" = "0"', source)
            self.assertIn('SSH_CONNECTION', source)
        self.assertIn('case "$-" in *i*)', self.auto_menu)
        self.assertIn('[ -t 0 ] && [ -t 1 ]', self.auto_menu)
        self.assertIn('document["auto_menu"] = target', self.cli)

    def test_updater_restores_hook_only_when_saved_setting_is_true(self):
        self.assertIn('sync_auto_menu_hook "$AUTO_MENU_ENABLED"', self.update)
        self.assertIn('copy_optional_script "auto-menu.sh" 644', self.update)
        self.assertIn('if [[ "$enabled" == "true" ]]', self.update)
        self.assertIn('grep -Fq "$marker" "$hook"', self.update)
        self.assertIn('sync_auto_menu_hook "$AUTO_MENU_ENABLED"', self.update)

    def test_uninstaller_removes_only_recognized_auto_menu_hook(self):
        self.assertIn(MARKER, self.uninstall)
        self.assertIn("grep -Fq '/usr/local/bin/conecta'", self.uninstall)
        self.assertIn("grep -Fq 'CONECTA_AUTO_MENU_RUNNING'", self.uninstall)
        self.assertIn('rm -f -- "$hook"', self.uninstall)

    def test_uninstaller_cleans_hook_before_services_and_rechecks_after_payload_removal(self):
        first_call = self.uninstall.index('cleanup_auto_menu_hook\n', self.uninstall.index('if [[ "$CONFIRM"'))
        service_stop = self.uninstall.index('systemctl disable --now "$SERVICE"')
        payload_remove = self.uninstall.index('shutil.rmtree(root)')
        second_call = self.uninstall.index('cleanup_auto_menu_hook', payload_remove)
        self.assertLess(first_call, service_stop)
        self.assertLess(payload_remove, second_call)
        self.assertIn('[[ ! -e "$hook" && ! -L "$hook" ]] || fail', self.uninstall)
        self.assertGreaterEqual(self.uninstall.count('cleanup_auto_menu_hook'), 3)

    def _run_uninstaller_hook_cleanup(self, hook_path):
        match = re.search(r"(?ms)^cleanup_auto_menu_hook\(\) \{.*?^\}", self.uninstall)
        self.assertIsNotNone(match, "cleanup_auto_menu_hook function must exist")
        function = match.group(0).replace(
            'local hook="/etc/profile.d/conecta-auto-menu.sh"',
            f'local hook="{hook_path}"',
            1,
        )
        script = 'set -euo pipefail\nfail(){ echo "[x] $*" >&2; exit 1; }\ninfo(){ echo "[+] $*"; }\n' + function + '\ncleanup_auto_menu_hook\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)

    def test_uninstaller_runtime_removes_managed_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "conecta-auto-menu.sh"
            hook.write_text(MARKER + "\ncase \"$-\" in *i*) ;; *) return 0 ;; esac\n")
            result = self._run_uninstaller_hook_cleanup(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(hook.exists())
            self.assertIn("Hook AUTO MENU de Conecta retirado", result.stdout)

    def test_uninstaller_runtime_removes_known_legacy_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "conecta-auto-menu.sh"
            hook.write_text('[ -r /opt/sshpanel/auto-menu.sh ] || return 0\nexec /usr/local/bin/conecta\n')
            result = self._run_uninstaller_hook_cleanup(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(hook.exists())

    def test_uninstaller_runtime_preserves_unrelated_profile_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "conecta-auto-menu.sh"
            content = 'export OTHER_PRODUCT_SETTING=1\n'
            hook.write_text(content)
            result = self._run_uninstaller_hook_cleanup(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(hook.exists())
            self.assertEqual(hook.read_text(), content)

    def test_no_ssh_service_restart_commands_are_added(self):
        for name, source in (("install.sh", self.install), ("update.sh", self.update), ("uninstall.sh", self.uninstall)):
            with self.subTest(script=name):
                self.assertNotRegex(source, r"systemctl\s+(?:restart|reload)\s+sshd?\b")
                self.assertNotRegex(source, r"systemctl\s+restart\s+sshpanel-online-bridge\b")

    def test_auto_menu_setting_change_has_rollback_on_hook_failure(self):
        start = self.cli.index("def auto_menu_toggle():")
        end = self.cli.index("def ssh_connection_limit_toggle():", start)
        block = self.cli[start:end]
        self.assertIn('sync_auto_menu_hook(target)', block)
        self.assertIn('document["auto_menu"] = current', block)
        self.assertIn('Cerrá y volvé a abrir la sesión SSH', block)


if __name__ == "__main__":
    unittest.main()
