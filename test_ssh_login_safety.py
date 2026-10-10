"""Regression tests for SSH-login safety in installer and updater."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
HOOK = "/etc/profile.d/conecta-auto-menu.sh"


class SSHLoginSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = (ROOT / "install.sh").read_text()
        cls.update = (ROOT / "update.sh").read_text()

    def test_never_installs_or_creates_the_legacy_hook(self):
        # Only the compatibility-removal function may refer to the active path.
        for name, source in (("install.sh", self.install), ("update.sh", self.update)):
            with self.subTest(script=name):
                self.assertNotRegex(source, r"install\s+[^\n]*auto-menu\.sh[^\n]*/etc/profile\.d")
                self.assertNotRegex(source, r"(?:cp|ln|mv|tee)\s+[^\n]*\s" + re.escape(HOOK) + r"(?:\s|$)")
                self.assertNotRegex(source, r"(?:>|>>|\|\s*tee\s+)\s*" + re.escape(HOOK))
                self.assertNotIn('"$SOURCE_DIR/auto-menu.sh" /etc/profile.d/', source)
                self.assertNotIn('"$SCRIPT_DIR/auto-menu.sh" /etc/profile.d/', source)

    def test_both_scripts_have_safe_legacy_hook_removal(self):
        for name, source in (("install.sh", self.install), ("update.sh", self.update)):
            with self.subTest(script=name):
                self.assertIn("disable_legacy_login_hook()", source)
                self.assertIn('grep -qE \'conecta|sshpanel|auto_menu\' "$hook"', source)
                self.assertIn('backup="$backup_dir/conecta-auto-menu.sh.disabled.$(date +%s%N)"', source)
                self.assertIn('mv -- "$hook" "$backup"', source)
                self.assertIn('if [[ ! -L "$backup" ]]', source)

    def test_updater_disables_hook_before_fetch_build_or_service_stop(self):
        definition = self.update.index("disable_legacy_login_hook()")
        early_call = self.update.index("disable_legacy_login_hook\n", definition)
        fetch = self.update.index("prepare_source_from_git\n")
        build = self.update.index("build_binary\n")
        stop = self.update.index("stop_service\n")
        self.assertLess(definition, early_call)
        self.assertLess(early_call, fetch)
        self.assertLess(early_call, build)
        self.assertLess(early_call, stop)
        # Keep a second idempotent guard during the apply stage as defense in depth.
        self.assertIn("  disable_legacy_login_hook\n", self.update[self.update.index("apply_update() {"):])

    def test_installer_disables_hook_before_snapshot_and_rollback_never_restores_it(self):
        snapshot_fn = self.install[self.install.index("create_rollback_snapshot() {"):self.install.index("restore_rollback_snapshot() {")]
        self.assertNotIn(HOOK, snapshot_fn)
        preflight = self.install.index("preflight_checks\n", self.install.index("# ── 1."))
        early_call = self.install.index("disable_legacy_login_hook\n", preflight)
        snapshot_call = self.install.index("create_rollback_snapshot\n", preflight)
        self.assertLess(preflight, early_call)
        self.assertLess(early_call, snapshot_call)
        # Final call is intentionally retained as an idempotent safeguard after linking CLI.
        self.assertGreater(self.install.rfind("disable_legacy_login_hook\n"), self.install.index("ln -sfn \"$INSTALL_DIR/conectassh_cli.py\" /usr/local/bin/conecta"))

    def test_no_ssh_service_restart_commands_are_added(self):
        for name, source in (("install.sh", self.install), ("update.sh", self.update)):
            with self.subTest(script=name):
                self.assertNotRegex(source, r"systemctl\s+(?:restart|reload)\s+sshd?\b")


if __name__ == "__main__":
    unittest.main()
