"""Regression guard: installer/updater must not hijack SSH login."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent

class SSHLoginSafetyTests(unittest.TestCase):
    def test_no_automatic_login_hook_installation(self):
        for script in ("install.sh", "update.sh"):
            source = (ROOT / script).read_text()
            with self.subTest(script=script):
                self.assertNotIn('install -m 0644 "$SCRIPT_DIR/auto-menu.sh" /etc/profile.d/', source)
                self.assertNotIn('install -m 0644 "$SOURCE_DIR/auto-menu.sh" /etc/profile.d/', source)
                self.assertNotIn('systemctl restart ssh', source)
                self.assertNotIn('systemctl restart sshd', source)

if __name__ == "__main__":
    unittest.main()
