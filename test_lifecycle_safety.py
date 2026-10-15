#!/usr/bin/env python3
"""Isolated lifecycle tests. All absolute paths are rewritten into a temporary root."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent
INSTALL = (REPO / "install.sh").read_text()
UPDATE = (REPO / "update.sh").read_text()
UNINSTALL = (REPO / "uninstall.sh").read_text()


def run(cmd, **kw):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


class LifecycleSafetyTests(unittest.TestCase):
    def test_shell_syntax_and_ssh_invariants(self):
        for name in ("install.sh", "update.sh", "uninstall.sh"):
            result = run(["bash", "-n", str(REPO / name)])
            self.assertEqual(result.returncode, 0, result.stdout)
        for source in (INSTALL, UPDATE, UNINSTALL):
            self.assertNotRegex(source, r"(?im)^\s*(?:systemctl|service)\s+(?:restart|reload|stop|disable|enable)\s+(?:ssh|sshd)(?:\.service)?\b")
            self.assertNotIn("/etc/ssh/sshd_config", source)
        self.assertNotRegex(UPDATE, r"(?i)(iptables|ip6tables|nft\s|ensure_dnstt_redirect|systemd-resolved|/etc/resolv\.conf)")

    def test_existing_valid_install_routes_to_idempotent_updater(self):
        # Existing valid product installs must be updated, not rejected or overwritten.
        self.assertIn('exec env UPDATE_SOURCE=local bash "$SCRIPT_DIR/update.sh"', INSTALL)
        self.assertIn("grep -qx 'STATE=installed' \"$INSTALL_DIR/.conecta-install-manifest\"", INSTALL)
        self.assertIn("grep -q 'ExecStart=/opt/sshpanel/sshpanel'", INSTALL)

    def test_installer_checks_real_postgres_credentials_and_uses_idempotent_ddl(self):
        self.assertIn("PGPASSWORD=\"$DB_PASS\" psql -h 127.0.0.1 -U \"$DB_USER\" -d \"$DB_NAME\"", INSTALL)
        self.assertIn("CREATE TABLE IF NOT EXISTS ssh_users", INSTALL)
        self.assertIn("CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}", INSTALL)
        self.assertIn("CREATE USER ${DB_USER} WITH PASSWORD", INSTALL)

    def test_installer_removes_only_known_recovery_override_and_checks_api_listener(self):
        # A stale systemd drop-in can keep launching the recovery binary after
        # reinstall, even when the base unit points to the real panel binary.
        self.assertIn('temporary-recovery.conf', INSTALL)
        self.assertIn('ExecStart=/opt/sshpanel/sshpanel-recovery -config /opt/sshpanel/config.json', INSTALL)
        self.assertIn('UnsetEnvironment=PG_DSN', INSTALL)
        self.assertIn('! -L "$RECOVERY_OVERRIDE"', INSTALL)
        self.assertIn("timeout 2 bash -c ':</dev/tcp/127.0.0.1/9090'", INSTALL)
        self.assertIn('sshpanel no abrió 127.0.0.1:9090', INSTALL)

    def test_online_bridge_unit_is_registered_and_removed_transactionally(self):
        self.assertIn('register_resource unit /etc/systemd/system/conecta-online-bridge.service', INSTALL)
        self.assertIn('OWNED_UNIT_ONLINE_BRIDGE=${OWNED_UNIT_ONLINE_BRIDGE:-0}', INSTALL)
        self.assertIn('ExecStart=/opt/sshpanel/online-bridge/conecta-online-bridge', INSTALL)
        self.assertIn('unit_name="conecta-online-bridge.service"', INSTALL)
        self.assertIn('OWNED_UNIT_ONLINE_BRIDGE="${OWNED_UNIT_ONLINE_BRIDGE:-0}"', UNINSTALL)
        self.assertIn("cmp -s \"$source_dir/conecta-online-bridge.service\" /etc/systemd/system/conecta-online-bridge.service", UPDATE)
        self.assertIn("Repaired verified legacy online-bridge ownership marker", UPDATE)
        self.assertIn("grep -qx 'OWNED_UNIT_ONLINE_BRIDGE=1' \"$INSTALL_DIR/.conecta-install-manifest\"", UPDATE)

    def _sandbox_uninstaller(self, root):
        install_dir = root / "opt" / "sshpanel"
        systemd = root / "etc" / "systemd" / "system"
        bindir = root / "usr" / "local" / "bin"
        state_dir = root / "var" / "lib" / "conecta-ssh-pro"
        for p in (install_dir, systemd, bindir, state_dir):
            p.mkdir(parents=True, exist_ok=True)
        (install_dir / "certs").mkdir()
        (install_dir / "keys").mkdir()
        (install_dir / "logs").mkdir()
        (install_dir / ".env").write_text("PG_DSN=preserve-me\nADMIN_TOKEN=secret\n")
        (install_dir / "certs" / "fullchain.pem").write_text("CERTIFICATE")
        (install_dir / "keys" / "host.key").write_text("PRIVATE KEY")
        (install_dir / "logs" / "panel.log").write_text("important log")
        (install_dir / "database.dump").write_text("database backup")
        (install_dir / "conectassh_cli.py").write_text("#!/bin/sh\n")
        (install_dir / ".conecta-install-manifest").write_text(
            "PRODUCT=ConectaSSH-PRO\nMANIFEST_VERSION=3\nSTATE=installed\n"
            f"INSTALL_DIR={install_dir}\nINSTALL_ID=test-install-001\n"
            "DB_NAME=sshpanel\nDB_USER=sshpanel\nDB_CREATED_BY_CONECTA=0\n"
            "DB_ROLE_CREATED_BY_CONECTA=0\nOWNED_UNIT_SSH_PANEL=1\n"
            "OWNED_UNIT_ONLINE_BRIDGE=0\nOWNED_UNIT_DNSTT_REDIRECT=0\n"
            "OWNED_PATH_CLI_CONECTA=1\nOWNED_PATH_CLI_CONECTASSH=1\n"
        )
        os.chmod(install_dir / ".conecta-install-manifest", 0o600)
        unit = systemd / "sshpanel.service"
        unit.write_text(
            "[Service]\n"
            f"WorkingDirectory={install_dir}\n"
            f"ExecStart={install_dir}/sshpanel -config {install_dir}/config.json\n"
        )
        (install_dir / "sshpanel").write_text("binary")
        os.symlink(install_dir / "conectassh_cli.py", bindir / "conecta")
        os.symlink(install_dir / "conectassh_cli.py", bindir / "conectassh")
        (state_dir / "manifest").write_text(
            "PRODUCT=ConectaSSH-PRO\nMANIFEST_VERSION=3\nSTATE=installed\n"
            f"INSTALL_DIR={install_dir}\nINSTALL_DIR_CREATED=1\n"
        )
        os.chmod(state_dir / "manifest", 0o600)

        # Rewrite every absolute operational path into this fixture and use a
        # fake systemctl so no host service can be affected by the test.
        script = UNINSTALL
        replacements = (
            ("/opt/sshpanel", str(install_dir)),
            ("/etc/systemd/system", str(systemd)),
            ("/usr/local/bin", str(bindir)),
            ("/var/lib/conecta-ssh-pro", str(state_dir)),
            ("/var/tmp/conecta-ssh-pro-logs", str(root / "var" / "tmp" / "logs")),
        )
        for old, new in replacements:
            script = script.replace(old, new)
        script_path = root / "uninstall-test.sh"
        script_path.write_text(script)
        fakebin = root / "fakebin"
        fakebin.mkdir()
        fake_systemctl = fakebin / "systemctl"
        fake_systemctl.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TEST_SYSTEMCTL_LOG\"\nexit 0\n")
        fake_systemctl.chmod(0o755)
        return install_dir, systemd, bindir, state_dir, script_path, fakebin, fake_systemctl

    def test_uninstall_preserves_credentials_certs_keys_logs_and_data_by_default(self):
        with tempfile.TemporaryDirectory(prefix="conecta-uninstall-preserve-") as td:
            root = pathlib.Path(td)
            install_dir, systemd, bindir, state_dir, script_path, fakebin, _ = self._sandbox_uninstaller(root)
            env = os.environ.copy()
            env.update(PATH=f"{fakebin}:{env['PATH']}", CONFIRM="YES", TEST_SYSTEMCTL_LOG=str(root / "systemctl.log"))
            result = run(["bash", str(script_path)], env=env)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(install_dir.exists())
            preserved = list((root / "opt").glob("sshpanel.preserved.*"))
            self.assertEqual(len(preserved), 1)
            p = preserved[0]
            self.assertEqual((p / ".env").read_text(), "PG_DSN=preserve-me\nADMIN_TOKEN=secret\n")
            self.assertEqual((p / "certs" / "fullchain.pem").read_text(), "CERTIFICATE")
            self.assertEqual((p / "keys" / "host.key").read_text(), "PRIVATE KEY")
            self.assertEqual((p / "logs" / "panel.log").read_text(), "important log")
            self.assertEqual((p / "database.dump").read_text(), "database backup")
            self.assertFalse((systemd / "sshpanel.service").exists())
            self.assertFalse((bindir / "conecta").exists())
            self.assertFalse((bindir / "conectassh").exists())
            self.assertIn("STATE=preserved", (state_dir / "manifest").read_text())
            log = (root / "systemctl.log").read_text()
            self.assertIn("disable --now sshpanel.service", log)
            self.assertNotRegex(log, r"\bsshd?\b")

    def test_purge_requires_flag_and_removes_only_sandbox_product_payload(self):
        with tempfile.TemporaryDirectory(prefix="conecta-uninstall-purge-") as td:
            root = pathlib.Path(td)
            install_dir, systemd, bindir, state_dir, script_path, fakebin, _ = self._sandbox_uninstaller(root)
            env = os.environ.copy()
            env.update(PATH=f"{fakebin}:{env['PATH']}", CONFIRM="YES", TEST_SYSTEMCTL_LOG=str(root / "systemctl.log"))
            result = run(["bash", str(script_path), "--purge"], env=env)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(install_dir.exists())
            self.assertFalse((systemd / "sshpanel.service").exists())
            self.assertFalse((bindir / "conecta").exists())
            self.assertIn("STATE=uninstalled", (state_dir / "manifest").read_text())

    def test_corrupt_install_recovery_preserves_data_and_clears_owned_cli(self):
        with tempfile.TemporaryDirectory(prefix="conecta-corrupt-recovery-") as td:
            root = pathlib.Path(td)
            install_dir = root / "opt" / "sshpanel"
            state_dir = root / "var" / "lib" / "conecta-ssh-pro"
            bindir = root / "usr" / "local" / "bin"
            systemd = root / "etc" / "systemd" / "system"
            for p in (install_dir, state_dir, bindir, systemd):
                p.mkdir(parents=True, exist_ok=True)
            (install_dir / ".env").write_text("credential=keep\n")
            (install_dir / ".conecta-install-manifest").write_text(
                "PRODUCT=ConectaSSH-PRO\nMANIFEST_VERSION=3\nSTATE=installed\n"
                f"INSTALL_DIR={install_dir}\n"
            )
            os.chmod(install_dir / ".conecta-install-manifest", 0o600)
            (install_dir / "conectassh_cli.py").write_text("#!/bin/sh\n")
            (state_dir / "manifest").write_text(
                "PRODUCT=ConectaSSH-PRO\nMANIFEST_VERSION=3\nSTATE=installed\n"
                f"INSTALL_DIR={install_dir}\nINSTALL_DIR_CREATED=1\n"
            )
            os.chmod(state_dir / "manifest", 0o600)
            os.symlink(install_dir / "conectassh_cli.py", bindir / "conecta")
            start = INSTALL.index("recover_corrupt_install() {")
            end = INSTALL.index("\npreflight_checks() {", start)
            helper = INSTALL[start:end]
            for old_path, new_path in (
                ("/opt/sshpanel", str(install_dir)),
                ("/etc/systemd/system", str(systemd)),
                ("/usr/local/bin", str(bindir)),
                ("/var/lib/conecta-ssh-pro", str(state_dir)),
            ):
                helper = helper.replace(old_path, new_path)
            fakebin = root / "fakebin"
            fakebin.mkdir()
            fake = fakebin / "systemctl"
            fake.write_text("#!/bin/sh\n[ \"$1\" = is-active ] && exit 1\nexit 0\n")
            fake.chmod(0o755)
            harness = root / "recover.sh"
            harness.write_text(
                "set -euo pipefail\n"
                f'INSTALL_DIR="{install_dir}"\nTXN_MANIFEST="{state_dir / "manifest"}"\n'
                f'RESOURCE_LEDGER="{state_dir / "resources.tsv"}"\n'
                'warn(){ echo "WARN: $*"; }\nerror(){ echo "ERROR: $*" >&2; exit 1; }\n'
                + helper + "\nrecover_corrupt_install\n"
            )
            env = os.environ.copy()
            env["PATH"] = f"{fakebin}:{env['PATH']}"
            result = run(["bash", str(harness)], env=env)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(install_dir.exists())
            self.assertFalse((bindir / "conecta").exists())
            recovery = list((root / "opt").glob("sshpanel.recovery.*"))
            self.assertEqual(len(recovery), 1)
            self.assertEqual((recovery[0] / ".env").read_text(), "credential=keep\n")
            self.assertIn("STATE=preserved", (state_dir / "manifest").read_text())

    def test_transaction_manifest_clean_install_rollback_and_reinstall(self):
        with tempfile.TemporaryDirectory(prefix="conecta-transaction-") as td:
            root = pathlib.Path(td)
            install_dir = root / "opt" / "sshpanel"
            state_dir = root / "var" / "lib" / "conecta-ssh-pro"
            systemd = root / "etc" / "systemd" / "system"
            bindir = root / "usr" / "local" / "bin"
            cli_path = install_dir / "conectassh_cli.py"
            conecta_path = bindir / "conecta"
            unit_path = systemd / "sshpanel.service"
            for p in (state_dir, systemd, bindir):
                p.mkdir(parents=True, exist_ok=True)
            start = INSTALL.index("write_transaction_manifest() {")
            end = INSTALL.index("\npreflight_checks() {", start)
            helpers = INSTALL[start:end]
            for old, new in (
                ("/var/lib/conecta-ssh-pro", str(state_dir)),
                ("/opt/sshpanel", str(install_dir)),
                ("/etc/systemd/system", str(systemd)),
                ("/usr/local/bin", str(bindir)),
            ):
                helpers = helpers.replace(old, new)
            fakebin = root / "fakebin"
            fakebin.mkdir()
            fake = fakebin / "systemctl"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            harness = root / "harness.sh"
            harness.write_text(
                "set -euo pipefail\n"
                f'INSTALL_ID="test-{root.name}"\nSTATE_DIR="{state_dir}"\n'
                f'TXN_MANIFEST="$STATE_DIR/manifest"\nRESOURCE_LEDGER="$STATE_DIR/resources.tsv"\n'
                f'INSTALL_DIR_CREATED=1\nDB_CREATED_BY_CONECTA=0\nDB_ROLE_CREATED_BY_CONECTA=0\nROLLBACK_DIR=""\n'
                'warn(){ echo "WARN: $*"; }\n'
                + helpers
                + "\n: > \"$RESOURCE_LEDGER\"\n"
                + 'write_transaction_manifest installing\n'
                + f'register_resource directory "{install_dir}"\n'
                + f'mkdir -p "{install_dir}"\n'
                + f'register_resource symlink "{conecta_path}" "{cli_path}"\n'
                + f'echo "#!/bin/sh" > "{cli_path}"\n'
                + f'ln -s "{cli_path}" "{conecta_path}"\n'
                + f'register_resource unit "{unit_path}"\n'
                + f'echo "[Service]" > "{unit_path}"\n'
                + f'echo "WorkingDirectory={install_dir}" >> "{unit_path}"\n'
                + f'echo "ExecStart={install_dir}/sshpanel -config {install_dir}/config.json" >> "{unit_path}"\n'
                + 'write_transaction_manifest rollback_pending\n'
                + 'rollback_transaction_resources\n'
                + f'test ! -e "{install_dir}"\n'
                + f'test ! -e "{unit_path}"\n'
                + f': > "$RESOURCE_LEDGER"\n'
                + f'register_resource directory "{install_dir}"\n'
                + f'mkdir -p "{install_dir}"\n'
                + 'write_transaction_manifest installed\n'
                + f'test -d "{install_dir}"\n'
                + 'grep -qx "STATE=installed" "$TXN_MANIFEST"\n'
            )
            env = os.environ.copy()
            env["PATH"] = f"{fakebin}:{env['PATH']}"
            result = run(["bash", str(harness)], env=env)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertTrue(install_dir.is_dir())
            self.assertIn("STATE=installed", (state_dir / "manifest").read_text())


if __name__ == "__main__":
    unittest.main()
