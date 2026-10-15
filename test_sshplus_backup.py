import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

MODULE = Path(__file__).with_name("sshplus_backup.py")
spec = importlib.util.spec_from_file_location("sshplus_backup_test_module", MODULE)
sshplus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sshplus)


def make_backup(path, count=95, include_root=False):
    members = {
        "root/usuarios.db": "",
        "etc/passwd": "",
        "etc/shadow": "",
    }
    rows, passwd, shadow = [], [], []
    names = ["root"] if include_root else []
    names += [f"user{i:03d}" for i in range(count)]
    for index, username in enumerate(names):
        rows.append(f"{username} {index + 1}")
        passwd.append(f"{username}:x:{2000+index}:{2000+index}::/home/{username}:/bin/false")
        # Keep no expiry for this fixture; tests focus on safe selection.
        shadow.append(f"{username}:$6$hash:20000:0:99999:7:::")
        members[f"etc/SSHPlus/senha/{username}"] = f"pw-{username}\n"
    members["root/usuarios.db"] = "\n".join(rows) + "\n"
    members["etc/passwd"] = "\n".join(passwd) + "\n"
    members["etc/shadow"] = "\n".join(shadow) + "\n"
    with tarfile.open(path, "w") as archive:
        for name, data in members.items():
            raw = data.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


class SSHPlusBackupSafetyTest(unittest.TestCase):
    def test_inspection_detects_exactly_95_without_showing_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.vps"
            make_backup(path)
            output = io.StringIO()
            with redirect_stdout(output):
                sshplus.inspect(path)
            rendered = output.getvalue()
            self.assertIn('"users_found": 95', rendered)
            self.assertIn('"ready": true', rendered)
            self.assertNotIn("pw-user", rendered)
            users, _, _ = sshplus._archive_data(path)
            self.assertEqual(len(users), 95)
            self.assertEqual(users[0]["max_connections"], 1)

    def test_root_is_never_imported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.vps"
            make_backup(path, count=94, include_root=True)
            users, _, _ = sshplus._archive_data(path)
            self.assertEqual(len(users), 94)
            self.assertNotIn("root", {user["username"] for user in users})

    def test_restore_accepts_large_user_counts_and_sends_batches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.vps"
            make_backup(path, count=450)
            calls = []
            def fake_req(method, route, data, timeout=120):
                calls.append(data["users"])
                return {"restored": len(data["users"]), "total": len(data["users"])}
            with patch.object(sshplus, "req", side_effect=fake_req):
                output = io.StringIO()
                with redirect_stdout(output):
                    sshplus.restore(path)
            self.assertEqual(sum(len(batch) for batch in calls), 450)
            self.assertGreater(len(calls), 1)
            self.assertTrue(all(len(batch) <= sshplus.RESTORE_BATCH_SIZE for batch in calls))
            self.assertIn("USUARIOS_RESTAURADOS 450", output.getvalue())

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.vps"
            with tarfile.open(path, "w") as archive:
                link = tarfile.TarInfo("etc/shadow")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/shadow"
                archive.addfile(link)
            with self.assertRaisesRegex(ValueError, "enlaces"):
                sshplus._archive_data(path)


if __name__ == "__main__":
    unittest.main()
