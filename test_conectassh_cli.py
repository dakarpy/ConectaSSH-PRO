import importlib.util
import copy
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


MODULE = Path(__file__).with_name("conectassh_cli.py")
spec = importlib.util.spec_from_file_location("test_conectassh_cli", MODULE)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class WebsocketPort80MenuTest(unittest.TestCase):
    def test_activate_port80_preserves_other_extra_listeners(self):
        config = {"listen": "0.0.0.0:443", "extra_listen": ["0.0.0.0:8080", "0.0.0.0:80"]}
        with patch.object(cli, "request", return_value=config), patch.object(cli, "save_settings") as save:
            with redirect_stdout(io.StringIO()):
                cli.websocket_port80_activate()
        saved = save.call_args.args[1]
        self.assertEqual(saved["listen"], "0.0.0.0:80")
        self.assertEqual(saved["extra_listen"], ["0.0.0.0:8080"])

    def test_deactivate_main_port80_preserves_8080(self):
        config = {"listen": "0.0.0.0:80", "extra_listen": ["0.0.0.0:8080"]}
        with patch.object(cli, "request", return_value=config), patch.object(cli, "save_settings") as save:
            with redirect_stdout(io.StringIO()):
                cli.websocket_port80_deactivate()
        saved = save.call_args.args[1]
        self.assertEqual(saved["listen"], "disabled")
        self.assertEqual(saved["extra_listen"], ["0.0.0.0:8080"])

    def test_websocket_menu_exposes_activate_deactivate_and_status(self):
        with patch.object(cli, "menu") as menu:
            cli.websocket_menu()
        options = menu.call_args.args[1]
        self.assertIn("ACTIVAR PUERTO 80", options["2"][0])
        self.assertIn("DESACTIVAR PUERTO 80", options["3"][0])
        self.assertIn("ESTADO DEL PUERTO 80", options["4"][0])


class TokenManagementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = Path(self.temp.name) / ".env"
        env.write_text("PG_DSN=test\nADMIN_TOKEN=" + "a" * 48 + "\nADMIN_HTTP_ADDR=127.0.0.1:9090\n")
        env.chmod(0o600)
        self.path = env
        patcher = patch.object(cli, "ENV_FILE", env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_rotation_preserves_other_env_and_never_prompts(self):
        with patch.object(cli, "service_action") as service, patch.object(cli, "request", return_value=[]):
            with patch("builtins.input", side_effect=AssertionError("prompted")):
                with redirect_stdout(io.StringIO()):
                    cli.rotate_api_password()
        self.assertNotEqual(cli.api_password(), "a" * 48)
        self.assertIn("PG_DSN=test\n", self.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        service.assert_called_once_with("restart")

    def test_failed_rotation_restores_previous_token(self):
        with patch.object(cli, "service_action", side_effect=[None, None]), \
                patch.object(cli, "request", side_effect=cli.CLIError("bad API")), \
                patch.object(cli.time, "sleep"):
            with self.assertRaises(cli.CLIError):
                cli.rotate_api_password()
        self.assertEqual(cli.api_password(), "a" * 48)

    def test_live_vps_header_counts_users_and_rates(self):
        responses = [
            {"cpu_percent": 12.5, "mem_total_bytes": 8 * 1024**3,
             "mem_used_bytes": 2 * 1024**3,
             "interfaces": [{"rx_mbps": 18.5, "tx_mbps": 4.2}]},
            [{"username": "alice", "active_conns": 2, "expires_at": "2099-01-01T00:00:00Z"},
             {"username": "bob", "active_conns": 0, "expires_at": "2020-01-01T00:00:00Z"}],
            {"online_users": 3},
        ]
        with patch.object(cli, "request", side_effect=responses), \
                patch.object(cli.shutil, "disk_usage", return_value=SimpleNamespace(used=50, total=100)), \
                patch.object(cli.subprocess, "run", return_value=SimpleNamespace(stdout="active\n")):
            status = cli.collect_vps_status()
        header = cli.render_vps_status(status)
        self.assertIn("12.5%", header)
        self.assertIn("1 conectados  |  1 vencidos  |  2 total", header)
        self.assertIn("Xray: 3 conectados", header)
        self.assertIn("18.50 Mbps", header)
        self.assertEqual(len({len(row) for row in header.splitlines()}), 1)
        with patch.object(cli, "request", return_value={"auto_menu": False}):
            menu_text = cli.render_menu(
                "MAIN MENU", cli.main_menu_options(), status
            )
            mobile = cli.render_menu(
                "MAIN MENU", cli.main_menu_options(), status, columns=40
            )
        self.assertIn("MODO DE CONEXIÓN", menu_text)
        self.assertNotIn("Resellers", menu_text)
        self.assertLessEqual(max(map(len, mobile.splitlines())), 40)
        self.assertIn("CPU: 2 (12.5%", mobile)
        self.assertIn("Onlines: 1", mobile)

    def test_menu_clears_on_open_and_redraw_after_output_pause(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(output, "isatty", return_value=True), \
                patch.object(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
                patch("builtins.input", side_effect=["1", "", "0"]) as ask:
            cli.menu("TEST", {"1": ("Show result", lambda: print("RESULT"))})
        self.assertEqual(output.getvalue().count("\033[2J\033[H"), 2)
        self.assertIn("RESULT", output.getvalue())
        self.assertIn("Presioná Enter para volver al menú", ask.call_args_list[1].args[0])

    def test_returning_from_submenu_redraws_without_extra_pause(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(output, "isatty", return_value=True), \
                patch.object(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
                patch("builtins.input", side_effect=["1", "0", "0"]) as ask:
            cli.menu("PARENT", {"1": ("Submenu", lambda: cli.menu("CHILD", {}))})
        self.assertEqual(ask.call_count, 3)
        self.assertEqual(output.getvalue().count("\033[2J\033[H"), 3)

    def test_menu_refreshes_dynamic_options_after_a_change(self):
        calls = []
        def options():
            calls.append(True)
            return {"1": ("New" if len(calls) > 1 else "Old", lambda: None)}
        with patch("builtins.input", side_effect=["1", "0"]), redirect_stdout(io.StringIO()) as output:
            cli.menu("TEST", options)
        self.assertEqual(len(calls), 2)
        self.assertIn("NEW", output.getvalue())

    def test_server_setting_updates_one_field_and_keeps_other_blocks(self):
        config = {"listen": "0.0.0.0:80", "extra_listen": [],
                  "users": [{"username": "alice"}], "bhttp": {"shared_ports": True}}
        writes = []
        def fake_request(method, path, data=None):
            if method == "GET":
                return copy.deepcopy(config)
            writes.append((path, data))
            return {"warnings": []}
        with patch.object(cli, "request", side_effect=fake_request), \
                patch.object(cli, "ask", return_value="0.0.0.0:8080"), \
                redirect_stdout(io.StringIO()):
            cli.edit_field("/api/server/config", cli.SSH_FIELDS[0])
        self.assertEqual(writes[0][1]["listen"], "0.0.0.0:8080")
        self.assertEqual(writes[0][1]["users"], config["users"])
        self.assertEqual(writes[0][1]["bhttp"], config["bhttp"])

    def test_protocol_can_be_enabled_through_menu_fields(self):
        config = {"listen": "0.0.0.0:80", "hcr": None}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(config), {"ok": True}]) as request, \
                redirect_stdout(io.StringIO()):
            cli.toggle_block("hcr")
        payload = request.call_args.args[2]
        self.assertEqual(payload["hcr"]["listen"], ["0.0.0.0:8880"])

    def test_bot_setting_keeps_existing_token_flags(self):
        bot = {"enabled": True, "has_telegram_token": True, "telegram_token": "",
               "trial_hours": 1, "mp_confirm_mode": "polling"}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(bot), {"ok": True}]) as request, \
                patch.object(cli, "number", return_value=24), redirect_stdout(io.StringIO()):
            cli.edit_field("/api/bot/config", ("trial_hours", "Trial hours", "int"))
        self.assertEqual(request.call_args.args[2]["trial_hours"], 24)
        self.assertTrue(request.call_args.args[2]["has_telegram_token"])

    def test_new_xray_inbound_uses_next_available_port(self):
        config = {"inbounds": [{"tag": "vless-in", "port": 10086}]}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(config), None]) as request, \
                patch.object(cli, "ask", side_effect=["new-in", "vless", "0.0.0.0", "tcp"]), \
                patch.object(cli, "number", side_effect=lambda label, default, *_: default), \
                redirect_stdout(io.StringIO()):
            cli.xray_inbound_add()
        inbound = request.call_args.args[2]["inbounds"][1]
        self.assertEqual(inbound["port"], 10087)
        self.assertEqual(inbound["streamSettings"]["network"], "tcp")
        self.assertTrue(inbound["settings"]["clients"][0]["id"])

    def test_configuration_entries_open_guided_menus(self):
        with patch.object(cli, "menu") as open_menu:
            cli.config_menu()
            config = open_menu.call_args.args[1]
            self.assertIs(config["4"][1], cli.multi_protocol_menu)
            self.assertIs(config["5"][1], cli.xray_settings_menu)
            self.assertIs(config["6"][1], cli.bot_settings_menu)
            cli.connection_menu()
            self.assertIs(open_menu.call_args.args[1]["3"][1], cli.protocol_stats)
            cli.xray_menu()
            self.assertIs(open_menu.call_args.args[1]["7"][1], cli.xray_settings_menu)

    def test_check_for_update_detects_matching_remote_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cli, "INSTALL_DIR", Path(directory)), \
                    patch.object(cli.subprocess, "run", return_value=type("Result", (), {
                        "returncode": 0, "stdout": "abc123 refs/heads/main\n", "stderr": ""})()):
                (Path(directory) / ".installed_commit").write_text("abc123\n", encoding="utf-8")
                self.assertFalse(cli.check_for_update())

    def test_check_for_update_detects_new_remote_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cli, "INSTALL_DIR", Path(directory)), \
                    patch.object(cli.subprocess, "run", return_value=type("Result", (), {
                        "returncode": 0, "stdout": "def456 refs/heads/main\n", "stderr": ""})()):
                (Path(directory) / ".installed_commit").write_text("abc123\n", encoding="utf-8")
                self.assertTrue(cli.check_for_update())

    def test_user_backup_menu_is_unique_and_points_to_conecta_backup_flow(self):
        with patch.object(cli, "request", return_value={"auto_menu": False}):
            self.assertIs(cli.main_menu_options()["6"][1], cli.user_backup_menu)
        self.assertEqual(cli.user_backup_menu.__code__.co_filename, str(MODULE))

    def test_backup_is_gzip_atomic_and_mode_600(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ConectaSSH-backup-test.json.gz"
            document = {"format": "conecta-ssh-backup", "version": 2,
                        "ssh": {"users": [{"username": "alice"}]},
                        "xray": {"config": {"inbounds": []}}}
            cli._write_backup_atomic(target, document)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(cli._read_backup_document(target), document)
            self.assertFalse(list(Path(directory).glob("*.tmp")))

    def test_backup_creation_uses_compression_and_secure_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "backup.json.gz"
            with patch.object(cli, "require_root"), \
                    patch.object(cli, "backup_users_file_path", return_value=target), \
                    patch.object(cli, "request", side_effect=[
                        {"users": [{"username": "alice"}]},
                        {"inbounds": []},
                    ]), redirect_stdout(io.StringIO()):
                cli.backup_users()
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with gzip.open(target, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["ssh"]["users"][0]["username"], "alice")

    def test_guided_config_labels_fit_mobile_width(self):
        options = {str(i): (field[1], lambda: None) for i, field in enumerate(cli.SSH_FIELDS, 1)}
        self.assertLessEqual(max(map(len, cli.render_menu("SSH SETTINGS", options, columns=40).splitlines())), 40)

    def test_long_mobile_settings_menu_has_pages(self):
        chosen = []
        options = {str(i): (f"Setting {i}", lambda value=i: chosen.append(value)) for i in range(1, 21)}
        with patch.object(cli, "terminal_columns", return_value=40), \
                patch("builtins.input", side_effect=["n", "11", "0"]), \
                redirect_stdout(io.StringIO()) as output:
            cli.menu("SETTINGS", options)
        self.assertEqual(chosen, [11])
        self.assertIn("SETTING 11", output.getvalue())

    def test_user_list_fits_phone_terminal(self):
        users = [{"username": "account-with-a-long-name", "active_conns": 2,
                  "max_connections": 5, "total_bytes": 1234567,
                  "expires_at": "2099-05-01T12:00:00Z"}]
        with patch.object(cli, "request", return_value=users), \
                patch.object(cli, "terminal_columns", return_value=40), \
                redirect_stdout(io.StringIO()) as output:
            cli.list_users()
        self.assertLessEqual(max(map(len, output.getvalue().splitlines())), 40)

    def test_shared_xray_generates_path_without_password_prompt(self):
        server = {"listen": "0.0.0.0:80", "tls_forwarders": [{"listen": "0.0.0.0:443"}],
                  "xray": {"mode": "native"}}
        config = {"inbounds": [{"tag": "first", "protocol": "vless", "dragoncoreSharedPort": True,
                                "streamSettings": {"network": "ws", "wsSettings": {"path": "/c1"}}}]}
        calls = []

        def fake_request(method, path, data=None):
            calls.append((method, path, data))
            if path == "/api/server/config":
                return server
            if path == "/api/xray/config" and method == "GET":
                return config
            if path == "/api/xray/status":
                return {"running": False}
            return None

        # The flow asks only for the tag, transport, path, protocol, and consent.
        with patch.object(cli, "request", side_effect=fake_request), \
                patch("builtins.input", side_effect=["second", "", "", "", "SI"]), \
                redirect_stdout(io.StringIO()):
            cli.xray_shared_port()
        new = config["inbounds"][1]
        self.assertEqual(new["streamSettings"]["wsSettings"]["path"], "/c2")
        self.assertEqual(new["streamSettings"]["security"], "none")
        self.assertTrue(new["dragoncoreSharedPort"])
        self.assertEqual([item[1] for item in calls[-3:]],
                         ["/api/xray/config", "/api/xray/status", "/api/xray/start"])

    def test_shared_xray_rejects_external_mode(self):
        with patch.object(cli, "request", return_value={"xray": {"mode": "external"}}), \
                patch("builtins.input", side_effect=AssertionError("prompted")):
            with self.assertRaisesRegex(cli.CLIError, "nativo"):
                cli.xray_shared_port()

    def test_xray_client_id_is_displayed_and_editable(self):
        inbounds = [{"tag": "vless", "protocol": "vless", "clients": [
            {"id": "client-uuid", "name": "alice", "max_conns": 2}
        ]}]
        with patch.object(cli, "request", return_value=inbounds) as request, \
                patch.object(cli, "ask", side_effect=["client-uuid", "2"]), \
                patch.object(cli, "number", return_value=3), \
                redirect_stdout(io.StringIO()) as output:
            cli.xray_inbounds()
            cli.xray_edit()
        self.assertIn("client-uuid", output.getvalue())
        self.assertEqual(request.call_args.args[:2], ("POST", "/api/xray/clients/update"))
        self.assertEqual(request.call_args.args[2]["uuid"], "client-uuid")

    def test_public_ports_accept_port_only_and_normalize_to_all_interfaces(self):
        self.assertEqual(cli.normalize_public_endpoint("8080"), "0.0.0.0:8080")
        self.assertEqual(cli.normalize_public_endpoint("65535"), "0.0.0.0:65535")
        self.assertEqual(cli.normalize_public_endpoint("0.0.0.0:443"), "0.0.0.0:443")
        self.assertEqual(
            cli.normalize_public_endpoints(["8080", "0.0.0.0:8443"]),
            ["0.0.0.0:8080", "0.0.0.0:8443"],
        )
        with self.assertRaises(cli.CLIError):
            cli.normalize_public_endpoint("65536")

    def test_tls_listener_add_accepts_port_only(self):
        cfg = {"tls_forwarders": []}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(cfg), None]) as request, \
                patch.object(cli, "ask", return_value="8443"), \
                patch.object(cli, "select_certificate", return_value=("/cert.pem", "/key.pem")), \
                redirect_stdout(io.StringIO()):
            cli.tls_listener_add()
        self.assertEqual(request.call_args.args[2]["tls_forwarders"][0]["listen"], "0.0.0.0:8443")

    def test_ssh_ports_accept_port_only_for_main_and_secondary(self):
        cfg = {"listen": "0.0.0.0:80", "extra_listen": ["0.0.0.0:8080"], "users": []}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(cfg), None]) as request, \
                patch.object(cli, "ask", return_value="443"), \
                patch("builtins.input", side_effect=["8081, 8082"]), \
                redirect_stdout(io.StringIO()):
            cli.set_ssh_ports()
        payload = request.call_args.args[2]
        self.assertEqual(payload["listen"], "0.0.0.0:443")
        self.assertEqual(payload["extra_listen"], ["0.0.0.0:8081", "0.0.0.0:8082"])

    def test_ssh_main_port_can_be_disabled_without_disabling_extra_ports(self):
        cfg = {"listen": "0.0.0.0:80", "extra_listen": ["0.0.0.0:8080"], "users": []}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(cfg), None]) as request, \
                patch.object(cli, "ask", return_value="-"), \
                patch("builtins.input", side_effect=[""]), \
                redirect_stdout(io.StringIO()):
            cli.set_ssh_ports()
        payload = request.call_args.args[2]
        self.assertEqual(payload["listen"], "disabled")
        self.assertEqual(payload["extra_listen"], ["0.0.0.0:8080"])

    def test_ssh_main_port_can_be_reenabled(self):
        cfg = {"listen": "disabled", "extra_listen": ["0.0.0.0:8080"], "users": []}
        with patch.object(cli, "request", side_effect=[copy.deepcopy(cfg), None]) as request, \
                patch.object(cli, "ask", return_value="80"), \
                patch("builtins.input", side_effect=[""]), \
                redirect_stdout(io.StringIO()):
            cli.set_ssh_ports()
        payload = request.call_args.args[2]
        self.assertEqual(payload["listen"], "0.0.0.0:80")
        self.assertEqual(payload["extra_listen"], ["0.0.0.0:8080"])

    def test_git_update_uses_installed_updater_without_prompt(self):
        updater = Path(self.temp.name) / "update.sh"
        updater.write_text("#!/bin/bash\n")
        with patch.object(cli, "INSTALL_DIR", Path(self.temp.name)), \
                patch.object(cli.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch("builtins.input", side_effect=AssertionError("prompted")), \
                redirect_stdout(io.StringIO()):
            cli.update_from_git()
        run.assert_called_once_with(["bash", str(updater)], check=False)


class AutoConfigurePreflightTest(unittest.TestCase):
    def test_occupied_default_port_blocks_configuration_without_prompting(self):
        occupied = SimpleNamespace(
            returncode=0,
            stdout='LISTEN 0 4096 *:80 *:* users:(("nginx",pid=4321,fd=7))\n',
            stderr="",
        )
        free = SimpleNamespace(returncode=0, stdout="", stderr="")
        responses = [occupied, free, free, free, free, free]
        with patch.object(cli.subprocess, "run", side_effect=responses) as run:
            with patch("builtins.input", side_effect=AssertionError("must not prompt")):
                with redirect_stdout(io.StringIO()) as output:
                    cli.auto_configure()
        text = output.getvalue()
        self.assertIn("TCP/80", text)
        self.assertIn("OCUPADO por nginx (PID 4321)", text)
        self.assertIn("NO SE PUEDE CONTINUAR", text)
        self.assertIn("Libere los puertos marcados", text)
        self.assertIn("No se realizaron cambios", text)
        self.assertEqual(run.call_count, 6)
        with patch.object(cli, "request", return_value={"auto_menu": False}):
            self.assertIn("AUTO CONFIGURAR", cli.main_menu_options()["12"][0])

    def test_free_ports_do_not_claim_activation_was_completed(self):
        free = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(cli.subprocess, "run", return_value=free):
            with redirect_stdout(io.StringIO()) as output:
                cli.auto_configure()
        self.assertIn("Todos los puertos están disponibles", output.getvalue())
        self.assertIn("La activación no se ejecutó", output.getvalue())


if __name__ == "__main__":
    unittest.main()
