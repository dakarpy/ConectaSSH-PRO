# ConectaSSH-PRO CLI

ConectaSSH-PRO is an independent Linux server script with a terminal command menu and an HTTP API. It manages SSH accounts, native Xray clients and inbounds, connection protocols, TLS certificates, VPS traffic, and a Telegram sales bot. There is no web administration panel. Run the menu as root; it reads the local API credential and never asks the operator for a login or password. The menu is designed for mobile SSH terminals and shows live VPS status at the top.

## Install

On a fresh Linux server with systemd, clone this repository and run the installer:

```bash
git clone https://github.com/dakarpy/ConectaSSH-PRO.git
cd ConectaSSH-PRO
sudo bash install.sh
sudo menu
```

The installer installs required packages, Go, PostgreSQL, Xray, the `sshpanel` systemd service, and the `menu` command. It generates service credentials and writes configuration under `/opt/sshpanel`. It needs network access for system packages, Go, and Xray. An extracted source archive can be installed with `sudo bash install.sh` from its root. If `/usr/local/bin/menu` already exists, the installer saves a timestamped backup before replacing it. Use a fresh server because installation creates new database and configuration credentials.

Run `sudo menu` for the command menu. `sudo conectassh` is an alias for the same administration CLI. The header shows CPU, RAM, disk, uptime, network traffic, SSH and Xray activity, and service status. Each menu redraw clears the visible terminal; after a command prints results, press Enter to return to the menu. The menu adjusts to narrow terminals; `sudo menu --mobile` forces the compact layout, or set `CONECTASSH_COLUMNS=36`. Long menus have `n`/`p` page navigation. Configuration uses guided fields instead of opening a JSON editor.

| Command | Purpose |
| --- | --- |
| `sudo menu` | Interactive command menu |
| `sudo menu status` | VPS and service status |
| `sudo menu users` | SSH users |
| `sudo menu logs` | Service logs |
| `sudo menu update` | Update from the Git repository |
| `sudo menu api-password show` | Reveal the local API password to root |
| `sudo menu api-password change` | Generate, install, and verify a new API password |

The CLI generates SSH account passwords and Xray UUIDs when creating them. It does not request any password from the person using the menu. API clients may supply credentials in their requests where an endpoint requires them. Reseller administration is handled in the Telegram bot; there is no reseller menu.

## Updates and files

`sudo menu update` (or `sudo bash /opt/sshpanel/update.sh`) fetches the default branch from `https://github.com/dakarpy/ConectaSSH-PRO.git`, builds it, and restarts the service. Set `UPDATE_REF=branch-name` to choose a branch. From a local checkout or extracted source release, run `sudo env UPDATE_SOURCE=local bash update.sh`. The updater preserves the installed `.env`, `config.json`, `xray_config.json`, SSH keys, certificates, accounts, and PostgreSQL database. The previous binary is kept as `/opt/sshpanel/sshpanel.bak`.

| Location | Purpose |
| --- | --- |
| `/opt/sshpanel/.env` | Local service and API secrets; root access only |
| `/opt/sshpanel/config.json` | SSH, listener, and protocol configuration |
| `/opt/sshpanel/xray_config.json` | Native Xray configuration |
| `/opt/sshpanel/certs/` | Managed TLS certificates |
| `/etc/systemd/system/sshpanel.service` | Service unit |
| `/usr/local/bin/menu` | Terminal command |

## Menu features

- **SSH users:** create and list accounts, 24-hour trials, renew or edit limits, inspect online usage and speed, reset traffic, remove individual or expired users.
- **Xray:** manage inbounds and clients, generate UUIDs, adjust limits and quotas, reset traffic, edit JSON, control the service, and configure shared listener ports.
- **Connection modes:** inspect SSH/TLS, DNSTT, BHTTP, BTUN, HCR, UDPGW, and Xray status, settings, and available logs; manage TLS certificates and DNSTT keys.
- **VPS and traffic:** CPU, RAM, storage, uptime, per-interface traffic, daily/monthly totals, system logs, and update status.
- **Configuration and service:** guided SSH, TLS, DNSTT, BHTTP, BTUN, HCR, UDPGW, Xray, and bot settings; managed server overview and settings; service controls and API password rotation. Existing remote server credentials can be retained while editing. Adding a remote server requires its credential through the authenticated API.

## HTTP API

A fresh install binds the API to `http://127.0.0.1:9090` (`ADMIN_HTTP_ADDR` in `.env`). The root path has no browser UI. All request bodies below are JSON unless stated otherwise. Write operations ordinarily return JSON or an empty success response; errors use HTTP error status codes. Do not publish the HTTP listener openly: when remote API access is needed, place it behind TLS and restrict access.

**Authentication:** `Authorization: Bearer <API password>` supplies the local superadmin credential (`ADMIN_TOKEN` in `.env`). Root can inspect or rotate it through `menu api-password`. Alternatively, `POST /api/auth/login` accepts an admin/reseller username and password and returns a session `token`; send it as `X-Session-Token: <token>`. Use `POST /api/auth/logout` with that header to revoke the session. In the tables, **session** means either a valid session token or the bearer API password; **admin** means superadmin only. A reseller session can use the permitted account APIs within its ownership and limits. The two public endpoints require neither header.

For local shell use, avoid putting the secret directly in command history:

```bash
TOKEN="$(sudo menu api-password show)"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9090/api/users
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9090/api/xray/inbounds
unset TOKEN
```

### Authentication and SSH accounts

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | Public | `{"username":"admin","password":"..."}`; returns `token`, `username`, `role` |
| POST | `/api/auth/logout` | Session | Revoke the `X-Session-Token` supplied in the request |
| GET | `/api/auth/me` | Session | Current identity, role, and reseller limits if applicable |
| GET | `/api/users` | Session | SSH users, connection counts, expiry, traffic, quotas, and ownership |
| POST | `/api/users/create` | Session | Create or edit SSH user; see payload below |
| POST | `/api/users/reset-traffic` | Session | `{"username":"alice"}`; optional `server_id` |
| DELETE | `/api/users/delete?username=alice` | Session | Delete user; optional `server_id` |

The SSH create/edit body supports `username`, `password`, `max_connections`, `expires_at` (RFC3339 or empty), `limit_mbps_up`, `limit_mbps_down`, `data_quota_bytes`, `quota_action`, `quota_throttle_mbps`, `reset_usage`, `totp_secret`, `totp_period`, `totp_window`, `totp_digits`, `allow_static_password`, `use_pam`, `owner_username`, and `server_id`. An omitted or empty password keeps the current password when editing; supply a generated password for a new account. The CLI generates it automatically.

```bash
curl -X POST http://127.0.0.1:9090/api/users/create \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"choose-a-generated-secret","max_connections":2,"expires_at":"2026-12-31T23:59:59Z"}'
```

### VPS, protocols, and logs

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| GET | `/api/stats` | Session | VPS metrics, network interfaces, and account activity |
| POST | `/api/stats/interfaces/reset` | Admin | Reset interface traffic counters |
| GET | `/api/vnstat?days=30&months=12` | Admin | Daily and monthly historical traffic |
| POST | `/api/vnstat/reset` | Admin | Reset historical traffic |
| GET | `/api/system/logs?source=panel&lines=100` | Admin | Logs; `source` also accepts `dnstt` or `xray` |
| POST | `/api/system/logs/reset` | Admin | Reset system logs |
| GET | `/api/system/update-status?refresh=1` | Admin | Git build/update information; `refresh=1` bypasses cache |
| GET | `/api/dnstt` | Admin | DNSTT status and statistics |
| GET | `/api/dnstt/logs` | Admin | DNSTT logs |
| GET | `/api/bhttp` | Admin | BHTTP status and statistics |
| GET | `/api/bhttp/logs` | Admin | BHTTP logs |
| GET | `/api/btun` | Admin | BTUN status and statistics |
| GET | `/api/btun/logs` | Admin | BTUN logs |
| GET | `/api/hcr` | Admin | HCR status and statistics |
| GET | `/api/hcr/logs` | Admin | HCR logs |
| POST | `/api/dnstt/genkey` | Admin | Generate a DNSTT key pair |
| GET | `/api/dnstt/pubkey` | Admin | Read DNSTT public key |

### Managed servers and configuration

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| GET | `/api/servers` | Session | Local and managed server list |
| POST | `/api/servers` | Admin | Create/update managed server; payload below |
| DELETE | `/api/servers?id=2` | Admin | Delete a managed server |
| POST | `/api/servers/test` | Admin | Test credentials using managed server payload |
| GET, POST | `/api/servers/config?server_id=2` | Admin | Read/write selected managed server configuration; `local` selects this host |
| GET, POST | `/api/server/config` | Admin | Read/write this host's complete `config.json` |
| GET | `/api/resellers` | Admin | List reseller API accounts |
| POST | `/api/resellers/create` | Admin | Create/update reseller account |
| DELETE | `/api/resellers/delete?username=name` | Admin | Delete reseller account |

Managed server JSON uses `id` (for updates), `name`, `base_url`, `admin_username`, `admin_key`, `enable_ssh`, `enable_xray`, and `is_active`. Configuration POST expects the server configuration JSON; read it with GET, modify the desired fields, and POST the resulting document. The CLI reads that document internally, changes the selected field, and saves it through the API. It presents menus instead of a JSON editor. Reseller routes remain available to the bot and other API integrations, while reseller management stays outside the CLI.

Reseller create/update JSON uses `username`, `password`, `max_users`, `expires_at` (RFC3339 or empty), and `is_active`. A new reseller requires a password in the API request; omitting it on an update leaves the existing password intact. The CLI never asks its operator for one.

### Xray

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| GET | `/api/xray/status` | Session | Xray mode and runtime status |
| POST | `/api/xray/start` | Admin | Start Xray |
| POST | `/api/xray/stop` | Admin | Stop Xray |
| POST | `/api/xray/restart` | Admin | Restart Xray |
| POST | `/api/xray/stats/repair` | Admin | Repair Xray statistics integration |
| GET, POST | `/api/xray/config` | Admin | Read/write native Xray JSON |
| GET | `/api/xray/logs` | Admin | Xray logs |
| GET | `/api/xray/inbounds` | Session | Inbounds and clients, usage, limits, and links |
| POST | `/api/xray/clients/add` | Session | Add client to `inbound_tag`; payload below |
| POST | `/api/xray/clients/update` | Session | Edit a client identified by `uuid` |
| POST | `/api/xray/clients/reset-traffic` | Session | `{"uuid":"..."}`; optional `server_id` |
| DELETE | `/api/xray/clients/remove?inbound_tag=tag&uuid=id` | Session | Delete client; optional `server_id` |

Add-client JSON fields: `inbound_tag`, `uuid`, `email`, `name`, `expires_at` (RFC3339 or `YYYY-MM-DD`), `max_connections`, `data_quota_bytes`, `quota_action`, `quota_throttle_mbps`, `owner_username`, and `server_id`. Update accepts `uuid`, `name`, `email`, `expires_at`, the same limit/quota fields, `reset_usage`, and `server_id`. In GET `/api/xray/inbounds`, the client UUID is serialized as **`id`**; mutation requests call it **`uuid`**.

To share a native Xray inbound on the public SSH/TLS listeners, use **Xray → Share SSH/TLS ports (WS/XHTTP)**. Select/create a VLESS or VMess inbound and choose WS or XHTTP. Each shared inbound needs a distinct path; leaving the prompt empty assigns `/c1`, `/c2`, and so on. The config marks it with `conectaSharedPort: true`. The public listener handles TLS, so the inbound itself uses `security: none`; clients use TLS when connecting to the TLS listener and the configured path. Shared raw TCP and external Xray mode are unsupported. After changing an existing inbound transport, update its clients' connection settings.

### TLS certificates

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| POST | `/api/tls/generate-selfsigned` | Admin | `{"domain":"example.com"}`; returns certificate/key paths |
| POST | `/api/tls/letsencrypt` | Admin | `{"domain":"example.com","email":"ops@example.com"}`; requires certbot and port 80 |
| POST | `/api/tls/upload-pem` | Admin | `{"name":"site","cert":"PEM...","key":"PEM..."}` |
| GET | `/api/tls/certs` | Admin | Available certs and references |
| POST | `/api/tls/certs/update` | Admin | `name` or `cert_file`/`key_file`, `fullchain`/`privkey` (or `cert`/`key`), optional `reload`, `force` |

### Telegram bot and payments

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| GET, POST | `/api/bot/config` | Admin | Bot, trial, Telegram, and Mercado Pago settings |
| GET, POST, DELETE | `/api/bot/plans` | Admin | List/upsert plans; DELETE with `?id=...` |
| GET, POST, DELETE | `/api/bot/credit-packages` | Admin | List/upsert credit packages; DELETE with `?id=...` |
| GET, POST | `/api/bot/users` | Admin | List users; POST `telegram_id`, `action` |
| GET, POST | `/api/bot/transactions` | Admin | GET `?status=&limit=`; POST `id`, `action` |
| GET, POST | `/api/bot/settings` | Admin | Read/write bot text settings |
| POST | `/api/bot/test` | Admin | Test Telegram and Mercado Pago tokens |
| POST | `/api/mp/webhook` | Public | Mercado Pago notifications; webhook signature validated when webhook mode is configured |

Bot config includes `enabled`, `telegram_token`, `mp_access_token`, `mp_confirm_mode` (`polling` or `webhook`), `mp_webhook_secret`, `mp_poll_interval`, `pix_expiration_minutes`, trial settings, `admin_telegram_ids`, `currency`, `public_host`, and `xray_public_host`. GET returns `has_telegram_token`, `has_mp_access_token`, and `has_mp_webhook_secret` flags instead of the secrets; empty secret fields on POST keep stored values. Config POST requires the complete settings document, including valid mode and limits.

Plan JSON uses Go field names: `ID` (for updates), `Name`, `Kind` (`ssh` or `xray`), `Days`, `MaxConnections`, `LimitMbpsUp`, `LimitMbpsDown`, `XrayInboundTag`, `XrayProtocol`, `PriceCents`, `CreditCost`, `ServerID`, `IsActive`, and `SortOrder`. Credit packages use `ID`, `Name`, `Credits`, `PriceCents`, `IsActive`, and `SortOrder`. Bot user POST actions are `set_role` (with `role` and optional `linked_admin_username`), `block`, `unblock`, `adjust_credits` (with `credits`); transaction actions are `refund` or `reprocess`. Bot settings POST accepts a string map with `welcome_text`, `contact_text`, `app_text`, or `app_url`.

### Public account check

| Method | Route | Access | Request or result |
| --- | --- | --- | --- |
| GET, OPTIONS | `/check?user=alice` or `/check?uuid=id` | Public | Connection count, limit, and expiry; `user` takes precedence if both are given |

## Build and checks

Requires the Go version listed in `go.mod` (currently 1.25.4), Python 3 standard library for the menu, PostgreSQL, and the installer's system dependencies. From the repository root:

```bash
go build -o sshpanel .
go test ./...
python3 -m unittest -q test_conectassh_cli.py
python3 -m py_compile conectassh_cli.py
bash -n install.sh update.sh
```
