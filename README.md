# LensIQ Management Server

Control plane for the LensIQ desktop tool: employee gate, telemetry, remote config
(API keys + fallback key + model), broadcasts, remote updates, QR admin login.

**The desktop tool is offline-first** — it works exactly as it does today even when
this server is down (Gemini calls go directly to Google, local OCR/DeBERTa, API key
cached locally). This server only *pushes* config, *collects* usage, *broadcasts*,
and *ships updates* when it's reachable.

## Ports
| Port | Service | Notes |
|------|---------|-------|
| 7788 | Backend API + WebSocket (`mgmt_server.py`) | tool + dashboard talk to this |
| 7789 | Admin dashboard static site (`frontend_server.py`) | open in a browser |

Open the firewall for **both** (you already did 7789):
```bash
sudo iptables -I INPUT 6 -p tcp --dport 7788 -j ACCEPT
sudo iptables -I INPUT 6 -p tcp --dport 7789 -j ACCEPT
sudo netfilter-persistent save
```

## Install & run (on the VM 129.159.20.37)
```bash
cd lensiq-server
python3 -m venv venv && source venv/bin/activate     # optional but recommended
pip install -r requirements.txt
npm i -g pm2                                          # if not installed
pm2 start ecosystem.config.js
pm2 save && pm2 startup                               # auto-start on reboot
```
Quick manual run (no pm2):
```bash
python3 mgmt_server.py        # :7788
python3 frontend_server.py    # :7789
```

## Use
- Dashboard: **http://129.159.20.37:7789**
- Default admins (change after first login):
  - `skylinx@gmail.com` / `admin@159`
  - `vbs@gmail.com` / `admin@159`
- **Set `LENSIQ_SECRET`** to a long random string in `ecosystem.config.js` (signs admin tokens).

## Data
- `lensiq.db` — SQLite (admins, employees, usage, settings, qr tokens). Back this up.
- `updates/` — uploaded installer files.

## API surface (for the desktop tool)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/employee/verify` | employee-id gate (`{employee_id}`) |
| GET  | `/api/config?employee_id=` | pull admin pw, api key, **fallback key**, model, broadcast, latest version |
| POST | `/api/usage` | push usage (single or `{events:[...]}` batch for offline flush) |
| GET  | `/api/updates/latest` | check for update |
| GET  | `/api/updates/download/{file}` | download installer |
| POST | `/api/qr/create` / GET `/api/qr/status/{t}` | QR admin login (tool side) |
| WS   | `/ws/tool/{employee_id}` | realtime: `broadcast`, `config_changed`, `update_available` |

Admin/dashboard endpoints require `Authorization: Bearer <token>` from `/api/admin/login`.

## HRMS-ready
Employees, usage, and settings are plain SQLite tables with clean REST endpoints —
straightforward to sync to an HRMS later (export `/api/usage/summary`, map `employee_id`).
