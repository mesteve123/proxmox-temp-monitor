# Proxmox Temp Monitor

Web tool (Docker) that connects to your Proxmox hosts over SSH, runs `sensors`
(lm-sensors) every X time and keeps a temperature history shown as charts.

## Run

```bash
docker compose up -d --build
```

Open http://DOCKER-HOST-IP:8080

## Usage

- **+ Add host**: friendly name, IP, SSH port, username and password. It tests the SSH
  connection and checks whether `lm-sensors` is installed. If it isn't, it asks whether you
  want to install it (`apt-get install lm-sensors` + `sensors-detect --auto`). Once everything
  works, the host is saved.
- **🗑**: deletes the host and its history.
- **⚙ Settings** (only two options):
  - *Query each host every…*: how often the host is queried. Every query is also saved to the history.
  - *Keep history for… days*: how long the history is kept.
- Per-host chart with 1 h / 6 h / 24 h / 7 d / 30 d ranges. One line per component (CPU, GPU, NVMe…).

## Notes

- Everything is stored in `./data` (SQLite + encryption key). SSH passwords are stored
  encrypted with Fernet; the key lives in `data/secret.key` (back up both, or you will lose
  access to the saved hosts).
- The UI has no login by default: keep it on your LAN or set `AUTH_USER` / `AUTH_PASS`.
- New SSH host keys are accepted automatically (no fingerprint verification).
- Absurd readings (e.g. `-263.2°C` from `acpitz`) and `N/A` sensors are discarded.
- If the user is not root, the installation uses `sudo`.
