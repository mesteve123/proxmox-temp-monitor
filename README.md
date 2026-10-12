# Proxmox TEMP Monitor

Web tool (Docker) that connects to your Proxmox hosts over SSH, runs sensors (lm-sensors) every X time and keeps a temperature history shown as charts.


---

# 🚀 Installation

## Prerequisites

* Docker
* Docker Compose

## Docker Compose

Create a `docker-compose.yml` file with the following content, if you wish you can configure access credentials in the last lines of the YAML file:

```yaml
services:
  tempmon:
    image: ghcr.io/mesteve123/proxmox-temp-monitor:latest
    container_name: proxmox-temp-monitor
    restart: unless-stopped
    ports:
      - "5080:8080"
    volumes:
      - ./data:/data
    environment:
      TZ: Europe/Madrid
      # Optional: protect the UI with a username/password (HTTP Basic)
      # AUTH_USER: admin
      # AUTH_PASS: change-me


```

Start the container:

```bash
docker compose up -d
```

Once running, open your browser and go to:

```
http://YOUR_SERVER_IP:5080
```
