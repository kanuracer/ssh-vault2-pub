# ssh-vault2 public self-hosting source

ssh-vault2 is a self-hostable SSH/SFTP desktop client plus optional sync/download server.

This repository is meant for public self-hosting. It contains source code and deployment documentation only:

- no private deployment data
- no local runtime state
- no release artifacts
- no bundled databases
- no secrets or keys
- no internal test fixtures

## Repository layout

```text
client/   Desktop app source (Go/Wails + React)
server/   Self-hosted web/API server source
LICENSE   AGPLv3 license
```

## Components

### Client

The desktop app provides:

- SSH terminal sessions
- SFTP file browser and transfers
- local encrypted vault storage
- optional encrypted sync through your own server
- optional release/update checks against your own download server

The client connects directly to your SSH/SFTP targets. The server below is not an SSH gateway.

### Server

The server provides:

- public website/download page
- account registration/login/admin UI
- encrypted sync API
- release metadata/feed
- download hosting and checksum metadata

The server stores only its own web/account/sync data. SSH connections still happen from the desktop client to your target machines.

## License

GNU Affero General Public License v3.0 (AGPL-3.0-only). See `LICENSE`.

Network/server use is covered by AGPL section 13: if you run a modified version as a network service, users interacting with it must be offered the corresponding source code.

## Prerequisites

For the server:

- Linux host or VPS
- Git
- Docker + Docker Compose
- public DNS name, e.g. `ssh-vault.example.org`
- HTTPS reverse proxy, e.g. Caddy, Nginx, Traefik, or a hosting panel
- persistent storage for `/opt/ssh-vault2-server`

For the client build:

- Go
- Node.js + npm
- Wails v3 toolchain
- OS-specific build dependencies for your target platform

## Fresh server install

These commands assume a fresh Linux server. Replace example domains and account names with your own values.

### 1. Install Git and Docker

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y git ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

Log out and back in once after adding the Docker group, or use `sudo docker ...`.

Verify:

```bash
git --version
docker --version
docker compose version
```

### 2. Clone the repository on the server

```bash
cd /tmp
git clone https://github.com/kanuracer/ssh-vault2-pub.git ssh-vault2-source
sudo mv /tmp/ssh-vault2-source /opt/ssh-vault2-source
sudo chown -R $USER:$USER /opt/ssh-vault2-source
```

Verify expected files:

```bash
ls /opt/ssh-vault2-source/client
ls /opt/ssh-vault2-source/server/Dockerfile
ls /opt/ssh-vault2-source/server/compose.yaml
```

### 3. Prepare persistent server data

```bash
sudo mkdir -p /opt/ssh-vault2-server/downloads
sudo mkdir -p /opt/ssh-vault2-server/data
sudo chown -R 988:988 /opt/ssh-vault2-server
```

Directory meaning:

```text
/opt/ssh-vault2-source   Git checkout; safe to update with git pull
/opt/ssh-vault2-server   persistent data, downloads, compose.yaml; do not delete
```

### 4. Install Compose file

```bash
sudo cp /opt/ssh-vault2-source/server/compose.yaml /opt/ssh-vault2-server/compose.yaml
sudo nano /opt/ssh-vault2-server/compose.yaml
```

Edit at least:

```yaml
SSH_VAULT2_PUBLIC_URL: "https://ssh-vault.example.org"
SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
```

Use your real public HTTPS domain and your own first admin account name/email.

### 5. Start server

```bash
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
sudo docker ps
curl -fsS http://127.0.0.1:18080/healthz
curl -fsS http://127.0.0.1:18080/api/v1/releases
```

Expected health output contains:

```json
{"ok":true}
```

If the container does not start:

```bash
sudo docker logs --tail=200 ssh-vault2-server
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml config
```

## Docker Compose configuration

The included `server/compose.yaml` builds from the server subdirectory:

```yaml
services:
  ssh-vault2-server:
    build:
      context: /opt/ssh-vault2-source/server
      dockerfile: Dockerfile
    image: ssh-vault2-server:local
    container_name: ssh-vault2-server
    restart: unless-stopped
    user: "988:988"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=64m,mode=1777
    ports:
      - "127.0.0.1:18080:18080"
    environment:
      HOST: "0.0.0.0"
      PORT: "18080"
      SSH_VAULT2_ROOT: "/var/lib/ssh-vault2"
      SSH_VAULT2_PUBLIC_URL: "https://ssh-vault.example.org"
      SSH_VAULT2_REGISTRATION_MODE: "approval"
      SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
    volumes:
      - /opt/ssh-vault2-server:/var/lib/ssh-vault2
```

Important values:

| Setting | Meaning |
|---|---|
| `build.context` | path to this repo's `server/` directory on your host |
| `SSH_VAULT2_ROOT` | server data directory inside the container |
| `volumes` | persistent host data mounted into the container |
| `SSH_VAULT2_PUBLIC_URL` | public HTTPS URL used by web UI and cookies |
| `SSH_VAULT2_REGISTRATION_MODE` | `open`, `approval`, or `closed` |
| `SSH_VAULT2_ADMIN_ACCOUNTS` | comma-separated admin usernames/emails |

## Reverse proxy and HTTPS

Public deployments should use HTTPS.

If the reverse proxy runs on the same host, keep Compose bound to localhost:

```yaml
ports:
  - "127.0.0.1:18080:18080"
```

Proxy target:

```text
http://127.0.0.1:18080
```

If your reverse proxy runs on another machine, change the port binding:

```yaml
ports:
  - "0.0.0.0:18080:18080"
```

Then restrict access with a firewall so only the proxy can reach port `18080`.

After proxy setup, verify:

```bash
curl -fsS https://ssh-vault.example.org/healthz
curl -fsS https://ssh-vault.example.org/api/v1/releases
```

## Autostart with systemd

Install the included unit:

```bash
sudo cp /opt/ssh-vault2-source/server/ssh-vault2-server.service /etc/systemd/system/ssh-vault2-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-vault2-server.service
```

Verify:

```bash
systemctl is-enabled ssh-vault2-server.service
systemctl is-active ssh-vault2-server.service
sudo docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' ssh-vault2-server
```

Expected:

```text
enabled
active
running healthy
```

## Account registration and admin setup

Registration modes:

| Mode | Behavior |
|---|---|
| `open` | users can register and use accounts immediately |
| `approval` | users can register, admin must approve |
| `closed` | registration disabled |

Recommended for public servers:

```yaml
SSH_VAULT2_REGISTRATION_MODE: "approval"
```

Set admins with:

```yaml
SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
```

After first login, the matching user gets admin functions.

## Downloads and release feed

The server exposes release metadata from its download directory.

Place built client artifacts here:

```text
/opt/ssh-vault2-server/downloads
```

Generate checksums:

```bash
cd /opt/ssh-vault2-server/downloads
sha256sum * > SHA256SUMS.txt
sudo chown -R 988:988 /opt/ssh-vault2-server
```

Verify feed:

```bash
curl -fsS http://127.0.0.1:18080/api/v1/releases
```

If you sign checksums, keep the private signing key outside `/opt/ssh-vault2-server`. Only the public verification key belongs in client source.

## Build the desktop client

```bash
cd /opt/ssh-vault2-source/client
npm ci --prefix frontend
npm run build --prefix frontend
wails3 task build
```

Platform notes:

- Build Windows packages on Windows or with a configured cross-build environment.
- Build macOS packages on macOS or with a compatible cross-build setup.
- Linux builds require GTK/WebKit/Wails dependencies.

## Update server

```bash
cd /opt/ssh-vault2-source
git pull
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build --force-recreate
curl -fsS http://127.0.0.1:18080/healthz
```

Always use `--build` after source updates so Docker does not reuse stale code.

## Backup and restore

Back up persistent server data:

```bash
sudo tar -C /opt -czf ssh-vault2-server-backup-$(date +%F).tar.gz ssh-vault2-server
```

Important data:

```text
/opt/ssh-vault2-server/data
/opt/ssh-vault2-server/downloads
/opt/ssh-vault2-server/SHA256SUMS.txt
```

Restore example:

```bash
sudo systemctl stop ssh-vault2-server.service
sudo tar -C /opt -xzf ssh-vault2-server-backup-YYYY-MM-DD.tar.gz
sudo chown -R 988:988 /opt/ssh-vault2-server
sudo systemctl start ssh-vault2-server.service
```

## Troubleshooting

| Symptom | Check |
|---|---|
| container exits | `sudo docker logs --tail=200 ssh-vault2-server` |
| healthcheck unhealthy | `curl http://127.0.0.1:18080/healthz` |
| reverse proxy returns 502 | proxy target and port binding |
| admin UI missing | `SSH_VAULT2_ADMIN_ACCOUNTS` must match the login |
| registration blocked | check `SSH_VAULT2_REGISTRATION_MODE` |
| feed empty | check downloads and `SHA256SUMS.txt` |
| permission denied | `sudo chown -R 988:988 /opt/ssh-vault2-server` |

## Public repository hygiene

This repository intentionally excludes:

- test fixtures
- local build output
- dependency directories
- release archives/installers
- local vaults and runtime databases
- private keys, tokens, `.env` files
- private deployment hostnames, usernames, or internal IPs

Before publishing your own fork, run a scanner such as gitleaks or trufflehog and review all docs for real infrastructure values.
