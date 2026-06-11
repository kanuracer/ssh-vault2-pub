# ssh-vault2

ssh-vault2 is a cross-platform remote workspace for SSH terminals, SFTP file management, integrated RDP sessions, encrypted local vault storage and optional self-hosted sync.

The repository contains the public self-hosting source split into:

- `client/` — desktop application source
- `server/` — self-hosted download, account and sync server
- `docs/` — technical notes
- [`changelog.md`](./changelog.md) — detailed product changelog

## Highlights

- Bugfix release `1.5.14` for settings readability, settings tab alignment, terminal paste handling, RDP session input stability and Windows installer metadata
- SSH terminal sessions with tabs and stable xterm rendering
- SFTP commander with upload, download, folders, properties and file operations
- Integrated RDP workspace with in-app desktop viewer, scaling modes, keyboard/mouse input and clipboard support
- Local encrypted vault for passwords and private keys
- Optional encrypted sync through a self-hosted server
- Account portal with registration modes, tokens, TOTP and admin controls
- Release/download server with health check, checksums and app update feed
- Desktop builds for Windows, Linux and macOS

## Repository layout

```text
.
├── client/   # Wails/Go desktop app + React/Vite frontend
├── server/   # Node.js self-hosting server + Docker files
├── docs/     # Technical documentation
└── changelog.md
```

## Quick start: self-host the server

Example target paths:

```text
/opt/ssh-vault2-source  # cloned GitHub source
/opt/ssh-vault2-server  # persistent runtime data and compose file
```

### 1. Install prerequisites

On a fresh Linux host:

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-plugin
sudo systemctl enable --now docker
```

### 2. Clone source

```bash
cd /tmp
git clone https://github.com/kanuracer/ssh-vault2-pub.git ssh-vault2-source
sudo mv /tmp/ssh-vault2-source /opt/ssh-vault2-source
sudo chown -R "$USER:$USER" /opt/ssh-vault2-source
```

### 3. Prepare persistent data

```bash
sudo mkdir -p /opt/ssh-vault2-server/downloads /opt/ssh-vault2-server/data
sudo chown -R 988:988 /opt/ssh-vault2-server
sudo cp /opt/ssh-vault2-source/server/compose.yaml /opt/ssh-vault2-server/compose.yaml
```

Edit the compose file:

```bash
sudo nano /opt/ssh-vault2-server/compose.yaml
```

Set at least:

```yaml
SSH_VAULT2_PUBLIC_URL: "https://ssh-vault.example.org"
SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
```

Use your own HTTPS domain and admin account.

### 4. Build and start

```bash
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
sudo docker ps
curl -fsS http://127.0.0.1:18080/healthz
```

Expected health response:

```json
{
  "ok": true,
  "service": "ssh-vault2",
  "version": "1.5.14"
}
```

### 5. Put HTTPS in front

Run the container behind a normal HTTPS reverse proxy such as Caddy, Nginx, Traefik or Nginx Proxy Manager.

Recommended public route:

```text
https://ssh-vault.example.org  ->  http://127.0.0.1:18080
```

Keep the container port bound to `127.0.0.1` when the reverse proxy runs on the same machine. If the proxy runs on another machine, expose the port only to that proxy with firewall rules.

## What the server does

The server is not an SSH or RDP gateway. It provides:

- website and documentation pages
- account registration/login/admin UI
- sync token management
- encrypted sync blob storage
- release feed and downloads
- checksum endpoints

The desktop app connects directly from the user's machine to target systems via SSH, SFTP or RDP.

## Build the desktop client

Prerequisites:

- Go matching the version in `client/go.mod`
- Node.js and npm
- Wails v3 tooling
- platform-specific build tools for Windows/Linux/macOS packages

Basic development build:

```bash
cd client
npm ci --prefix frontend
npm run build --prefix frontend
go test ./...
wails3 build
```

The frontend source lives in `client/frontend/`. Generated Wails bindings are committed so the project is easier to inspect and build from a clean checkout.

## Update an existing self-hosted server

```bash
cd /opt/ssh-vault2-source
git pull --ff-only
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
curl -fsS http://127.0.0.1:18080/healthz
```

Back up `/opt/ssh-vault2-server` before major updates.

## Backups

Back up the persistent runtime directory:

```bash
sudo tar -czf ssh-vault2-server-backup.tgz /opt/ssh-vault2-server
```

This contains server-side account metadata, sync blobs, downloads and release metadata. Sync blobs are encrypted by the client, but backups should still be handled as sensitive operational data.

## Security notes

- Use HTTPS for public access.
- Keep registration in `approval` or `closed` mode unless open registration is intentional.
- Use strong passwords and enable TOTP for admin accounts.
- Store SMTP credentials through a secret file or environment management system.
- Do not expose the container port directly to the internet when a reverse proxy is available.
- The desktop app stores secrets locally in the encrypted vault; the sync server stores encrypted blobs only.

## Changelog

See [`changelog.md`](./changelog.md) for the detailed changelog, including the `1.5.14` bugfix update.

## License

This public source release is licensed under the GNU Affero General Public License v3.0. See [`LICENSE`](./LICENSE).
