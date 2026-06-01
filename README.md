# ssh-vault2 public self-hosting source

Self-hostable SSH/SFTP desktop client plus optional sync/download server. This public repository contains only source and self-hosting docs: no private deployment data, no local runtime state, no release artifacts, and no internal test fixtures.

## Layout

```text
client/   Desktop app source (Go/Wails + React)
server/   Self-hosted web/API server source
LICENSE   AGPLv3 license
```

## Server quickstart

Replace placeholders with your own values.

```bash
sudo apt update
sudo apt install -y git ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh

cd /tmp
git clone https://github.com/<GITHUB_OWNER>/ssh-vault2-pub.git ssh-vault2-source
sudo mv /tmp/ssh-vault2-source /opt/ssh-vault2-source
sudo mkdir -p /opt/ssh-vault2-server/downloads /opt/ssh-vault2-server/data
sudo chown -R 988:988 /opt/ssh-vault2-server
sudo cp /opt/ssh-vault2-source/server/compose.yaml /opt/ssh-vault2-server/compose.yaml
sudo nano /opt/ssh-vault2-server/compose.yaml
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
curl -fsS http://127.0.0.1:18080/healthz
```

Edit before public use:

```yaml
SSH_VAULT2_PUBLIC_URL: "https://ssh-vault.example.org"
SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
```

Use a reverse proxy with HTTPS. If the proxy runs on the same host, keep the server bound to `127.0.0.1:18080`. If the proxy is remote, bind `0.0.0.0:18080` and restrict access by firewall.

## Autostart

```bash
sudo cp /opt/ssh-vault2-source/server/ssh-vault2-server.service /etc/systemd/system/ssh-vault2-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-vault2-server.service
```

## Client build

```bash
cd /opt/ssh-vault2-source/client
npm ci --prefix frontend
npm run build --prefix frontend
wails3 task build
```

## Backups

```bash
sudo tar -C /opt -czf ssh-vault2-server-backup-$(date +%F).tar.gz ssh-vault2-server
```

## Security notes

- keep public access behind HTTPS
- use `approval` or `closed` registration for real deployments
- enable TOTP for admin accounts
- never commit `.env`, keys, tokens, local vaults, runtime DBs, or release signing private keys
- keep private signing keys outside mounted server data

## License

GNU Affero General Public License v3.0 (AGPL-3.0-only). See `LICENSE`.

Network/server use is covered by AGPL section 13: if you run a modified version as a network service, users interacting with it must be offered the corresponding source code.
