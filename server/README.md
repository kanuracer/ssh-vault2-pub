# ssh-vault2 server

Self-hosted web/API server for account management, encrypted sync, downloads, and release metadata.

## Run

```bash
sudo mkdir -p /opt/ssh-vault2-server/downloads /opt/ssh-vault2-server/data
sudo chown -R 988:988 /opt/ssh-vault2-server
sudo cp /opt/ssh-vault2-source/server/compose.yaml /opt/ssh-vault2-server/compose.yaml
sudo nano /opt/ssh-vault2-server/compose.yaml
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
curl -fsS http://127.0.0.1:18080/healthz
```

Set your own `SSH_VAULT2_PUBLIC_URL` and `SSH_VAULT2_ADMIN_ACCOUNTS`.

## License

GNU Affero General Public License v3.0 (AGPL-3.0-only). See `../LICENSE`.
