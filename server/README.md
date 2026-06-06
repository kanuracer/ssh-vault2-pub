# ssh-vault2 Self-Hosted Server

The server provides the website, account portal, encrypted sync API, download area and release feed for ssh-vault2.

It is not an SSH or RDP gateway. Desktop clients connect directly to target systems via SSH, SFTP or RDP.

## Docker quick start

```bash
sudo mkdir -p /opt/ssh-vault2-source /opt/ssh-vault2-server/downloads /opt/ssh-vault2-server/data
cd /opt/ssh-vault2-source
git clone https://github.com/kanuracer/ssh-vault2-pub.git .
sudo cp server/compose.yaml /opt/ssh-vault2-server/compose.yaml
sudo nano /opt/ssh-vault2-server/compose.yaml
sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
curl -fsS http://127.0.0.1:18080/healthz
```

Set these values in `compose.yaml`:

```yaml
SSH_VAULT2_PUBLIC_URL: "https://ssh-vault.example.org"
SSH_VAULT2_ADMIN_ACCOUNTS: "adminuser"
```

## Important paths

- `/var/lib/ssh-vault2/downloads` inside container: downloadable release assets
- `/var/lib/ssh-vault2/data` inside container: accounts, sync data, metadata
- `/opt/ssh-vault2-server` on host: persistent data mount in the example compose file

## Environment variables

| Variable | Purpose |
| --- | --- |
| `HOST` | bind address inside container |
| `PORT` | server port, default `18080` |
| `SSH_VAULT2_ROOT` | runtime data root inside container |
| `SSH_VAULT2_PUBLIC_URL` | public HTTPS URL used for links and cookies |
| `SSH_VAULT2_REGISTRATION_MODE` | `open`, `approval` or `closed` |
| `SSH_VAULT2_ADMIN_ACCOUNTS` | comma-separated admin account names |
| `SSH_VAULT2_SMTP_*` | optional SMTP settings for password reset |

## Security notes

- Put HTTPS in front of the server.
- Keep the container port private when using a reverse proxy on the same host.
- Use `approval` or `closed` registration mode for controlled deployments.
- Back up the persistent data directory.
- Treat downloads and account metadata as operationally sensitive even when sync blobs are encrypted.
