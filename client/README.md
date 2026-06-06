# ssh-vault2 Desktop Client

Cross-platform desktop client for SSH, SFTP, RDP, encrypted local vault storage and optional self-hosted sync.

## Features

- SSH terminal sessions with tabs
- SFTP file manager with upload/download and file operations
- Integrated RDP sessions with scaling, keyboard/mouse input and clipboard support
- Encrypted local vault for credentials and private keys
- Optional encrypted sync through a self-hosted ssh-vault2 server
- Update feed support through the configured release server

## Development setup

```bash
cd client
npm ci --prefix frontend
npm run build --prefix frontend
go test ./...
wails3 build
```

## Frontend

```bash
cd client/frontend
npm ci
npm run build
```

## Configuration

The public source uses documentation-safe placeholder defaults. For production use, configure your own server endpoint in the app settings or adjust `releaseServer` in `appservice.go` before building your own branded/self-hosted client.

## License

AGPL-3.0-only. See the repository root `LICENSE` file.
