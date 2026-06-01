# ssh-vault2 client

Cross-platform Wails/Go + React desktop client for SSH, SFTP, local encrypted vaults, and optional encrypted sync.

## Build

```bash
npm ci --prefix frontend
npm run build --prefix frontend
wails3 task build
```

Set your own sync/download endpoint in app settings or rebuild with your own defaults.

## License

GNU Affero General Public License v3.0 (AGPL-3.0-only). See `../LICENSE`.
