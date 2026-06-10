import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const backend = readFileSync(new URL('../../appservice.go', import.meta.url), 'utf8');
const server = readFileSync(new URL('../../../server/server.mjs', import.meta.url), 'utf8');
const compose = readFileSync(new URL('../../../server/compose.yaml', import.meta.url), 'utf8');
const prodCompose = compose;

test('frontend Wails event listeners are unsubscribed and update status is not contradictory', () => {
  assert.match(app, /const offData = Events\.On\('ssh:data'/, 'ssh:data listener must keep unsubscribe handle');
  assert.match(app, /const offStatus = Events\.On\('ssh:status'/, 'ssh:status listener must keep unsubscribe handle');
  assert.match(app, /return \(\) => \{\s*offData\(\);\s*offStatus\(\);\s*offRdpStatus\(\);\s*offRdpAudio\(\);[\s\S]*?\}/s, 'effect cleanup must unregister Wails listeners');
  assert.doesNotMatch(app, /Events\.On\('rdp:frame|Events\.On\('rdp:frames/, 'RDP render frames must not use Wails events');
  assert.doesNotMatch(app, /Noch keine kompatiblen Versionen geladen/, 'up-to-date status must not also claim versions are not loaded');
  assert.match(app, /Du bist auf dem neusten Stand\./, 'empty update list needs the requested compact copy');
  assert.doesNotMatch(app, /Keine neuere kompatible Version verfügbar/, 'old redundant empty update copy must stay removed');
});

test('SFTP editor/upload paths refuse remote symlinks and use upload ids with offsets', () => {
  assert.match(backend, /func \(s \*AppService\) ReadTextSFTP[\s\S]*?rejectRemoteSymlink\(r, remotePath\)/, 'remote text read must Lstat/block symlinks before opening');
  assert.match(backend, /func \(s \*AppService\) WriteTextSFTP[\s\S]*?rejectRemoteSymlink\(r, remotePath\)/, 'remote text write must block existing symlink targets');
  assert.match(backend, /func uploadFileSFTP\(r \*sftpRec[\s\S]*?rejectRemoteExistingSymlink\(r, remotePath\)/, 'regular SFTP uploads must block existing remote symlink targets');
  assert.match(backend, /func uploadAnySFTP\(r \*sftpRec[\s\S]*?rejectRemoteParentSymlinks\(r, remotePath\)/, 'directory uploads must check remote parent symlinks before mkdir');
  assert.match(backend, /func \(s \*AppService\) UploadSFTPChunk\(id, uploadID, remotePath string, offset int64, base64Data string\)/, 'chunk upload must include upload id and exact offset, not append bool');
  assert.doesNotMatch(backend, /OpenFile\(remotePath, flags\)[\s\S]*O_APPEND/, 'chunk upload must not append blindly');
  assert.match(app, /const uploadID = crypto\.randomUUID\(\)/, 'frontend must create a per-file upload id');
  assert.match(app, /API\.UploadSFTPChunk\(sftpId, uploadID, targetPath, off, data\)/, 'frontend must pass upload id and byte offset');
});

test('update extraction is prepared by Go safety checks, not shell find/tar trust', () => {
  assert.match(backend, /validateLinuxUpdateArchive\(/, 'Linux archive validator must inspect archive entries before apply');
  assert.match(backend, /regexp\.MustCompile\(`\^\[A-Za-z0-9\._\+@%=-\]\+/, 'validated archive paths must be shell-safe whitelisted before being embedded in apply scripts');
  assert.match(backend, /validateDarwinUpdateArchive\(/, 'macOS archive validator must inspect zip entries before apply');
  assert.doesNotMatch(backend, /find \"\$work\" -type f -name 'ssh-vault2'/, 'Linux updater must not pick arbitrary first binary with find');
  assert.doesNotMatch(backend, /find \"\$work\" -name 'ssh-vault2\.app'/, 'macOS updater must not pick arbitrary first app bundle with find');
});

test('server account hardening: stronger passwords, encrypted TOTP, no app HSTS duplication', () => {
  assert.match(server, /const minPasswordLength = envInt\('SSH_VAULT2_MIN_PASSWORD_LENGTH', 12\)/, 'server must default to >=12 char passwords');
  assert.match(server, /encryptTotpSecret\(/, 'TOTP secret must be encrypted before storage');
  assert.match(server, /migrateLegacyTotpSecret\(/, 'legacy plaintext TOTP secrets must be migrated after successful authenticated use');
  assert.match(server, /decryptTotpSecret\(/, 'TOTP secret must be decrypted only for verification');
  assert.doesNotMatch(server, /ctx\.rec\.totpSecret = secret/, 'raw TOTP secret must not be stored in account JSON');
  assert.doesNotMatch(server, /Strict-Transport-Security/, 'app should not duplicate HSTS when reverse proxy owns TLS');
  assert.doesNotMatch(server, /unsafe-inline/, 'CSP must avoid unsafe-inline; use hashed inline blocks/handlers instead');
});

test('docker compose examples run server as hardened non-root container', () => {
  for (const text of [compose, prodCompose]) {
    assert.match(text, /user:\s*["']988:988["']/, 'compose must run as service UID 988');
    assert.match(text, /read_only:\s*true/, 'compose must use read-only root filesystem');
    assert.match(text, /cap_drop:\s*\n\s*- ALL/, 'compose must drop all Linux capabilities');
    assert.match(text, /security_opt:\s*\n\s*- no-new-privileges:true/, 'compose must set no-new-privileges');
    assert.match(text, /tmpfs:\s*\n\s*- \/tmp/, 'compose must provide tmpfs for temporary files');
  }
});
