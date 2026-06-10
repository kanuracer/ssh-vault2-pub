import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const serverPath = new URL('./server.mjs', import.meta.url).pathname;

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
async function startServer({ root, port, mode = 'open', admins = '', extraEnv = {} }) {
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  const child = spawn(process.execPath, [serverPath], {
    env: { ...process.env, SSH_VAULT2_ROOT: root, PORT: String(port), SSH_VAULT2_REGISTRATION_MODE: mode, SSH_VAULT2_ADMIN_ACCOUNTS: admins, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(base + '/healthz'); if (r.ok) return { child, base }; } catch {}
    if (child.exitCode !== null) throw new Error('server exited early');
    await wait(100);
  }
  child.kill();
  throw new Error('server did not start');
}
async function stopServer(child) { child.kill(); await wait(100); }
async function api(base, p, body, cookie = '', extraHeaders = {}) {
  const r = await fetch(base + p, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', Origin: base, ...(cookie ? { Cookie: cookie } : {}), ...extraHeaders }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = { text }; }
  return { status: r.status, headers: r.headers, json };
}
async function syncPut(base, account, token, blob, extraHeaders = {}) {
  const r = await fetch(base + '/api/v1/sync/' + encodeURIComponent(account), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': token, 'X-Sync-Host-Count': '1', 'X-Sync-Vault-Count': '0', ...extraHeaders },
    body: JSON.stringify(blob)
  });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = { text }; }
  return { status: r.status, headers: r.headers, json };
}

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '')) { const idx = base32Alphabet.indexOf(ch); if (idx < 0) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
test('landing page shows only quickstart and links detailed desktop guide page', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-landing-'));
  const srv = await startServer({ root, port: 18249, mode: 'open' });
  try {
    let r = await fetch(srv.base + '/');
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /<h2>Quickstart\.<\/h2>/);
    assert.match(html, /downloadPlatformName\(p\)/, 'landing page must render platform-specific download group headings');
    assert.match(html, /downloadGroups/, 'landing page must group downloads by platform');
    assert.match(html, /windows:\[\]/, 'landing page must maintain a Windows download group');
    assert.match(html, /macos:\[\]/, 'landing page must maintain a macOS download group');
    assert.match(html, /linux:\[\]/, 'landing page must maintain a Linux download group');
    assert.match(html, /Windows/);
    assert.match(html, /macOS/);
    assert.match(html, /Linux/);
    assert.match(html, /Desktop SSH, SFTP & RDP Client/);
    assert.match(html, /SSH\. SFTP\. RDP\. Sync\./);
    assert.match(html, /RDP im App-Fenster/);
    assert.match(html, /RDP desktop ready/);
    assert.match(html, /windows-host<\/b><span>rdp/);
    assert.match(html, /SSH, SFTP oder RDP öffnen/);
    assert.match(html, /RDP öffnen/);
    assert.match(html, /<a href="#guide">Quickstart<\/a><span class="navDrop">/);
    assert.match(html, /<span class="navMenu" role="menu"><a href="\/desktop-guide" role="menuitem">Desktop-App<\/a><a href="\/server-guide" role="menuitem">Server<\/a><a href="\/web-guide" role="menuitem">Webseite<\/a><\/span>/);
    assert.doesNotMatch(html, /<a href="\/desktop-guide">Desktop-App<\/a><span class="navDrop">/);
    assert.match(html, /Dokus ▾/);
    assert.match(html, /class="navDrop"/);
    assert.match(html, /\.navDrop:after\{content:"";position:absolute;left:-120px;right:-8px;top:100%;height:10px\}/);
    assert.match(html, /href="\/server-guide"/);
    assert.match(html, /href="\/web-guide"/);
    assert.doesNotMatch(html, /<h2>Ausführliche Desktop-App-Anleitung\.<\/h2>/);
    assert.doesNotMatch(html, /<h2>Server-Anleitung\.<\/h2>/);
    assert.doesNotMatch(html, /<h2>Webseiten-Anleitung\.<\/h2>/);
    assert.doesNotMatch(html, /SFTP-Dateimanager verwenden/);
    assert.doesNotMatch(html, /Benutzeranleitung/);

    r = await fetch(srv.base + '/desktop-guide');
    assert.equal(r.status, 200);
    const desktopGuide = await r.text();
    assert.match(desktopGuide, /<h2>Ausführliche Desktop-App-Anleitung\.<\/h2>/);
    assert.match(desktopGuide, /Schritt-für-Schritt-Dokumentation für Einsteiger/);
    assert.match(desktopGuide, /Windows installieren/);
    assert.match(desktopGuide, /Linux installieren/);
    assert.match(desktopGuide, /macOS installieren/);
    assert.match(desktopGuide, /Host-Key-Fingerprint prüfen/);
    assert.match(desktopGuide, /SFTP-Dateimanager verwenden/);
    assert.match(desktopGuide, /RDP-Sitzung öffnen/);
    assert.match(desktopGuide, /RDP direkt in ssh-vault2 öffnen/);
    assert.match(desktopGuide, /Skalierung je Host wählen/);
    assert.match(desktopGuide, /Maus, Tastatur, Clipboard/);
    assert.match(desktopGuide, /Sync einrichten/);
    assert.match(desktopGuide, /Fehler schnell eingrenzen/);
    assert.match(desktopGuide, /href="\/#guide">Quickstart/);

    r = await fetch(srv.base + '/server-guide');
    assert.equal(r.status, 200);
    const serverGuide = await r.text();
    assert.match(serverGuide, /<h2>Server-Anleitung\.<\/h2>/);
    assert.match(serverGuide, /Installations- und Betriebsdokumentation/);
    assert.match(serverGuide, /weder SSH- noch RDP-Gateway/);
    assert.match(serverGuide, /direkt per SSH, SFTP oder RDP/);
    assert.match(serverGuide, /Voraussetzungen/);
    assert.match(serverGuide, /Auf diesem Server bauen und starten/);
    assert.match(serverGuide, /git clone https:\/\/github\.com\/example-org\/ssh-vault2\.git ssh-vault2-source/);
    assert.match(serverGuide, /up -d --build/);
    assert.match(serverGuide, /build\.context/);
    assert.match(serverGuide, /Reverse-Proxy und HTTPS/);
    assert.match(serverGuide, /Release-Feed/);
    assert.match(serverGuide, /\/api\/v1\/releases/);
    assert.match(serverGuide, /Backup und Restore/);
    assert.match(serverGuide, /Server aktualisieren/);
    assert.match(serverGuide, /Härtungs-Checkliste/);

    r = await fetch(srv.base + '/web-guide');
    assert.equal(r.status, 200);
    const webGuide = await r.text();
    assert.match(webGuide, /<h2>Webseiten-Anleitung\.<\/h2>/);
    assert.match(webGuide, /Download:<\/b> aktuelle Pakete für Windows, Linux und macOS/);
    assert.match(webGuide, /Desktop-App mit SSH, SFTP und RDP/);
    assert.match(webGuide, /Konto anlegen/);
    assert.match(webGuide, /Anmelden/);
    assert.match(webGuide, /Sync-Token erzeugen/);
    assert.match(webGuide, /Desktop-App mit Web-Konto verbinden/);
    assert.match(webGuide, /TOTP aktivieren/);
    assert.match(webGuide, /Adminbereich verstehen/);
    assert.match(webGuide, /Typische Probleme lösen/);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

function testTotp(secret, step = Math.floor(Date.now() / 30000)) {
  const key = base32Decode(secret); const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(step / 0x100000000), 0); msg.writeUInt32BE(step >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(msg).digest(); const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 127) << 24) | ((h[o + 1] & 255) << 16) | ((h[o + 2] & 255) << 8) | (h[o + 3] & 255);
  return String(bin % 1000000).padStart(6, '0');
}


test('auth rate limits include account identity, not only IP', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-rate-account-'));
  const srv = await startServer({ root, port: 18244, mode: 'open', extraEnv: { SSH_VAULT2_AUTH_ACCOUNT_RATE_MAX: '3' } });
  try {
    for (let i = 0; i < 3; i++) {
      const r = await api(srv.base, '/api/v1/accounts/token', { account: 'missing@example.com', password: 'wrong-password' });
      assert.notEqual(r.status, 429);
    }
    const limited = await api(srv.base, '/api/v1/accounts/token', { account: 'missing@example.com', password: 'wrong-password' });
    assert.equal(limited.status, 429);
    assert.match(limited.json.error, /rate limit/i);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('sync rate limits include account and token hash', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-rate-token-'));
  const srv = await startServer({ root, port: 18245, mode: 'open', extraEnv: { SSH_VAULT2_SYNC_TOKEN_RATE_MAX: '2' } });
  try {
    for (let i = 0; i < 2; i++) {
      const r = await fetch(srv.base + '/api/v1/sync/missing@example.com', { headers: { 'X-Sync-Token': 'same-bad-token' } });
      assert.notEqual(r.status, 429);
    }
    const limited = await fetch(srv.base + '/api/v1/sync/missing@example.com', { headers: { 'X-Sync-Token': 'same-bad-token' } });
    assert.equal(limited.status, 429);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('sync write enforces per-account quota and preserves existing data', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-sync-quota-'));
  const srv = await startServer({ root, port: 18250, mode: 'open', extraEnv: { SSH_VAULT2_SYNC_ACCOUNT_BYTES_MAX: '1400' } });
  try {
    const account = 'quota@example.com';
    let r = await api(srv.base, '/api/v1/self/register', { account, username: 'quotauser', password: 'test-password' });
    assert.equal(r.status, 200);
    const token = r.json.token;
    const okBlob = { ciphertext: 'a'.repeat(512), salt: 'salt', nonce: 'nonce' };
    r = await syncPut(srv.base, account, token, okBlob);
    assert.equal(r.status, 200);
    const syncPath = path.join(root, 'data', 'sync', account + '.json');
    const before = fs.readFileSync(syncPath, 'utf8');
    const tooLarge = { ciphertext: 'b'.repeat(1800), salt: 'salt', nonce: 'nonce' };
    r = await syncPut(srv.base, account, token, tooLarge);
    assert.equal(r.status, 413);
    assert.match(r.json.error, /quota|limit/i);
    assert.equal(fs.readFileSync(syncPath, 'utf8'), before);
    const backupDir = path.join(root, 'data', 'sync-backups', account);
    assert.equal(fs.existsSync(backupDir), false, 'rejected writes must not create backups');
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('sync write enforces global quota and backup retention count', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-sync-global-quota-'));
  const srv = await startServer({ root, port: 18251, mode: 'open', extraEnv: { SSH_VAULT2_SYNC_GLOBAL_BYTES_MAX: '2400', SSH_VAULT2_SYNC_BACKUP_MAX_COUNT: '2' } });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'one@example.com', username: 'oneuser', password: 'test-password' });
    assert.equal(r.status, 200);
    const t1 = r.json.token;
    r = await api(srv.base, '/api/v1/self/register', { account: 'two@example.com', username: 'twouser', password: 'test-password' });
    assert.equal(r.status, 200);
    const t2 = r.json.token;
    for (const ch of ['a', 'b', 'c', 'd']) {
      r = await syncPut(srv.base, 'one@example.com', t1, { ciphertext: ch.repeat(512), salt: 'salt', nonce: 'nonce' });
      assert.equal(r.status, 200);
      await wait(5);
    }
    const backups = fs.readdirSync(path.join(root, 'data', 'sync-backups', 'one@example.com')).filter(n => n.endsWith('.json'));
    assert.equal(backups.length, 2);

    r = await syncPut(srv.base, 'two@example.com', t2, { ciphertext: 'z'.repeat(2000), salt: 'salt', nonce: 'nonce' });
    assert.equal(r.status, 507);
    assert.match(r.json.error, /global|storage|quota/i);
    assert.equal(fs.existsSync(path.join(root, 'data', 'sync', 'two@example.com.json')), false);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('self import enforces sync account quota before writing backups', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-import-quota-'));
  const srv = await startServer({ root, port: 18252, mode: 'open', extraEnv: { SSH_VAULT2_SYNC_ACCOUNT_BYTES_MAX: '1400' } });
  try {
    const account = 'importquota@example.com';
    let r = await api(srv.base, '/api/v1/self/register', { account, username: 'importquota', password: 'test-password' });
    assert.equal(r.status, 200);
    const cookie = r.headers.get('set-cookie').split(';')[0];
    const token = r.json.token;
    r = await syncPut(srv.base, account, token, { ciphertext: 'a'.repeat(512), salt: 'salt', nonce: 'nonce' });
    assert.equal(r.status, 200);
    const syncPath = path.join(root, 'data', 'sync', account + '.json');
    const before = fs.readFileSync(syncPath, 'utf8');
    r = await api(srv.base, '/api/v1/self/import', { profile: { account }, sync: { account, blob: { ciphertext: 'b'.repeat(1800), salt: 'salt', nonce: 'nonce' } } }, cookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /quota|limit/i);
    assert.equal(fs.readFileSync(syncPath, 'utf8'), before);
    const backupDir = path.join(root, 'data', 'sync-backups', account);
    assert.equal(fs.existsSync(backupDir), false, 'rejected import must not create backup');
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('account endpoints use uniform non-enumerating errors', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-enum-'));
  const srv = await startServer({ root, port: 18246, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'enum@example.com', username: 'enumuser', password: 'test-password' });
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/accounts/token', { account: 'missing@example.com', password: 'test-password' });
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'bad username or password');
    r = await api(srv.base, '/api/v1/accounts/token', { account: 'enum@example.com', password: 'wrong-password' });
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'bad username or password');
    r = await api(srv.base, '/api/v1/self/register', { account: 'enum@example.com', username: 'otheruser', password: 'test-password' });
    assert.equal(r.status, 409);
    assert.equal(r.json.error, 'registration cannot be completed');
    r = await api(srv.base, '/api/v1/self/register', { account: 'other@example.com', username: 'enumuser', password: 'test-password' });
    assert.equal(r.status, 409);
    assert.equal(r.json.error, 'registration cannot be completed');
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('release file serving ignores symlinks and filesystem races', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-release-safe-'));
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  fs.writeFileSync(path.join(root, 'downloads', 'ssh-vault2-9.9.9-linux-amd64.tar.gz'), 'ok');
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt'), crypto.createHash('sha256').update('ok').digest('hex') + '  ssh-vault2-9.9.9-linux-amd64.tar.gz\n');
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt.sig'), 'sig\n');
  fs.symlinkSync('/etc/passwd', path.join(root, 'downloads', 'ssh-vault2-9.9.9-linux-amd64-evil.tar.gz'));
  fs.mkdirSync(path.join(root, 'downloads', 'ssh-vault2-9.9.9-linux-amd64-dir.tar.gz'));
  const srv = await startServer({ root, port: 18247 });
  try {
    const feed = await api(srv.base, '/api/v1/releases');
    assert.equal(feed.status, 200);
    const names = feed.json.versions.flatMap(v => v.assets.map(a => a.name));
    assert.deepEqual(names, ['ssh-vault2-9.9.9-linux-amd64.tar.gz']);
    const evil = await fetch(srv.base + '/downloads/ssh-vault2-9.9.9-linux-amd64-evil.tar.gz');
    assert.equal(evil.status, 404);
    const dir = await fetch(srv.base + '/downloads/ssh-vault2-9.9.9-linux-amd64-dir.tar.gz');
    assert.equal(dir.status, 404);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('release feed reads checksums from downloads fallback', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-release-'));
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  const name = 'ssh-vault2-9.9.9-linux-amd64.tar.gz';
  const body = Buffer.from('fake-release');
  const hash = crypto.createHash('sha256').update(body).digest('hex');
  fs.writeFileSync(path.join(root, 'downloads', name), body);
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt'), `${hash}  ${name}\n`);
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt.sig'), 'sig\n');
  const srv = await startServer({ root, port: 18239 });
  try {
    const r = await api(srv.base, '/api/v1/releases');
    assert.equal(r.status, 200);
    assert.equal(r.json.versions[0].assets[0].sha256, hash);
    const sums = await fetch(srv.base + '/SHA256SUMS.txt');
    assert.equal(sums.status, 200);
    assert.match(await sums.text(), new RegExp(hash));
  } finally { await stopServer(srv.child); }
});

test('release feed includes sanitized per-version changelog', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-changelog-'));
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  const name = 'ssh-vault2-9.9.9-linux-amd64.tar.gz';
  const body = Buffer.from('fake-release');
  const hash = crypto.createHash('sha256').update(body).digest('hex');
  fs.writeFileSync(path.join(root, 'downloads', name), body);
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt'), `${hash}  ${name}\n`);
  fs.writeFileSync(path.join(root, 'downloads', 'SHA256SUMS.txt.sig'), 'sig\n');
  fs.writeFileSync(path.join(root, 'downloads', 'CHANGELOG.json'), JSON.stringify({ versions: { '9.9.9': ['Update-Dialog zeigt Changelog', 'SFTP Fix\nmit Zeilenumbruch'] } }));
  const srv = await startServer({ root, port: 18248 });
  try {
    const r = await api(srv.base, '/api/v1/releases');
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.changelog, ['Update-Dialog zeigt Changelog', 'SFTP Fix mit Zeilenumbruch']);
    assert.deepEqual(r.json.versions[0].changelog, ['Update-Dialog zeigt Changelog', 'SFTP Fix mit Zeilenumbruch']);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('registration modes, admin status, export, and TOTP challenge', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  let srv = await startServer({ root, port: 18231, mode: 'approval', admins: 'admin@example.com' });
  try {
    let r = await api(srv.base, '/api/v1/self/config');
    assert.equal(r.json.registration.mode, 'approval');
    r = await api(srv.base, '/api/v1/self/register', { account: 'bob@example.com', username: 'bobuser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.pending, true);
    r = await api(srv.base, '/api/v1/self/login', { account: 'bob@example.com', username: 'bobuser', password: 'test-password' });
    assert.equal(r.status, 403);
  } finally { await stopServer(srv.child); }

  srv = await startServer({ root, port: 18231, mode: 'open', admins: 'admin@example.com' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'admin@example.com', username: 'adminuser', password: 'admin-password' });
    assert.equal(r.status, 200);
  } finally { await stopServer(srv.child); }

  srv = await startServer({ root, port: 18231, mode: 'approval', admins: 'admin@example.com' });
  try {
    let r = await api(srv.base, '/api/v1/self/login', { account: 'admin@example.com', username: 'adminuser', password: 'admin-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.isAdmin, true);
    const cookie = r.headers.get('set-cookie').split(';')[0];

    r = await api(srv.base, '/api/v1/admin/settings/registration', { mode: 'closed' }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.registration.mode, 'closed');
    r = await api(srv.base, '/api/v1/self/config');
    assert.equal(r.json.registration.mode, 'closed');
    r = await api(srv.base, '/api/v1/self/register', { account: 'closed@example.com', username: 'closeduser', password: 'test-password' });
    assert.equal(r.status, 403);

    r = await api(srv.base, '/api/v1/admin/settings/registration', { mode: 'open' }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.registration.mode, 'open');

    r = await api(srv.base, '/api/v1/admin/users/status', { account: 'bob@example.com', status: 'active' }, cookie);
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/admin/users/role', { account: 'bob@example.com', isAdmin: true }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.user.isAdmin, true);
    r = await api(srv.base, '/api/v1/self/login', { account: 'bob@example.com', username: 'bobuser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.isAdmin, true);
    const bobCookie = r.headers.get('set-cookie').split(';')[0];
    r = await api(srv.base, '/api/v1/admin/users', undefined, bobCookie);
    assert.equal(r.status, 200);

    r = await api(srv.base, '/api/v1/admin/users/status', { account: 'bob@example.com', status: 'suspended' }, bobCookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /self status lockout/);

    r = await api(srv.base, '/api/v1/admin/users/status', { account: 'admin@example.com', status: 'suspended' }, bobCookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /env admin status/);

    r = await api(srv.base, '/api/v1/admin/users/delete', { account: 'admin@example.com' }, bobCookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /env admin delete/);

    r = await api(srv.base, '/api/v1/admin/users/role', { account: 'bob@example.com', isAdmin: 'false' }, cookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /bad admin role value/);

    r = await api(srv.base, '/api/v1/admin/users/role', { account: 'bob@example.com', isAdmin: false }, cookie);
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/admin/users', undefined, bobCookie);
    assert.equal(r.status, 403);

    r = await api(srv.base, '/api/v1/admin/users/role', { account: 'bob@example.com', isAdmin: true }, cookie);
    assert.equal(r.status, 200);

    const bobFile = path.join(root, 'data', 'accounts', 'bob@example.com.json');
    const bob = JSON.parse(fs.readFileSync(bobFile, 'utf8'));
    bob.totpSecret = 'JBSWY3DPEHPK3PXP';
    fs.writeFileSync(bobFile, JSON.stringify(bob, null, 2));
    r = await api(srv.base, '/api/v1/self/login', { account: 'bob@example.com', username: 'bobuser', password: 'test-password' });
    assert.equal(r.status, 401);
    assert.equal(r.json.totpRequired, true);
    r = await api(srv.base, '/api/v1/accounts/token', { account: 'bobuser', password: 'test-password' });
    assert.equal(r.status, 401);
    assert.equal(r.json.totpRequired, true);
    r = await api(srv.base, '/api/v1/accounts/token', { account: 'bobuser', password: 'test-password', totp: testTotp('JBSWY3DPEHPK3PXP') });
    assert.equal(r.status, 200);
    assert.ok(r.json.token);

    r = await api(srv.base, '/api/v1/self/export', undefined, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.account, 'admin@example.com');
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('closed registration mode rejects registration', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18232, mode: 'closed' });
  try {
    const r = await api(srv.base, '/api/v1/self/register', { account: 'x@example.com', username: 'xuser', password: 'test-password' });
    assert.equal(r.status, 403);
    assert.match(r.json.error, /disabled/);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('password reset requires email account and consumes hashed reset token', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18234, mode: 'open', extraEnv: { SSH_VAULT2_SMTP_DRY_RUN: '1', SSH_VAULT2_PUBLIC_URL: 'http://127.0.0.1:18234' } });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'reset@example.com', username: 'resetuser', password: 'old-password' });
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/self/password/forgot', { email: 'reset@example.com' });
    assert.equal(r.status, 200);
    assert.match(r.json.message, /Reset-Link|existiert|versendet/);

    const f = path.join(root, 'data', 'accounts', 'reset@example.com.json');
    let rec = JSON.parse(fs.readFileSync(f, 'utf8'));
    assert.ok(rec.passwordReset?.sha256);
    assert.notEqual(rec.passwordReset.sha256, 'test-reset-token');
    rec.passwordReset = { sha256: crypto.createHash('sha256').update('test-reset-token').digest('hex'), expiresAt: Date.now() + 60000, createdAt: Date.now() };
    fs.writeFileSync(f, JSON.stringify(rec, null, 2));

    r = await api(srv.base, '/api/v1/self/password/reset', { token: 'test-reset-token', newPassword: 'new-password' });
    assert.equal(r.status, 200);
    rec = JSON.parse(fs.readFileSync(f, 'utf8'));
    assert.equal(rec.passwordReset, undefined);
    assert.ok(rec.tokenSha256);

    r = await api(srv.base, '/api/v1/self/login', { account: 'reset@example.com', username: 'resetuser', password: 'old-password' });
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/login', { account: 'reset@example.com', password: 'new-password' });
    assert.equal(r.status, 200);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('cookie APIs reject cross-origin unsafe requests', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18242, mode: 'open', admins: 'admin@example.com' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'admin@example.com', username: 'adminuser', password: 'test-password' });
    assert.equal(r.status, 200);
    const cookie = r.headers.get('set-cookie').split(';')[0];
    r = await api(srv.base, '/api/v1/self/token', {}, cookie, { Origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    assert.match(r.json.error, /csrf|origin/i);
    r = await api(srv.base, '/api/v1/admin/settings/registration', { mode: 'closed' }, cookie, { Origin: 'https://evil.example' });
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/token', {}, cookie, { Origin: srv.base.replace('http://', 'https://') });
    assert.equal(r.status, 403);
    assert.match(r.json.error, /csrf|origin/i);
    r = await fetch(srv.base + '/api/v1/self/config', { headers: { Origin: srv.base.replace('http://', 'https://') } });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('access-control-allow-origin'), null);
    r = await fetch(srv.base + '/api/v1/self/logout', { method: 'GET', headers: { Cookie: cookie } });
    assert.equal(r.status, 405);
    r = await api(srv.base, '/api/v1/self/token', {}, cookie, { Origin: srv.base });
    assert.equal(r.status, 200);
    assert.ok(r.json.token);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('password change invalidates old session and old sync tokens', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18243, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'rotate@example.com', username: 'rotateuser', password: 'old-password' });
    assert.equal(r.status, 200);
    const oldCookie = r.headers.get('set-cookie').split(';')[0];
    const oldToken = r.json.token;
    const blob = { ciphertext: 'x'.repeat(512), salt: 'salt', nonce: 'nonce' };
    r = await fetch(srv.base + '/api/v1/sync/rotate@example.com', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Sync-Token': oldToken }, body: JSON.stringify(blob) });
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/self/password', { currentPassword: 'old-password', newPassword: 'new-password' }, oldCookie);
    assert.equal(r.status, 200);
    const newCookie = r.headers.get('set-cookie').split(';')[0];
    const newToken = r.json.token;
    assert.ok(newToken);
    r = await api(srv.base, '/api/v1/self/me', undefined, oldCookie);
    assert.equal(r.status, 401);
    r = await fetch(srv.base + '/api/v1/sync/rotate@example.com', { method: 'GET', headers: { 'X-Sync-Token': oldToken } });
    assert.equal(r.status, 403);
    r = await fetch(srv.base + '/api/v1/sync/rotate@example.com', { method: 'GET', headers: { 'X-Sync-Token': newToken } });
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/self/me', undefined, newCookie);
    assert.equal(r.status, 200);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('legacy non-email account login preserves exact case while new accounts require email', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18235, mode: 'open' });
  try {
    const salt = 'legacy-salt';
    const legacy = { status: 'active', passwordSalt: salt, passwordHash: crypto.scryptSync('legacy-password', salt, 32).toString('base64'), createdAt: Date.now(), updatedAt: Date.now() };
    const accountDir = path.join(root, 'data', 'accounts');
    fs.writeFileSync(path.join(accountDir, 'LegacyUser.json'), JSON.stringify(legacy, null, 2));

    let r = await api(srv.base, '/api/v1/self/login', { account: 'LegacyUser', password: 'legacy-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.account, 'LegacyUser');

    r = await api(srv.base, '/api/v1/self/login', { account: 'legacyuser', password: 'legacy-password' });
    assert.equal(r.status, 403);

    r = await api(srv.base, '/api/v1/self/register', { account: 'not-an-email', username: 'notemailuser', password: 'test-password' });
    assert.equal(r.status, 400);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('forgot password returns service unavailable uniformly when mail is disabled', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18236, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/password/forgot', { email: 'missing@example.com' });
    assert.equal(r.status, 503);
    r = await api(srv.base, '/api/v1/self/register', { account: 'exists@example.com', username: 'existsuser', password: 'test-password' });
    assert.equal(r.status, 200);
    r = await api(srv.base, '/api/v1/self/password/forgot', { email: 'exists@example.com' });
    assert.equal(r.status, 503);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});



test('new email account can login by username alias or email and rejects duplicate usernames', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18237, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'nouser@example.com', password: 'test-password' });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /username required/);
    r = await api(srv.base, '/api/v1/self/register', { account: 'alias@example.com', username: 'CoolUser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.username, 'cooluser');
    r = await api(srv.base, '/api/v1/self/login', { account: 'alias@example.com', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.account, 'alias@example.com');
    r = await api(srv.base, '/api/v1/self/login', { account: 'CoolUser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.account, 'alias@example.com');
    r = await api(srv.base, '/api/v1/self/register', { account: 'other@example.com', username: 'cooluser', password: 'test-password' });
    assert.equal(r.status, 409);
    assert.match(r.json.error, /registration cannot be completed/);

    const accountDir = path.join(root, 'data', 'accounts');
    fs.writeFileSync(path.join(accountDir, 'LegacyName.json'), JSON.stringify({ status: 'active', passwordSalt: 'x', passwordHash: 'x', createdAt: Date.now(), updatedAt: Date.now() }, null, 2));
    r = await api(srv.base, '/api/v1/self/register', { account: 'third@example.com', username: 'legacyname', password: 'test-password' });
    assert.equal(r.status, 409);
    assert.match(r.json.error, /registration cannot be completed/);

    r = await api(srv.base, '/api/v1/self/register', { account: 'baduser@example.com', username: 'bad user', password: 'test-password' });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /bad username/);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});


test('self email change preserves uniqueness and moves sync data; export can be imported back', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18239, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'old@example.com', username: 'olduser', password: 'test-password' });
    assert.equal(r.status, 200);
    const cookie = r.headers.get('set-cookie').split(';')[0];
    r = await api(srv.base, '/api/v1/self/register', { account: 'taken@example.com', username: 'takenuser', password: 'test-password' });
    assert.equal(r.status, 200);

    const oldSync = path.join(root, 'data', 'sync', 'old@example.com.json');
    const blob = { ciphertext: 'x'.repeat(512), salt: 'salt', nonce: 'nonce' };
    fs.writeFileSync(oldSync, JSON.stringify({ account: 'old@example.com', updatedAt: Date.now(), blob }, null, 2));

    r = await api(srv.base, '/api/v1/self/email', { email: 'taken@example.com', password: 'test-password' }, cookie);
    assert.equal(r.status, 409);
    r = await api(srv.base, '/api/v1/self/email', { email: 'new@example.com', password: 'wrongpass' }, cookie);
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/email', { email: 'new@example.com', password: 'test-password' }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.account, 'new@example.com');
    assert.equal(r.json.profile.username, 'olduser');
    assert.equal(fs.existsSync(path.join(root, 'data', 'accounts', 'old@example.com.json')), false);
    assert.equal(fs.existsSync(path.join(root, 'data', 'accounts', 'new@example.com.json')), true);
    assert.equal(fs.existsSync(oldSync), false);
    const movedSync = JSON.parse(fs.readFileSync(path.join(root, 'data', 'sync', 'new@example.com.json'), 'utf8'));
    assert.equal(movedSync.account, 'new@example.com');
    assert.equal(movedSync.blob.ciphertext, blob.ciphertext);
    const newCookie = r.headers.get('set-cookie').split(';')[0];

    r = await api(srv.base, '/api/v1/self/login', { account: 'old@example.com', password: 'test-password' });
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/login', { account: 'olduser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.account, 'new@example.com');
    assert.equal(r.json.profile.username, 'olduser');

    r = await api(srv.base, '/api/v1/self/username', { username: 'takenuser', password: 'test-password' }, newCookie);
    assert.equal(r.status, 409);
    r = await api(srv.base, '/api/v1/self/username', { username: 'newuser', password: 'wrongpass' }, newCookie);
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/username', { username: 'newuser', password: 'test-password' }, newCookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.account, 'new@example.com');
    assert.equal(r.json.profile.username, 'newuser');
    r = await api(srv.base, '/api/v1/self/login', { account: 'olduser', password: 'test-password' });
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/login', { account: 'newuser', password: 'test-password' });
    assert.equal(r.status, 200);
    assert.equal(r.json.account, 'new@example.com');

    const exported = await api(srv.base, '/api/v1/self/export', undefined, newCookie);
    assert.equal(exported.status, 200);
    assert.equal(exported.json.sync.blob.ciphertext, blob.ciphertext);
    fs.unlinkSync(path.join(root, 'data', 'sync', 'new@example.com.json'));
    r = await api(srv.base, '/api/v1/self/import', { ...exported.json, profile: { account: 'other@example.com' } }, newCookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /another account/);

    r = await api(srv.base, '/api/v1/self/import', { profile: { account: 'new@example.com' }, sync: { account: 'new@example.com', blob: { ciphertext: 'tiny', salt: 'salt', nonce: 'nonce' } } }, newCookie);
    assert.equal(r.status, 400);
    assert.match(r.json.error, /too small/);

    r = await api(srv.base, '/api/v1/self/import', exported.json, newCookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.sync.hasSync, true);
    const imported = JSON.parse(fs.readFileSync(path.join(root, 'data', 'sync', 'new@example.com.json'), 'utf8'));
    assert.equal(imported.account, 'new@example.com');
    assert.equal(imported.blob.ciphertext, blob.ciphertext);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('totp setup returns otpauth and enabled totp can be disabled', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18240, mode: 'open' });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'totp@example.com', username: 'totpuser', password: 'test-password' });
    assert.equal(r.status, 200);
    const cookie = r.headers.get('set-cookie').split(';')[0];
    r = await api(srv.base, '/api/v1/self/totp/setup', {}, cookie);
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/totp/setup', { password: 'test-password' }, cookie);
    assert.equal(r.status, 200);
    assert.match(r.json.otpauth, /^otpauth:\/\/totp\/ssh-vault2:/);
    const secret = r.json.secret;
    r = await api(srv.base, '/api/v1/self/totp/enable', { secret, code: testTotp(secret) }, cookie);
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/totp/enable', { password: 'test-password', secret, code: testTotp(secret) }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.totpEnabled, true);
    const accountFile = path.join(root, 'data', 'accounts', 'totp@example.com.json');
    const stored = JSON.parse(fs.readFileSync(accountFile, 'utf8'));
    assert.equal(stored.totpSecret, undefined);
    assert.match(stored.totpSecretEnc, /^v1\./);
    assert.notEqual(stored.totpSecretEnc, secret);
    r = await api(srv.base, '/api/v1/self/totp/disable', { password: 'wrongpass', code: testTotp(secret) }, cookie);
    assert.equal(r.status, 403);
    r = await api(srv.base, '/api/v1/self/totp/disable', { password: 'test-password', code: testTotp(secret) }, cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json.profile.totpEnabled, false);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('https public url enables secure cookie and security headers', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18238, mode: 'open', extraEnv: { SSH_VAULT2_PUBLIC_URL: 'https://ssh-vault.example.org' } });
  try {
    let r = await api(srv.base, '/api/v1/self/register', { account: 'secure@example.com', username: 'secureuser', password: 'test-password' });
    assert.equal(r.status, 200);
    const setCookie = r.headers.get('set-cookie') || '';
    assert.match(setCookie, /; Secure/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    const csp = r.headers.get('content-security-policy') || '';
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.doesNotMatch(csp, /unsafe-inline/);
    assert.doesNotMatch(csp, /Strict-Transport-Security/);
    assert.equal(r.headers.get('strict-transport-security'), null, 'HSTS is owned by the reverse proxy to avoid duplicate headers');
    const forgot = await fetch(srv.base + '/api/v1/self/config').then(x => x.json());
    assert.equal(forgot.login.usernameLogin, true);
    assert.equal(forgot.login.usernameRequiredForNewAccounts, true);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('landing and account pages are dark and routed separately', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-server-test-'));
  const srv = await startServer({ root, port: 18233, mode: 'approval', admins: 'admin@example.com' });
  try {
    const landing = await fetch(srv.base + '/').then(r => r.text());
    assert.match(landing, /SSH\. SFTP\. RDP\. Sync\./);
    assert.match(landing, /Quickstart/);
    assert.match(landing, /href="\/desktop-guide"/);
    assert.match(landing, /href="\/server-guide"/);
    assert.match(landing, /href="\/web-guide"/);
    assert.doesNotMatch(landing, /<h2>Ausführliche Desktop-App-Anleitung\.<\/h2>/);
    assert.doesNotMatch(landing, /Benutzeranleitung/);
    assert.match(landing, /background:#000/);
    assert.match(landing, /href="\/account"/);

    const account = await fetch(srv.base + '/account').then(r => r.text());
    assert.match(account, /Dark Sync Portal/);
    assert.match(account, /id="totpLoginBox" class="totpBox hidden"/);
    assert.match(account, /Passwort vergessen\?/);
    assert.match(account, /id="resetBox" class="totpBox hidden"/);
    assert.match(account, /Benutzername oder E-Mail/);
    assert.match(account, /id="registerUsernameBox"/);
    assert.doesNotMatch(account, /Benutzername optional/);
    assert.match(account, /Admin Panel/);
    assert.match(account, /data-reg="open"/);
    assert.match(account, /Admin machen/);
    assert.match(account, /body\{[^}]*background:#000;color:#f5f5f7/);
    assert.match(account, /\.card,\.authCard\{background:rgba\(255,255,255,\.07\)/);
    assert.match(account, /#submitBtn\{width:100%;margin-top:18px\}/);
    assert.match(account, /#resetBox \.primary,#changePasswordBtn,#changeEmailBtn,#changeUsernameBtn,#importBtn,#totpSetup \.primary,#totpDisable \.ghost\{width:100%;margin-top:18px\}/);
    assert.match(account, /id="usernameNew"/);
    assert.match(account, /id="emailNew"/);
    assert.match(account, /id="importFile"/);
    assert.match(account, /id="totpQr"/);
    assert.match(account, /function humanSize/);
    assert.match(account, /qrcode/);
    assert.match(account, /class="card accountSecurity"/);
    assert.doesNotMatch(account, /class="card accountSecurity span2"/);
    assert.match(account, /class="securityGrid"/);
    assert.match(account, /\.accountSecurity \.securityGrid\{grid-template-columns:1fr\}/);
    assert.match(account, /class=\"tokenListScroll\"/);
    assert.match(account, /scrollbar-color:#3a3a3c #050506/);
    assert.match(account, /\.tokenListScroll::-webkit-scrollbar-track\{background:#050506/);
    assert.match(account, /\.cardStack\{[^}]*align-self:start/);
    assert.match(account, /const displayName=profile.username\?'@'\+profile.username:profile.account/);
    assert.match(account, /class="filePicker"/);
    assert.match(account, /id="importFileName"/);
    assert.match(account, /function updateImportFileName/);
    assert.match(account, /class="authLinks"/);
    assert.match(account, /id="credentialFields"/);
    assert.match(account, /name="username" autocomplete="username"/);
    assert.match(account, /id="totpLoginMount"/);
    assert.match(account, /id="totpChallenge" inputmode="numeric"[^']+autocomplete="off"[^']+data-bwignore="true"/);
    assert.doesNotMatch(account, /autocomplete="one-time-code"/);
    assert.doesNotMatch(account, /name="one-time-code"/);
    assert.match(account, /id="accountPassword"/);
    assert.doesNotMatch(account, /id="emailPassword"/);
    assert.doesNotMatch(account, /id="currentPassword"/);
    assert.doesNotMatch(account, /example-org/);
    assert.doesNotMatch(account, /Registrierung kann offen/);
    assert.doesNotMatch(account, /autocomplete="username email"/);
    assert.match(account, /id="changePasswordBtn"/);
    assert.match(account, /history\.replaceState\(null,''/);
  } finally { await stopServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});
