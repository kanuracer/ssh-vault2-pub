import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

const serverPath = new URL('./server.mjs', import.meta.url).pathname;
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
async function startAuditServer(root, port) {
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  const child = spawn(process.execPath, [serverPath], { env: { ...process.env, SSH_VAULT2_ROOT: root, PORT: String(port), SSH_VAULT2_REGISTRATION_MODE: 'open' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50; i++) { try { const r = await fetch(base + '/healthz'); if (r.ok) return { child, base }; } catch {} await wait(100); }
  child.kill(); throw new Error('server did not start');
}
async function stopAuditServer(child) { child.kill(); await wait(100); }
async function post(base, p, body, cookie = '') {
  const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base, ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(body) });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = { text }; }
  return { status: r.status, headers: r.headers, json };
}
const b32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(str) { let bits = 0, value = 0; const out = []; for (const ch of String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '')) { const idx = b32.indexOf(ch); if (idx < 0) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
function totp(secret, step = Math.floor(Date.now() / 30000)) { const key = base32Decode(secret); const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(step / 0x100000000), 0); msg.writeUInt32BE(step >>> 0, 4); const h = crypto.createHmac('sha1', key).update(msg).digest(); const o = h[h.length - 1] & 15; const bin = ((h[o] & 127) << 24) | ((h[o + 1] & 255) << 16) | ((h[o + 2] & 255) << 8) | (h[o + 3] & 255); return String(bin % 1000000).padStart(6, '0'); }

test('TOTP setup and enable require current password step-up', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-audit-totp-stepup-'));
  const srv = await startAuditServer(root, 18321);
  try {
    const password = 'test-password-long';
    const reg = await post(srv.base, '/api/v1/self/register', { email: 'stepup@example.com', username: 'stepup', password });
    assert.equal(reg.status, 200);
    const cookie = reg.headers.get('set-cookie')?.split(';')[0] || '';
    const denied = await post(srv.base, '/api/v1/self/totp/setup', {}, cookie);
    assert.equal(denied.status, 403);
    assert.match(denied.json.error, /password/i);
    const setup = await post(srv.base, '/api/v1/self/totp/setup', { password }, cookie);
    assert.equal(setup.status, 200);
    const deniedEnable = await post(srv.base, '/api/v1/self/totp/enable', { secret: setup.json.secret, code: totp(setup.json.secret) }, cookie);
    assert.equal(deniedEnable.status, 403);
    const enabled = await post(srv.base, '/api/v1/self/totp/enable', { password, secret: setup.json.secret, code: totp(setup.json.secret) }, cookie);
    assert.equal(enabled.status, 200);
  } finally { await stopAuditServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('release feed excludes detached signatures and classifies download assets by platform', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-audit-release-assets-'));
  fs.mkdirSync(path.join(root, 'downloads'), { recursive: true });
  const artifacts = {
    'ssh-vault2-9.9.9-linux-amd64.tar.gz': 'linux artifact',
    'ssh-vault2-9.9.9-windows-amd64-installer.exe': 'windows artifact',
    'ssh-vault2-9.9.9-macos-arm64.app.zip': 'macos artifact'
  };
  let manifest = '';
  for (const [name, body] of Object.entries(artifacts)) {
    fs.writeFileSync(path.join(root, 'downloads', name), body);
    fs.writeFileSync(path.join(root, 'downloads', name + '.sig'), 'signature');
    manifest += `${crypto.createHash('sha256').update(body).digest('hex')}  ${name}\n${crypto.createHash('sha256').update('signature').digest('hex')}  ${name}.sig\n`;
  }
  fs.writeFileSync(path.join(root, 'SHA256SUMS.txt'), manifest);
  const srv = await startAuditServer(root, 18322);
  try {
    const r = await fetch(srv.base + '/api/v1/releases');
    assert.equal(r.status, 200);
    const j = await r.json();
    const byName = Object.fromEntries(j.files.map(x => [x.name, x]));
    assert.equal(byName['ssh-vault2-9.9.9-linux-amd64.tar.gz'].platform, 'linux');
    assert.equal(byName['ssh-vault2-9.9.9-windows-amd64-installer.exe'].platform, 'windows');
    assert.equal(byName['ssh-vault2-9.9.9-macos-arm64.app.zip'].platform, 'macos');
    assert.ok(!j.files.some(x => x.name.endsWith('.sig')));
  } finally { await stopAuditServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});

test('sync auth uses generic unauthorized for nonexistent accounts with token', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-audit-sync-enum-'));
  const srv = await startAuditServer(root, 18323);
  try {
    const r = await fetch(srv.base + '/api/v1/sync/doesnotexist@example.invalid', { headers: { 'X-Sync-Token': 'invalid-test-token' } });
    const j = await r.json();
    assert.equal(r.status, 403);
    assert.equal(j.error, 'sync unauthorized');
  } finally { await stopAuditServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});



test('startup migrates legacy plaintext TOTP secrets before login', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sshv-audit-totp-migrate-'));
  const accounts = path.join(root, 'data', 'accounts');
  fs.mkdirSync(accounts, { recursive: true });
  const account = 'legacytotp@example.com';
  fs.writeFileSync(path.join(accounts, account + '.json'), JSON.stringify({ account, status: 'active', passwordSalt: 'x', passwordHash: 'x', totpSecret: 'JBSWY3DPEHPK3PXP', createdAt: Date.now(), updatedAt: Date.now() }, null, 2));
  const srv = await startAuditServer(root, 18324);
  try {
    const rec = JSON.parse(fs.readFileSync(path.join(accounts, account + '.json'), 'utf8'));
    assert.equal(rec.totpSecret, undefined);
    assert.match(rec.totpSecretEnc, /^v1\./);
  } finally { await stopAuditServer(srv.child); fs.rmSync(root, { recursive: true, force: true }); }
});
