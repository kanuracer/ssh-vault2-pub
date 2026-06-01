import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import tls from 'node:tls';

const appDir = path.dirname(new URL(import.meta.url).pathname);
const root = process.env.SSH_VAULT2_ROOT || '/opt/ssh-vault2-server';
const downloads = path.join(root, 'downloads');
const changelogFile = path.join(downloads, 'CHANGELOG.json');
const data = path.join(root, 'data');
const syncDir = path.join(data, 'sync');
const syncBackupDir = path.join(data, 'sync-backups');
const accountDir = path.join(data, 'accounts');
const sessionSecretFile = path.join(data, 'account-session-secret');
const settingsFile = path.join(data, 'settings.json');
const port = Number(process.env.PORT || 18080);
const serverVersion = '1.2.26';
const envBool = (name, def = false) => {
  const v = String(process.env[name] ?? '').trim().toLowerCase();
  if (!v) return def;
  return ['1', 'true', 'yes', 'on'].includes(v);
};
const envInt = (name, def) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
};
const rawRegMode = String(process.env.SSH_VAULT2_REGISTRATION_MODE || '').trim().toLowerCase();
const defaultRegistrationMode = ['open', 'approval', 'closed'].includes(rawRegMode) ? rawRegMode : (envBool('SSH_VAULT2_REGISTRATION_APPROVAL') ? 'approval' : (envBool('SSH_VAULT2_REGISTRATION_ENABLED', true) ? 'open' : 'closed'));
const validRegistrationModes = new Set(['open', 'approval', 'closed']);
const adminAccountsRaw = String(process.env.SSH_VAULT2_ADMIN_ACCOUNTS || process.env.SSH_VAULT2_ADMINS || '');
const publicUrl = String(process.env.SSH_VAULT2_PUBLIC_URL || `http://127.0.0.1:${port}`).replace(/\/+$/, '');
const publicIsHttps = publicUrl.startsWith('https://');
const smtpHost = String(process.env.SSH_VAULT2_SMTP_HOST || '').trim();
const smtpPort = Number(process.env.SSH_VAULT2_SMTP_PORT || 465);
const smtpUser = String(process.env.SSH_VAULT2_SMTP_USER || '').trim();
const smtpPassFile = String(process.env.SSH_VAULT2_SMTP_PASS_FILE || '').trim();
const smtpPass = String(process.env.SSH_VAULT2_SMTP_PASS || (smtpPassFile && fs.existsSync(smtpPassFile) ? fs.readFileSync(smtpPassFile, 'utf8').trim() : ''));
const smtpFrom = String(process.env.SSH_VAULT2_SMTP_FROM || smtpUser || '').trim();
const smtpSecure = envBool('SSH_VAULT2_SMTP_SSL', true);
const smtpDryRun = envBool('SSH_VAULT2_SMTP_DRY_RUN', false);
const resetTtlMs = Number(process.env.SSH_VAULT2_RESET_TTL_MS || 30 * 60 * 1000);
const mailEnabled = smtpDryRun || !!(smtpHost && smtpUser && smtpPass && smtpFrom);
const authAccountRateMax = envInt('SSH_VAULT2_AUTH_ACCOUNT_RATE_MAX', 8);
const syncAccountRateMax = envInt('SSH_VAULT2_SYNC_ACCOUNT_RATE_MAX', 120);
const syncTokenRateMax = envInt('SSH_VAULT2_SYNC_TOKEN_RATE_MAX', 120);
const syncAccountBytesMax = envInt('SSH_VAULT2_SYNC_ACCOUNT_BYTES_MAX', 512 * 1024 * 1024);
const syncGlobalBytesMax = envInt('SSH_VAULT2_SYNC_GLOBAL_BYTES_MAX', 10 * 1024 * 1024 * 1024);
const syncBackupMaxCount = envInt('SSH_VAULT2_SYNC_BACKUP_MAX_COUNT', 20);
const syncBackupBytesMax = envInt('SSH_VAULT2_SYNC_BACKUP_BYTES_MAX', 512 * 1024 * 1024);
const minPasswordLength = envInt('SSH_VAULT2_MIN_PASSWORD_LENGTH', 12);
const genericLoginError = 'bad username or password';
const genericRegistrationError = 'registration cannot be completed';

for (const d of [downloads, syncDir, syncBackupDir, accountDir]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
function readSettings() {
  try { return fs.existsSync(settingsFile) ? JSON.parse(fs.readFileSync(settingsFile, 'utf8')) : {}; }
  catch { return {}; }
}
function saveSettings(settings) { atomicWriteJSON(settingsFile, settings); }
function currentRegistrationMode() { const m = readSettings().registrationMode; return validRegistrationModes.has(m) ? m : defaultRegistrationMode; }
function fsyncDirSync(dir) {
  try { const fd = fs.openSync(dir, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch {}
}
function atomicWriteFile(file, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, file);
  fsyncDirSync(path.dirname(file));
}
function atomicWriteJSON(file, obj, mode = 0o600) { atomicWriteFile(file, JSON.stringify(obj, null, 2), mode); }
function loadJSONFile(file, fallback = null) {
  if (!fs.existsSync(file)) return fallback;
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { const err = new Error(`json corrupt: ${path.basename(file)}`); err.cause = e; err.statusCode = 500; throw err; }
}

const cspBase = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'"
];
function cspHash(value) { return `'sha256-${crypto.createHash('sha256').update(String(value), 'utf8').digest('base64')}'`; }
function htmlCSP(body) {
  const scripts = new Set(["'self'"]); const styles = new Set(["'self'"]);
  for (const m of String(body).matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) scripts.add(cspHash(m[1]));
  for (const m of String(body).matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)) styles.add(cspHash(m[1]));
  for (const re of [/\son[a-z]+\s*=\s*"([^"]*)"/gi, /\son[a-z]+\s*=\s*'([^']*)'/gi]) for (const m of String(body).matchAll(re)) scripts.add(cspHash(m[1]));
  if (scripts.size > 1) scripts.add("'unsafe-hashes'");
  return [...cspBase, `script-src ${[...scripts].join(' ')}`, `style-src ${[...styles].join(' ')}`].join('; ');
}
const contentSecurityPolicy = [...cspBase, "script-src 'self'", "style-src 'self'"].join('; ');

function securityHeaders(csp = contentSecurityPolicy) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': csp
  };
}
const send = (res, code, body, headers = {}, csp = contentSecurityPolicy) => { res.writeHead(code, { ...securityHeaders(csp), ...headers }); res.end(body); };
const json = (res, code, obj, headers = {}) => send(res, code, JSON.stringify(obj, null, 2), { 'Content-Type': 'application/json', ...headers });
const html = (res, code, body) => send(res, code, body, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, htmlCSP(body));
const safe = s => { s = String(s || '').trim(); return /^[a-zA-Z0-9._@+ -]+$/.test(s) && s !== '.' && s !== '..' ? s : null; };
const emailRe = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const normalizeEmail = s => { const v = safe(String(s || '').trim().toLowerCase()); return v && emailRe.test(v) ? v : null; };
function normalizeAccountKey(s) { const v = safe(String(s || '').trim()); if (!v) return null; return emailRe.test(v) ? v.toLowerCase() : v; }
function normalizeUsername(s) { const v = String(s || '').trim(); if (!/^[a-zA-Z0-9._-]{3,64}$/.test(v) || emailRe.test(v)) return null; return v.toLowerCase(); }
function findAccountByUsername(username) {
  const u = normalizeUsername(username); if (!u) return null;
  if (!fs.existsSync(accountDir)) return null;
  for (const name of fs.readdirSync(accountDir).filter(n => n.endsWith('.json'))) {
    const account = name.slice(0, -5);
    const rec = loadAccount(account);
    if (normalizeUsername(rec?.username) === u) return account;
  }
  return null;
}
function resolveLoginAccount(s) {
  const raw = safe(String(s || '').trim()); if (!raw) return null;
  if (emailRe.test(raw)) return raw.toLowerCase();
  if (fs.existsSync(accountFile(raw))) return raw;
  const lower = raw.toLowerCase();
  if (lower !== raw && fs.existsSync(accountFile(lower))) return lower;
  return findAccountByUsername(raw);
}
function usernameAvailable(username, ownAccount = '') { const u = normalizeUsername(username); if (!u) return false; if (fs.existsSync(accountFile(u)) && u !== ownAccount) return false; const fileHit = fs.readdirSync(accountDir).filter(n => n.endsWith('.json')).map(n => n.slice(0, -5)).find(a => a.toLowerCase() === u && a !== ownAccount); if (fileHit) return false; const hit = findAccountByUsername(u); return !hit || hit === ownAccount; }
const adminAccounts = new Set(adminAccountsRaw.split(',').map(s => normalizeAccountKey(s)).filter(Boolean));
const shaBuf = b => crypto.createHash('sha256').update(b).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');
const scryptHash = (password, salt) => crypto.scryptSync(String(password || ''), salt, 32).toString('base64');
const b64u = s => Buffer.from(String(s), 'utf8').toString('base64url');
const unb64u = s => Buffer.from(String(s), 'base64url').toString('utf8');
const fmtTs = ms => ms ? new Date(ms).toISOString() : null;

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += base32Alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += base32Alphabet[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '')) { const idx = base32Alphabet.indexOf(ch); if (idx < 0) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function totpCode(secret, step = Math.floor(Date.now() / 30000)) {
  const key = base32Decode(secret); const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(step / 0x100000000), 0); msg.writeUInt32BE(step >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(msg).digest(); const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 127) << 24) | ((h[o + 1] & 255) << 16) | ((h[o + 2] & 255) << 8) | (h[o + 3] & 255);
  return String(bin % 1000000).padStart(6, '0');
}
function verifyTotp(secret, code) { const c = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(c)) return false; const step = Math.floor(Date.now() / 30000); for (let i = -1; i <= 1; i++) if (totpCode(secret, step + i) === c) return true; return false; }
function newTotpSecret() { return base32Encode(crypto.randomBytes(20)); }
function otpauth(account, secret) { return `otpauth://totp/ssh-vault2:${encodeURIComponent(account)}?secret=${secret}&issuer=ssh-vault2&algorithm=SHA1&digits=6&period=30`; }
function passwordOK(password) { return String(password || '').length >= minPasswordLength; }
function passwordMinError(label = 'password') { return `${label} min ${minPasswordLength} required`; }


function smtpRead(socket) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = chunk => {
      buf += chunk.toString('utf8');
      const lines = buf.split(/\r?\n/).filter(Boolean);
      if (lines.length && /^\d{3} /.test(lines[lines.length - 1])) {
        cleanup(); resolve(buf);
      }
    };
    const onErr = err => { cleanup(); reject(err); };
    const cleanup = () => { socket.off('data', onData); socket.off('error', onErr); };
    socket.on('data', onData); socket.on('error', onErr);
  });
}
async function smtpSend(socket, command, expect) {
  if (command) socket.write(command + '\r\n');
  const reply = await smtpRead(socket);
  if (expect && !String(reply).startsWith(String(expect))) throw new Error('smtp failed');
  return reply;
}
function mailDate() { return new Date().toUTCString(); }
function mailAddress(addr) { return String(addr || '').replace(/[\r\n<>]/g, '').trim(); }
function dotStuff(text) { return String(text).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..'); }
async function sendMail({ to, subject, text }) {
  to = mailAddress(to);
  const from = mailAddress(smtpFrom || 'noreply@example.invalid');
  if (!emailRe.test(to) || !from) throw new Error('bad mail address');
  if (smtpDryRun) return { ok: true, dryRun: true };
  if (!smtpSecure) throw new Error('smtp ssl required');
  const socket = tls.connect({ host: smtpHost, port: smtpPort, servername: smtpHost, rejectUnauthorized: true });
  await new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
  try {
    await smtpSend(socket, null, 220);
    await smtpSend(socket, `EHLO ${smtpHost || 'localhost'}`, 250);
    await smtpSend(socket, 'AUTH LOGIN', 334);
    await smtpSend(socket, Buffer.from(smtpUser).toString('base64'), 334);
    await smtpSend(socket, Buffer.from(smtpPass).toString('base64'), 235);
    await smtpSend(socket, `MAIL FROM:<${from}>`, 250);
    await smtpSend(socket, `RCPT TO:<${to}>`, 250);
    await smtpSend(socket, 'DATA', 354);
    const msg = [
      `From: ssh-vault2 <${from}>`,
      `To: ${to}`,
      `Date: ${mailDate()}`,
      `Subject: ${String(subject || '').replace(/[\r\n]/g, ' ')}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      dotStuff(text),
      '.'
    ].join('\r\n');
    await smtpSend(socket, msg, 250);
    await smtpSend(socket, 'QUIT', 221).catch(() => null);
    return { ok: true };
  } finally { socket.end(); }
}
async function sendPasswordResetMail(account, token) {
  if (!mailEnabled) throw new Error('smtp not configured');
  const url = `${publicUrl}/account?reset=${encodeURIComponent(token)}&email=${encodeURIComponent(account)}`;
  return sendMail({
    to: account,
    subject: 'ssh-vault2 Passwort zurücksetzen',
    text: `Hallo,\n\nfür dein ssh-vault2 Konto wurde ein Passwort-Reset angefordert.\n\nLink: ${url}\n\nDer Link ist 30 Minuten gültig. Wenn du das nicht warst, ignoriere diese Mail.\n\nssh-vault2`
  });
}
function issuePasswordReset(account, rec) {
  const token = randomToken();
  rec.passwordReset = { sha256: tokenHashFromValue(token), expiresAt: Date.now() + resetTtlMs, createdAt: Date.now() };
  rec.updatedAt = Date.now();
  saveAccount(account, rec);
  return token;
}
function consumePasswordReset(token, nextPassword) {
  if (!passwordOK(nextPassword)) throw new Error(passwordMinError('password'));
  const th = tokenHashFromValue(token);
  const now = Date.now();
  for (const name of fs.readdirSync(accountDir).filter(n => n.endsWith('.json'))) {
    const account = name.slice(0, -5);
    const rec = loadAccount(account);
    if (!rec?.passwordReset?.sha256 || rec.passwordReset.sha256 !== th) continue;
    if (Number(rec.passwordReset.expiresAt || 0) < now) { delete rec.passwordReset; saveAccount(account, rec); throw new Error('reset token expired'); }
    const salt = crypto.randomBytes(16).toString('base64');
    rec.passwordSalt = salt;
    rec.passwordHash = scryptHash(nextPassword, salt);
    delete rec.passwordReset;
    bumpSessionRevision(rec);
    replaceTokens(rec, 'Passwort-Reset Token');
    saveAccount(account, rec);
    return { ok: true, account, token: null, profile: publicAccount(account, rec), sync: syncSummary(account) };
  }
  throw new Error('reset token invalid');
}

function readOrCreateSecret(file, bytes = 32) {
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const v = crypto.randomBytes(bytes).toString('base64url');
  atomicWriteFile(file, v + '\n');
  return v;
}
const sessionSecret = readOrCreateSecret(sessionSecretFile);
function totpKey() { return crypto.createHash('sha256').update('ssh-vault2-totp\0' + sessionSecret + '\0' + String(process.env.SSH_VAULT2_TOTP_MASTER_KEY || '')).digest(); }
function encryptTotpSecret(secret) { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', totpKey(), iv); const enc = Buffer.concat([c.update(String(secret), 'utf8'), c.final()]); const tag = c.getAuthTag(); return 'v1.' + Buffer.concat([iv, tag, enc]).toString('base64url'); }
function decryptTotpSecret(value) { const raw = String(value || ''); if (!raw.startsWith('v1.')) return raw; const buf = Buffer.from(raw.slice(3), 'base64url'); if (buf.length < 29) throw new Error('bad totp secret'); const iv = buf.subarray(0, 12); const tag = buf.subarray(12, 28); const enc = buf.subarray(28); const d = crypto.createDecipheriv('aes-256-gcm', totpKey(), iv); d.setAuthTag(tag); return Buffer.concat([d.update(enc), d.final()]).toString('utf8'); }
function getTotpSecret(rec) { if (!rec) return ''; if (rec.totpSecretEnc) return decryptTotpSecret(rec.totpSecretEnc); return rec.totpSecret || ''; }
function setTotpSecret(rec, secret) { rec.totpSecretEnc = encryptTotpSecret(secret); delete rec.totpSecret; }
function hasTotp(rec) { return !!(rec?.totpSecretEnc || rec?.totpSecret); }
function migrateLegacyTotpSecret(account, rec) { if (rec?.totpSecret && !rec.totpSecretEnc) { setTotpSecret(rec, rec.totpSecret); rec.updatedAt = Date.now(); saveAccount(account, rec); return true; } return false; }
function migrateAllLegacyTotpSecrets() {
  let count = 0;
  for (const name of fs.readdirSync(accountDir).filter(n => n.endsWith('.json'))) {
    const account = name.slice(0, -5);
    const rec = loadAccount(account);
    if (migrateLegacyTotpSecret(account, rec)) count++;
  }
  if (count) console.log(`migrated ${count} legacy TOTP secret(s)`);
  return count;
}
function timingEqualStr(a, b) { const A = Buffer.from(String(a)); const B = Buffer.from(String(b)); return A.length === B.length && crypto.timingSafeEqual(A, B); }
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) { const i = part.indexOf('='); if (i >= 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1)); }
  return out;
}
function cookie(name, value, maxAge = 8 * 3600) { return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${publicIsHttps ? '; Secure' : ''}`; }
function sessionRevision(rec) { return Number(rec?.sessionRev || 0); }
function bumpSessionRevision(rec) { rec.sessionRev = sessionRevision(rec) + 1; rec.updatedAt = Date.now(); return rec.sessionRev; }
function signSession(account, exp, rev = null) {
  if (rev === null) { const rec = loadAccount(account); rev = sessionRevision(rec); }
  const payload = `user.${b64u(account)}.${exp}.${rev}`;
  const sig = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function sessionAccount(req) {
  const token = parseCookies(req).sshv_account || '';
  const parts = token.split('.');
  if ((parts.length !== 4 && parts.length !== 5) || parts[0] !== 'user') return null;
  const account = safe(unb64u(parts[1] || '')); const exp = Number(parts[2]);
  if (!account || !Number.isFinite(exp) || Date.now() > exp) return null;
  const rec = loadAccount(account); const rev = sessionRevision(rec);
  if (parts.length === 4) return rev === 0 && timingEqualStr(token, (() => { const payload = `user.${b64u(account)}.${exp}`; const sig = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url'); return `${payload}.${sig}`; })()) ? account : null;
  const tokenRev = Number(parts[3]);
  if (!Number.isFinite(tokenRev) || tokenRev !== rev) return null;
  return timingEqualStr(token, signSession(account, exp, rev)) ? account : null;
}
function setSessionCookie(account) { const exp = Date.now() + 8 * 3600 * 1000; return { token: signSession(account, exp), exp }; }

function safeRegularFile(f) {
  try { const st = fs.lstatSync(f); return st.isFile() && !st.isSymbolicLink() ? st : null; }
  catch { return null; }
}
function releaseFile(name) {
  const candidates = [path.join(root, name), path.join(downloads, name)];
  return candidates.find(f => safeRegularFile(f)) || candidates[0];
}
function downloadFile(name) {
  name = safe(name); if (!name) return null;
  const base = path.resolve(downloads);
  const f = path.resolve(downloads, name);
  if (!f.startsWith(base + path.sep)) return null;
  const st = safeRegularFile(f);
  return st ? { f, st } : null;
}
function sums() {
  const m = new Map(); const f = releaseFile('SHA256SUMS.txt'); if (!safeRegularFile(f)) return m;
  try { for (const l of fs.readFileSync(f, 'utf8').split(/\r?\n/)) { const x = l.match(/^([a-f0-9]{64})\s+(.+)$/i); if (x) m.set(path.basename(x[2].trim()), x[1].toLowerCase()); } } catch {}
  return m;
}
function cmp(a, b) { const A = a.split('.').map(Number), B = b.split('.').map(Number); for (let i = 0; i < 3; i++) { const d = (A[i] || 0) - (B[i] || 0); if (d) return d; } return 0; }
function normalizeChangelogLines(v) {
  const arr = Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/\r?\n/) : []);
  return arr.map(x => String(x || '').replace(/[\r\n]+/g, ' ').trim()).filter(Boolean).slice(0, 24);
}
function changelogMap() {
  try {
    if (!safeRegularFile(changelogFile)) return new Map();
    const raw = JSON.parse(fs.readFileSync(changelogFile, 'utf8'));
    const source = raw.versions && !Array.isArray(raw.versions) ? raw.versions : raw;
    const m = new Map();
    for (const [version, lines] of Object.entries(source || {})) {
      if (/^\d+\.\d+\.\d+$/.test(version)) m.set(version, normalizeChangelogLines(lines));
    }
    return m;
  } catch { return new Map(); }
}
function files() {
  const sm = sums(); let names = [];
  try { names = fs.readdirSync(downloads); } catch { return []; }
  return names.filter(f => !f.startsWith('.') && !f.endsWith('.sig') && f !== 'SHA256SUMS.txt' && f !== 'SHA256SUMS.txt.sig').flatMap(name => {
    try {
      const item = downloadFile(name); const sha256 = sm.get(name);
      return item && sha256 ? [{ name, url: `/downloads/${encodeURIComponent(name)}`, size: item.st.size, sha256 }] : [];
    } catch { return []; }
  });
}
function versions() {
  const changes = changelogMap();
  const g = new Map();
  for (const a of files()) { const v = a.name.match(/(\d+\.\d+\.\d+)/)?.[1]; if (v) g.set(v, [...(g.get(v) || []), a]); }
  return [...g.entries()].map(([version, assets]) => ({ version, assets, changelog: changes.get(version) || [] })).sort((a, b) => cmp(b.version, a.version));
}
function sendFile(res, f, headers = {}) {
  const st = safeRegularFile(f); if (!st) return json(res, 404, { error: 'not found' });
  const stream = fs.createReadStream(f);
  stream.on('error', err => { if (!res.headersSent) json(res, 404, { error: 'not found' }); else res.destroy(err); });
  res.writeHead(200, { ...securityHeaders(), 'Content-Length': st.size, ...headers });
  stream.pipe(res);
}
class BodyTooLargeError extends Error { constructor() { super('body too large'); this.statusCode = 413; } }
function readBody(req, limit = 20 * 1024 * 1024) { return new Promise((resolve, reject) => { let size = 0; const chunks = []; req.on('data', c => { size += c.length; if (size > limit) { reject(new BodyTooLargeError()); req.destroy(); } else chunks.push(c); }); req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', err => reject(err.message === 'body too large' ? new BodyTooLargeError() : err)); }); }
async function readJSON(req) { const b = await readBody(req, 1024 * 1024); try { return JSON.parse(b.toString('utf8') || '{}'); } catch { throw new Error('bad json'); } }
function tokenHashFromValue(t) { return t ? shaBuf(Buffer.from(String(t))) : ''; }
function tokenHash(req) { return tokenHashFromValue(String(req.headers['x-sync-token'] || '').trim()); }
function clientIP(req) { return String(req.socket?.remoteAddress || '').trim() || 'unknown'; }
const limits = new Map();
function ratePart(value) { return crypto.createHash('sha256').update(String(value || '')).digest('hex').slice(0, 32); }
function checkRateKey(k, max = 20, windowMs = 60_000) {
  const now = Date.now(); let b = limits.get(k);
  if (!b || now >= b.reset) b = { count: 0, reset: now + windowMs };
  b.count++; limits.set(k, b);
  if (limits.size > 10000) for (const [lk, lb] of limits) if (now >= lb.reset) limits.delete(lk);
  return { ok: b.count <= max, retryAfter: Math.max(1, Math.ceil((b.reset - now) / 1000)) };
}
function checkRate(req, key, max = 20, windowMs = 60_000) { return checkRateKey(`${key}:ip:${clientIP(req)}`, max, windowMs); }
function rateLimitedKey(res, key, max, windowMs) {
  const r = checkRateKey(key, max, windowMs);
  if (r.ok) return false;
  json(res, 429, { error: 'rate limit exceeded', retryAfter: r.retryAfter }, { 'Retry-After': String(r.retryAfter) });
  return true;
}
function rateLimitedValue(res, kind, value, max, windowMs = 60_000) {
  return rateLimitedKey(res, `${kind}:${ratePart(value)}`, max, windowMs);
}
function rateLimited(req, res, key, max, windowMs) {
  const r = checkRate(req, key, max, windowMs);
  if (r.ok) return false;
  json(res, 429, { error: 'rate limit exceeded', retryAfter: r.retryAfter }, { 'Retry-After': String(r.retryAfter) });
  return true;
}
function publicCorsHeaders() { return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,OPTIONS', 'Access-Control-Allow-Headers': 'content-type,x-sync-token' }; }
function expectedOrigins(req) {
  const host = String(req.headers.host || '').trim();
  let publicOrigin = '';
  let publicHost = '';
  try { const u = new URL(publicUrl); publicOrigin = u.origin; publicHost = u.host; } catch {}
  const out = new Set(publicOrigin ? [publicOrigin] : []);
  if (host && (host !== publicHost || !publicIsHttps)) out.add(`${publicIsHttps && host === publicHost ? 'https' : 'http'}://${host}`);
  return out;
}
function apiCorsHeaders(req) {
  const origin = String(req.headers.origin || '');
  if (!origin) return {};
  try { if (expectedOrigins(req).has(new URL(origin).origin)) return { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin' }; } catch {}
  return {};
}
function unsafeMethod(req) { return !['GET', 'HEAD', 'OPTIONS'].includes(String(req.method || 'GET').toUpperCase()); }
function sameOriginHeader(req, value) {
  if (!value) return true;
  try { return expectedOrigins(req).has(new URL(value).origin); } catch { return false; }
}
function requireCookieAPICSRF(req, res) {
  if (!unsafeMethod(req)) return true;
  const origin = String(req.headers.origin || '');
  const referer = String(req.headers.referer || '');
  if (origin) {
    if (!sameOriginHeader(req, origin)) { json(res, 403, { error: 'csrf origin rejected' }); return false; }
  } else if (referer) {
    if (!sameOriginHeader(req, referer)) { json(res, 403, { error: 'csrf referer rejected' }); return false; }
  } else {
    json(res, 403, { error: 'csrf origin required' }); return false;
  }
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (req.method !== 'GET' && req.method !== 'HEAD' && !ct.startsWith('application/json') && !ct.startsWith('multipart/form-data')) { json(res, 415, { error: 'content-type required' }); return false; }
  return true;
}
function dataFile(dir, name, ext = '.json') {
  name = safe(name);
  if (!name) throw new Error('bad account');
  const base = path.resolve(dir);
  const f = path.resolve(dir, name + ext);
  if (!f.startsWith(base + path.sep)) throw new Error('bad account path');
  return f;
}
function dataDir(dir, name) {
  name = safe(name);
  if (!name) throw new Error('bad account');
  const base = path.resolve(dir);
  const d = path.resolve(dir, name);
  if (!d.startsWith(base + path.sep)) throw new Error('bad account path');
  return d;
}
function deleteSyncData(account) {
  const f = syncFile(account); if (fs.existsSync(f)) fs.unlinkSync(f);
  const b = dataDir(syncBackupDir, account); if (fs.existsSync(b)) fs.rmSync(b, { recursive: true, force: true });
}
function accountFile(account) { return dataFile(accountDir, account); }
function syncFile(client) { return dataFile(syncDir, client); }
function fileSizeIfExists(file) {
  try { const st = fs.lstatSync(file); return st.isFile() ? st.size : 0; } catch { return 0; }
}
function listBackupEntries(account) {
  const dir = dataDir(syncBackupDir, account);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(n => n.endsWith('.json')).sort().map(name => {
    const file = path.join(dir, name);
    return { name, file, size: fileSizeIfExists(file) };
  }).filter(x => x.size > 0);
}
function retainedBackupEntries(entries) {
  let kept = entries.sort((a, b) => a.name.localeCompare(b.name));
  kept = kept.slice(Math.max(0, kept.length - syncBackupMaxCount));
  if (syncBackupBytesMax > 0) {
    let total = 0; const next = [];
    for (const entry of [...kept].reverse()) {
      if (total + entry.size > syncBackupBytesMax) continue;
      total += entry.size; next.push(entry);
    }
    kept = next.reverse();
  }
  return kept;
}
function pruneSyncBackups(account) {
  const dir = dataDir(syncBackupDir, account);
  if (!fs.existsSync(dir)) return;
  const keep = new Set(retainedBackupEntries(listBackupEntries(account)).map(x => x.name));
  for (const entry of listBackupEntries(account)) if (!keep.has(entry.name)) fs.rmSync(entry.file, { force: true });
  try { if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir); } catch {}
}
function projectedBackupBytes(account, oldSyncSize) {
  const entries = listBackupEntries(account);
  if (oldSyncSize > 0) entries.push({ name: '~pending-new-backup.json', file: '', size: oldSyncSize });
  return retainedBackupEntries(entries).reduce((sum, x) => sum + x.size, 0);
}
function dirBytes(dir, skipPrefix = '') {
  if (!fs.existsSync(dir)) return 0;
  const baseSkip = skipPrefix ? path.resolve(skipPrefix) : '';
  let total = 0;
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    const resolved = path.resolve(file);
    if (baseSkip && (resolved === baseSkip || resolved.startsWith(baseSkip + path.sep))) continue;
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) total += dirBytes(file, baseSkip);
    else if (st.isFile()) total += st.size;
  }
  return total;
}
function syncRecordBytes(record) { return Buffer.byteLength(JSON.stringify(record, null, 2)); }
function enforceSyncStorageQuota(account, file, record) {
  const newBytes = syncRecordBytes(record);
  const oldBytes = fileSizeIfExists(file);
  const accountProjected = newBytes + projectedBackupBytes(account, oldBytes);
  if (accountProjected > syncAccountBytesMax) {
    const err = new Error(`sync account quota exceeded (${accountProjected} > ${syncAccountBytesMax})`);
    err.statusCode = 413; throw err;
  }
  const otherBytes = dirBytes(syncDir, file) + dirBytes(syncBackupDir, dataDir(syncBackupDir, account));
  const globalProjected = otherBytes + accountProjected;
  if (globalProjected > syncGlobalBytesMax) {
    const err = new Error(`sync global storage quota exceeded (${globalProjected} > ${syncGlobalBytesMax})`);
    err.statusCode = 507; throw err;
  }
}
function writeSyncRecord(account, file, record) {
  enforceSyncStorageQuota(account, file, record);
  const backup = backupSyncFile(account, file);
  atomicWriteJSON(file, record);
  return backup;
}
function backupSyncFile(client, file) {
  if (!fs.existsSync(file)) return null;
  const dir = path.join(syncBackupDir, client);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const target = path.join(dir, `${ts}.json`);
  fs.copyFileSync(file, target);
  fs.chmodSync(target, 0o600);
  pruneSyncBackups(client);
  return target;
}
function loadAccount(account) { return loadJSONFile(accountFile(account), null); }
function saveAccount(account, rec) { atomicWriteJSON(accountFile(account), rec); }
function verifyPassword(rec, password) { return rec && rec.passwordHash === scryptHash(password, rec.passwordSalt); }
function requirePasswordStepUp(rec, body) {
  const password = String(body?.password || body?.currentPassword || '');
  if (!verifyPassword(rec, password)) { const err = new Error('password required'); err.statusCode = 403; throw err; }
}
function tokenId() { return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'); }
function normalizeTokens(rec) {
  const out = Array.isArray(rec?.tokens) ? rec.tokens.filter(t => t?.id && t?.sha256) : [];
  if (rec?.tokenSha256 && !out.some(t => t.sha256 === rec.tokenSha256)) out.unshift({ id: 'legacy', label: 'Legacy Token', sha256: rec.tokenSha256, createdAt: rec.updatedAt || rec.createdAt || Date.now(), lastUsedAt: null });
  return out;
}
function publicTokens(rec) { return normalizeTokens(rec).map(t => ({ id: t.id, label: t.label || 'Sync-Token', createdAt: t.createdAt || null, createdAtText: fmtTs(t.createdAt), lastUsedAt: t.lastUsedAt || null, lastUsedAtText: fmtTs(t.lastUsedAt) })); }
function accountStatus(rec) { return rec?.status || 'active'; }
function isAccountActive(rec) { return accountStatus(rec) === 'active'; }
function isEnvAdminAccount(account) { return adminAccounts.has(account); }
function isAdminAccount(account, rec = null) { return isEnvAdminAccount(account) || !!(rec || loadAccount(account))?.isAdmin; }
function registrationPublicConfig() { const mode = currentRegistrationMode(); return { mode, enabled: mode !== 'closed', approvalRequired: mode === 'approval' }; }
function addToken(rec, label = 'Sync-Token') {
  const token = randomToken();
  const item = { id: tokenId(), label, sha256: tokenHashFromValue(token), createdAt: Date.now(), lastUsedAt: null };
  const old = normalizeTokens(rec).filter(t => t.id !== 'legacy');
  rec.tokens = [item, ...old];
  rec.tokenSha256 = item.sha256;
  rec.updatedAt = Date.now();
  return { token, item };
}
function replaceTokens(rec, label = 'Sync-Token') {
  const token = randomToken();
  const item = { id: tokenId(), label, sha256: tokenHashFromValue(token), createdAt: Date.now(), lastUsedAt: null };
  rec.tokens = [item];
  rec.tokenSha256 = item.sha256;
  rec.updatedAt = Date.now();
  return { token, item };
}
function verifyAccountToken(rec, hash) {
  const toks = normalizeTokens(rec);
  const t = toks.find(x => x.sha256 === hash);
  if (!t) return false;
  t.lastUsedAt = Date.now();
  if (t.id === 'legacy') rec.tokenSha256 = t.sha256;
  else rec.tokens = toks.map(x => x.id === t.id ? t : x).filter(x => x.id !== 'legacy');
  rec.updatedAt = Date.now();
  return true;
}
function publicAccount(account, rec) { const tokens = publicTokens(rec); return { account, username: rec?.username || null, status: accountStatus(rec), isAdmin: isAdminAccount(account, rec), isEnvAdmin: isEnvAdminAccount(account), createdAt: rec.createdAt, updatedAt: rec.updatedAt, createdAtText: fmtTs(rec.createdAt), updatedAtText: fmtTs(rec.updatedAt), hasToken: tokens.length > 0, tokenCount: tokens.length, tokens, totpEnabled: hasTotp(rec) }; }
function syncSummary(account) {
  const f = syncFile(account); if (!fs.existsSync(f)) return { hasSync: false };
  const st = fs.statSync(f);
  try { const rec = JSON.parse(fs.readFileSync(f, 'utf8')); return { hasSync: !!rec.blob, size: st.size, updatedAt: rec.updatedAt || st.mtimeMs, updatedAtText: fmtTs(rec.updatedAt || st.mtimeMs) }; }
  catch { return { hasSync: false, size: st.size, broken: true, updatedAt: st.mtimeMs, updatedAtText: fmtTs(st.mtimeMs) }; }
}
function createOrUpdateAccount(account, password, rotateToken = true, opts = {}) {
  account = normalizeAccountKey(account);
  if (!account) throw new Error('bad account');
  if (!passwordOK(password)) throw new Error(passwordMinError('password'));
  const prev = loadAccount(account); const now = Date.now(); const salt = crypto.randomBytes(16).toString('base64');
  const rec = { ...(prev || {}), status: prev?.status || 'active', passwordSalt: salt, passwordHash: scryptHash(password, salt), createdAt: prev?.createdAt || now, updatedAt: now };
  const username = normalizeUsername(opts.username || rec.username || '');
  if (username) { if (!usernameAvailable(username, account)) throw new Error('username exists'); rec.username = username; }
  let token = null;
  if (rotateToken) { if (prev) { bumpSessionRevision(rec); token = replaceTokens(rec, 'Passwortwechsel Token').token; } else token = addToken(rec, 'Initialer Token').token; }
  else rec.tokens = normalizeTokens(rec).filter(t => t.id !== 'legacy');
  saveAccount(account, rec);
  return { ok: true, account, token, profile: publicAccount(account, rec), sync: syncSummary(account) };
}

async function handleAppAccount(req, res, u) {
  if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
  if (rateLimited(req, res, 'app-account', 10, 60_000)) return;
  const body = await readJSON(req);
  const isRegister = u.pathname === '/api/v1/accounts/register';
  const rawAccount = String(isRegister ? (body.email || body.account || '') : (body.account || body.login || body.email || body.username || '')).trim();
  if (rateLimitedValue(res, 'app-account-id', rawAccount || 'blank', authAccountRateMax)) return;
  const account = isRegister ? normalizeEmail(rawAccount) : resolveLoginAccount(rawAccount);
  const password = String(body.password || '');
  if (!account || (isRegister ? !passwordOK(password) : !password)) return json(res, 400, { error: `valid email/account and password (min ${isRegister ? minPasswordLength : 1}) required` });
  if (isRegister) {
    const mode = currentRegistrationMode(); if (mode === 'closed') return json(res, 403, { error: 'registration disabled' });
    const rawUsername = String(body.username || '').trim(); const username = normalizeUsername(rawUsername);
    if (!rawUsername) return json(res, 400, { error: 'username required' });
    if (!username) return json(res, 400, { error: 'bad username' });
    if (loadAccount(account)) return json(res, 409, { error: genericRegistrationError });
    if (!usernameAvailable(username, account)) return json(res, 409, { error: genericRegistrationError });
    const r = createOrUpdateAccount(account, password, mode !== 'approval', { username });
    if (mode === 'approval') { const rec = loadAccount(account); rec.status = 'pending'; rec.tokens = []; rec.tokenSha256 = ''; rec.updatedAt = Date.now(); saveAccount(account, rec); return json(res, 200, { ok: true, pending: true, account, profile: publicAccount(account, rec), message: 'Registrierung wartet auf Freigabe.' }); }
    return json(res, 200, { ...r, message: 'Konto erstellt. Sync-Token erzeugt.' });
  }
  const rec = account && loadAccount(account); if (!rec) return json(res, 403, { error: genericLoginError });
  if (!verifyPassword(rec, password)) return json(res, 403, { error: genericLoginError });
  if (!isAccountActive(rec)) return json(res, 403, { error: 'account unavailable' });
  const accountTotpSecret = getTotpSecret(rec);
  if (accountTotpSecret && !String(body.totp || '').trim()) return json(res, 401, { error: 'totp required', totpRequired: true });
  if (accountTotpSecret && !verifyTotp(accountTotpSecret, body.totp)) return json(res, 403, { error: 'bad totp code', totpRequired: true });
  if (accountTotpSecret) migrateLegacyTotpSecret(account, rec);
  if (u.pathname === '/api/v1/accounts/token') { const token = addToken(rec, 'App Token').token; saveAccount(account, rec); return json(res, 200, { ok: true, message: 'Sync-Token neu erstellt.', account, token, profile: publicAccount(account, rec), sync: syncSummary(account) }); }
  if (u.pathname === '/api/v1/accounts/password') { const next = String(body.newPassword || ''); if (!passwordOK(next)) return json(res, 400, { error: passwordMinError('new password') }); const r = createOrUpdateAccount(account, next, true); return json(res, 200, { ...r, message: 'Passwort geändert. Neuer Sync-Token erzeugt.' }); }
  return json(res, 404, { error: 'not found' });
}

async function handleSync(req, res, u) {
  if (rateLimited(req, res, req.method === 'GET' ? 'sync-get' : 'sync-write', req.method === 'GET' ? 240 : 60, 60_000)) return;
  const client = safe(decodeURIComponent(u.pathname.slice('/api/v1/sync/'.length))); if (!client) return json(res, 400, { error: 'bad client' });
  const th = tokenHash(req); if (!th) return json(res, 401, { error: 'missing sync token' });
  if (rateLimitedValue(res, 'sync-account-id', client, syncAccountRateMax)) return;
  if (rateLimitedValue(res, 'sync-token-hash', th, syncTokenRateMax)) return;
  const acc = loadAccount(client); const f = syncFile(client); let current = loadJSONFile(f, null);
  if (acc) { if (!isAccountActive(acc)) return json(res, 403, { error: 'sync unauthorized' }); if (!verifyAccountToken(acc, th)) return json(res, 403, { error: 'sync unauthorized' }); saveAccount(client, acc); }
  else if (!current || current?.tokenSha256 !== th) return json(res, 403, { error: 'sync unauthorized' });
  if (req.method === 'GET') { if (!current) return json(res, 403, { error: 'sync unauthorized' }); return json(res, 200, current.blob); }
  if (req.method === 'PUT' || req.method === 'POST') {
    const body = await readBody(req);
    let blob;
    try { blob = JSON.parse(body.toString('utf8')); } catch { return json(res, 400, { error: 'body must be encrypted sync json' }); }
    if (!blob?.ciphertext || !blob?.salt || !blob?.nonce) return json(res, 400, { error: 'invalid encrypted blob' });
    const oldCipherLen = current?.blob?.ciphertext ? String(current.blob.ciphertext).length : 0;
    const newCipherLen = String(blob.ciphertext).length;
    const hostCountHeader = req.headers['x-sync-host-count'];
    const vaultCountHeader = req.headers['x-sync-vault-count'];
    const hostCount = hostCountHeader === undefined ? null : Number(hostCountHeader);
    const vaultCount = vaultCountHeader === undefined ? null : Number(vaultCountHeader);
    if (current && req.headers['x-sync-allow-empty'] !== '1') {
      if (Number.isFinite(hostCount) && Number.isFinite(vaultCount) && hostCount <= 0 && vaultCount <= 0) {
        return json(res, 409, { error: 'sync overwrite rejected: empty host+vault payload; use a device with data or delete sync intentionally', hostCount, vaultCount });
      }
      if (newCipherLen < 256) {
        return json(res, 409, { error: 'sync overwrite rejected: encrypted payload too small; likely empty client state', oldCipherLen, newCipherLen });
      }
    }
    if (oldCipherLen >= 512 && newCipherLen < Math.floor(oldCipherLen * 0.5) && req.headers['x-sync-allow-shrink'] !== '1') {
      return json(res, 409, { error: 'sync overwrite rejected: new encrypted payload is much smaller than existing server payload; pull first or delete sync data intentionally', oldCipherLen, newCipherLen });
    }
    const record = { tokenSha256: acc ? undefined : (current?.tokenSha256 || th), account: client, updatedAt: Date.now(), blob };
    let backup;
    try { backup = writeSyncRecord(client, f, record); }
    catch (e) { return json(res, e.statusCode || 507, { error: String(e.message || e) }); }
    return json(res, 200, { ok: true, bytes: body.length, sha256: shaBuf(body), updatedAt: record.updatedAt, backup: !!backup });
  }
  return json(res, 405, { error: 'method not allowed' });
}

function requireUser(req, res) { const account = sessionAccount(req); if (!account) { json(res, 401, { error: 'login required' }); return null; } const rec = loadAccount(account); if (!rec) { json(res, 401, { error: 'account not found' }); return null; } if (!isAccountActive(rec)) { json(res, 403, { error: accountStatus(rec) === 'pending' ? 'account pending approval' : 'account suspended' }); return null; } return { account, rec }; }
function requireAdmin(req, res) { const ctx = requireUser(req, res); if (!ctx) return null; if (!isAdminAccount(ctx.account)) { json(res, 403, { error: 'admin required' }); return null; } return ctx; }
function accountListItem(account, rec) { return { ...publicAccount(account, rec), sync: syncSummary(account) }; }
function listAccounts() { return fs.readdirSync(accountDir).filter(n => n.endsWith('.json')).map(n => n.slice(0, -5)).filter(safe).sort().map(a => accountListItem(a, loadAccount(a))).filter(Boolean); }
function exportOwnData(account, rec) { const syncPath = syncFile(account); const backupsDir = dataDir(syncBackupDir, account); const syncRecord = loadJSONFile(syncPath, null); const backups = fs.existsSync(backupsDir) ? fs.readdirSync(backupsDir).filter(n => n.endsWith('.json')).sort().map(name => { const f = path.join(backupsDir, name); const st = fs.statSync(f); return { name, size: st.size, mtime: fmtTs(st.mtimeMs) }; }) : []; return { exportedAt: new Date().toISOString(), serverVersion, profile: publicAccount(account, rec), sync: syncRecord, backups }; }

function moveAccountEmail(oldAccount, newEmail, rec) {
  newEmail = normalizeEmail(newEmail);
  if (!newEmail) throw new Error('valid email required');
  if (oldAccount === newEmail) return { account: oldAccount, rec, changed: false };
  const oldAccountPath = accountFile(oldAccount); const newAccountPath = accountFile(newEmail);
  const oldSync = syncFile(oldAccount); const newSync = syncFile(newEmail);
  const oldBackups = dataDir(syncBackupDir, oldAccount); const newBackups = dataDir(syncBackupDir, newEmail);
  if (loadAccount(newEmail)) throw new Error('email already exists');
  if (fs.existsSync(newSync) || fs.existsSync(newBackups)) throw new Error('target email data exists');
  const syncPayload = loadJSONFile(oldSync, null);
  if (syncPayload) { syncPayload.account = newEmail; syncPayload.updatedAt = syncPayload.updatedAt || Date.now(); }
  if (isEnvAdminAccount(oldAccount)) rec.isAdmin = true;
  rec.updatedAt = Date.now();
  try {
    atomicWriteJSON(newAccountPath, rec);
    if (syncPayload) atomicWriteJSON(newSync, syncPayload);
    if (fs.existsSync(oldBackups)) fs.renameSync(oldBackups, newBackups);
    if (syncPayload) fs.unlinkSync(oldSync);
    fs.unlinkSync(oldAccountPath);
  } catch (e) {
    if (fs.existsSync(newAccountPath)) fs.rmSync(newAccountPath, { force: true });
    if (fs.existsSync(newSync)) fs.rmSync(newSync, { force: true });
    if (fs.existsSync(newBackups) && !fs.existsSync(oldBackups)) fs.renameSync(newBackups, oldBackups);
    throw e;
  }
  return { account: newEmail, rec, changed: true };
}
function extractImportBlob(account, payload) {
  if (payload?.profile?.account && payload.profile.account !== account) throw new Error('export belongs to another account');
  if (payload?.sync?.account && payload.sync.account !== account) throw new Error('sync export belongs to another account');
  const sync = payload?.sync?.blob ? payload.sync : (payload?.blob ? { blob: payload } : null);
  const blob = sync?.blob;
  if (!blob || typeof blob !== 'object') throw new Error('export contains no sync data');
  for (const k of ['ciphertext', 'salt', 'nonce']) if (!blob[k] || typeof blob[k] !== 'string') throw new Error('invalid encrypted sync blob');
  if (String(blob.ciphertext).length < 256) throw new Error('encrypted sync blob too small');
  return blob;
}
function importOwnData(account, payload) {
  const blob = extractImportBlob(account, payload);
  const f = syncFile(account); const current = loadJSONFile(f, null);
  const oldCipherLen = current?.blob?.ciphertext ? String(current.blob.ciphertext).length : 0;
  const newCipherLen = String(blob.ciphertext).length;
  if (oldCipherLen >= 512 && newCipherLen < Math.floor(oldCipherLen * 0.5) && !payload?.allowShrink) throw new Error('import rejected: encrypted payload is much smaller than existing sync data');
  const record = { account, updatedAt: Date.now(), blob };
  const backup = writeSyncRecord(account, f, record);
  return { ok: true, message: 'Sync-Daten importiert.', backup: !!backup, profile: publicAccount(account, loadAccount(account)), sync: syncSummary(account) };
}
async function handleSelfAPI(req, res, u) {
  if ((u.pathname === '/api/v1/self/login' || u.pathname === '/api/v1/self/register') && rateLimited(req, res, 'self-auth', 10, 60_000)) return;
  if ((u.pathname === '/api/v1/self/password/forgot' || u.pathname === '/api/v1/self/password/reset') && rateLimited(req, res, 'self-reset', 5, 60_000)) return;
  if ((u.pathname === '/api/v1/self/token' || u.pathname === '/api/v1/self/tokens/delete' || u.pathname === '/api/v1/self/password' || u.pathname === '/api/v1/self/email' || u.pathname === '/api/v1/self/import' || u.pathname.startsWith('/api/v1/self/totp/')) && rateLimited(req, res, 'self-sensitive', 20, 60_000)) return;
  if (u.pathname === '/api/v1/self/config' && req.method === 'GET') return json(res, 200, { ok: true, serverVersion, registration: registrationPublicConfig(), login: { emailRequiredForNewAccounts: true, usernameRequiredForNewAccounts: true, usernameLogin: true, legacyAccountsAllowed: true, passwordReset: mailEnabled } });
  if (u.pathname === '/api/v1/self/password/forgot' && req.method === 'POST') { if (!mailEnabled) return json(res, 503, { error: 'mail not configured' }); const body = await readJSON(req); const account = normalizeEmail(String(body.email || body.account || '').trim()); const rec = account && loadAccount(account); if (rec && isAccountActive(rec)) { const token = issuePasswordReset(account, rec); try { await sendPasswordResetMail(account, token); } catch (e) { console.error('password reset mail failed'); } } return json(res, 200, { ok: true, message: 'Wenn ein aktives Konto zu dieser E-Mail existiert, wurde ein Reset-Link versendet.' }); }
  if (u.pathname === '/api/v1/self/password/reset' && req.method === 'POST') { const body = await readJSON(req); try { consumePasswordReset(String(body.token || ''), String(body.newPassword || '')); return json(res, 200, { ok: true, message: 'Passwort geändert. Du kannst dich jetzt mit Benutzername oder E-Mail anmelden.' }); } catch (e) { return json(res, 400, { error: String(e.message || e) }); } }
  if (u.pathname === '/api/v1/self/register' && req.method === 'POST') { const mode = currentRegistrationMode(); if (mode === 'closed') return json(res, 403, { error: 'registration disabled' }); const body = await readJSON(req); const rawAccount = String(body.email || body.account || '').trim(); if (rateLimitedValue(res, 'self-account-id', rawAccount || 'blank', authAccountRateMax)) return; const account = normalizeEmail(rawAccount); const rawUsername = String(body.username || '').trim(); const username = normalizeUsername(rawUsername); const password = String(body.password || ''); if (!account || !passwordOK(password)) return json(res, 400, { error: `valid email and password min ${minPasswordLength} required` }); if (!rawUsername) return json(res, 400, { error: 'username required' }); if (!username) return json(res, 400, { error: 'bad username' }); if (!usernameAvailable(username, account)) return json(res, 409, { error: genericRegistrationError }); if (loadAccount(account)) return json(res, 409, { error: genericRegistrationError }); const r = createOrUpdateAccount(account, password, mode !== 'approval', { username }); if (mode === 'approval') { const rec = loadAccount(account); rec.status = 'pending'; rec.tokens = []; rec.tokenSha256 = ''; rec.updatedAt = Date.now(); saveAccount(account, rec); return json(res, 200, { ok: true, pending: true, account, profile: publicAccount(account, rec), message: 'Registrierung wartet auf Freigabe durch Admin.' }); } const sess = setSessionCookie(account); return json(res, 200, { ...r, message: 'Konto erstellt. Token wurde erzeugt.' }, { 'Set-Cookie': cookie('sshv_account', sess.token) }); }
  if (u.pathname === '/api/v1/self/login' && req.method === 'POST') { const body = await readJSON(req); const rawLogin = String(body.login || body.email || body.account || body.username || '').trim(); if (rateLimitedValue(res, 'self-account-id', rawLogin || 'blank', authAccountRateMax)) return; const account = resolveLoginAccount(rawLogin); const rec = account && loadAccount(account); if (!rec || !verifyPassword(rec, String(body.password || ''))) return json(res, 403, { error: genericLoginError }); if (!isAccountActive(rec)) return json(res, 403, { error: 'account unavailable' }); const loginTotpSecret = getTotpSecret(rec); if (loginTotpSecret && !String(body.totp || '').trim()) return json(res, 401, { error: 'totp required', totpRequired: true }); if (loginTotpSecret && !verifyTotp(loginTotpSecret, body.totp)) return json(res, 403, { error: 'bad totp code', totpRequired: true }); migrateLegacyTotpSecret(account, rec); const sess = setSessionCookie(account); return json(res, 200, { ok: true, account, profile: publicAccount(account, rec), sync: syncSummary(account), registration: registrationPublicConfig() }, { 'Set-Cookie': cookie('sshv_account', sess.token) }); }
  if (u.pathname === '/api/v1/self/logout') { if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' }); return json(res, 200, { ok: true }, { 'Set-Cookie': cookie('sshv_account', '', 0) }); }
  const ctx = requireUser(req, res); if (!ctx) return;
  if (u.pathname === '/api/v1/self/me' && req.method === 'GET') return json(res, 200, { ok: true, profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account), serverVersion, registration: registrationPublicConfig() });
  if (u.pathname === '/api/v1/self/export' && req.method === 'GET') return json(res, 200, exportOwnData(ctx.account, ctx.rec), { 'Content-Disposition': 'attachment; filename="ssh-vault2-' + ctx.account + '-export.json"' });
  if (u.pathname === '/api/v1/self/import' && req.method === 'POST') { try { const payload = JSON.parse((await readBody(req, 20 * 1024 * 1024)).toString('utf8') || '{}'); return json(res, 200, importOwnData(ctx.account, payload)); } catch (e) { return json(res, 400, { error: String(e.message || e) }); } }
  if (u.pathname === '/api/v1/self/email' && req.method === 'POST') { const body = await readJSON(req); if (!verifyPassword(ctx.rec, String(body.password || ''))) return json(res, 403, { error: 'password wrong' }); const nextEmail = normalizeEmail(String(body.email || '').trim()); if (!nextEmail) return json(res, 400, { error: 'valid email required' }); try { const moved = moveAccountEmail(ctx.account, nextEmail, ctx.rec); const sess = setSessionCookie(moved.account); return json(res, 200, { ok: true, account: moved.account, message: moved.changed ? 'E-Mail geändert.' : 'E-Mail unverändert.', profile: publicAccount(moved.account, moved.rec), sync: syncSummary(moved.account), registration: registrationPublicConfig() }, { 'Set-Cookie': cookie('sshv_account', sess.token) }); } catch (e) { return json(res, /exists/.test(String(e.message)) ? 409 : 400, { error: String(e.message || e) }); } }
  if (u.pathname === '/api/v1/self/username' && req.method === 'POST') { const body = await readJSON(req); if (!verifyPassword(ctx.rec, String(body.password || ''))) return json(res, 403, { error: 'password wrong' }); const nextUsername = normalizeUsername(String(body.username || '').trim()); if (!nextUsername) return json(res, 400, { error: 'username required' }); if (!usernameAvailable(nextUsername, ctx.account)) return json(res, 409, { error: 'username exists' }); ctx.rec.username = nextUsername; ctx.rec.updatedAt = Date.now(); saveAccount(ctx.account, ctx.rec); return json(res, 200, { ok: true, message: 'Benutzername geändert.', profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account), registration: registrationPublicConfig() }); }
  if (u.pathname === '/api/v1/self/tokens' && req.method === 'GET') return json(res, 200, { ok: true, tokens: publicTokens(ctx.rec), profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account) });
  if (u.pathname === '/api/v1/self/token' && req.method === 'POST') { const token = addToken(ctx.rec, 'Webpanel Token').token; saveAccount(ctx.account, ctx.rec); return json(res, 200, { ok: true, token, message: 'Neuer Sync-Token erzeugt.', profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account) }); }
  if (u.pathname === '/api/v1/self/tokens/delete' && req.method === 'POST') { const body = await readJSON(req); const id = String(body.id || ''); const before = normalizeTokens(ctx.rec); const next = before.filter(t => t.id !== id); if (next.length === before.length) return json(res, 404, { error: 'token not found' }); ctx.rec.tokens = next.filter(t => t.id !== 'legacy'); ctx.rec.tokenSha256 = ctx.rec.tokens[0]?.sha256 || ''; ctx.rec.updatedAt = Date.now(); saveAccount(ctx.account, ctx.rec); return json(res, 200, { ok: true, message: 'Sync-Token gelöscht.', profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account), tokens: publicTokens(ctx.rec) }); }
  if (u.pathname === '/api/v1/self/totp/setup' && req.method === 'POST') { const body = await readJSON(req); try { requirePasswordStepUp(ctx.rec, body); } catch (e) { return json(res, e.statusCode || 403, { error: String(e.message || e) }); } const secret = newTotpSecret(); return json(res, 200, { ok: true, secret, otpauth: otpauth(ctx.account, secret), message: 'TOTP Secret erzeugt. In Authenticator-App eintragen und Code bestätigen.' }); }
  if (u.pathname === '/api/v1/self/totp/enable' && req.method === 'POST') { const body = await readJSON(req); try { requirePasswordStepUp(ctx.rec, body); } catch (e) { return json(res, e.statusCode || 403, { error: String(e.message || e) }); } const secret = String(body.secret || '').replace(/\s/g, '').toUpperCase(); if (!verifyTotp(secret, body.code)) return json(res, 400, { error: 'bad totp code' }); setTotpSecret(ctx.rec, secret); ctx.rec.updatedAt = Date.now(); saveAccount(ctx.account, ctx.rec); return json(res, 200, { ok: true, message: 'TOTP aktiviert.', profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account) }); }
  if (u.pathname === '/api/v1/self/totp/disable' && req.method === 'POST') { const body = await readJSON(req); if (!verifyPassword(ctx.rec, String(body.password || ''))) return json(res, 403, { error: 'password wrong' }); const disableTotpSecret = getTotpSecret(ctx.rec); if (disableTotpSecret && !verifyTotp(disableTotpSecret, body.code)) return json(res, 403, { error: 'bad totp code' }); delete ctx.rec.totpSecret; delete ctx.rec.totpSecretEnc; ctx.rec.updatedAt = Date.now(); saveAccount(ctx.account, ctx.rec); return json(res, 200, { ok: true, message: 'TOTP deaktiviert.', profile: publicAccount(ctx.account, ctx.rec), sync: syncSummary(ctx.account) }); }
    if (u.pathname === '/api/v1/self/password' && req.method === 'POST') { const body = await readJSON(req); if (!verifyPassword(ctx.rec, String(body.currentPassword || ''))) return json(res, 403, { error: 'current password wrong' }); const next = String(body.newPassword || ''); if (!passwordOK(next)) return json(res, 400, { error: passwordMinError('new password') }); const r = createOrUpdateAccount(ctx.account, next, true); const sess = setSessionCookie(ctx.account); return json(res, 200, { ...r, message: 'Passwort geändert. Neuer Token erzeugt.' }, { 'Set-Cookie': cookie('sshv_account', sess.token) }); }
  if (u.pathname === '/api/v1/self/sync/delete' && req.method === 'POST') { deleteSyncData(ctx.account); return json(res, 200, { ok: true, message: 'Sync-Daten und Backups gelöscht.', profile: publicAccount(ctx.account, loadAccount(ctx.account)), sync: syncSummary(ctx.account) }); }
  if (u.pathname === '/api/v1/self/delete' && req.method === 'POST') { const body = await readJSON(req); if (!verifyPassword(ctx.rec, String(body.password || ''))) return json(res, 403, { error: 'password wrong' }); const af = accountFile(ctx.account); if (fs.existsSync(af)) fs.unlinkSync(af); deleteSyncData(ctx.account); return json(res, 200, { ok: true, message: 'Konto, Sync-Daten und Backups gelöscht.' }, { 'Set-Cookie': cookie('sshv_account', '', 0) }); }
  return json(res, 404, { error: 'not found' });
}

async function handleAdminAPI(req, res, u) {
  const ctx = requireAdmin(req, res); if (!ctx) return;
  if (rateLimited(req, res, 'admin', 60, 60_000)) return;
  if (u.pathname === '/api/v1/admin/users' && req.method === 'GET') return json(res, 200, { ok: true, users: listAccounts(), registration: registrationPublicConfig() });
  if (u.pathname === '/api/v1/admin/settings/registration' && req.method === 'POST') {
    const body = await readJSON(req); const mode = String(body.mode || '').trim();
    if (!validRegistrationModes.has(mode)) return json(res, 400, { error: 'bad registration mode' });
    const settings = readSettings(); settings.registrationMode = mode; settings.updatedAt = Date.now(); saveSettings(settings);
    return json(res, 200, { ok: true, message: 'Registrierung → ' + mode, registration: registrationPublicConfig(), users: listAccounts() });
  }
  if (u.pathname === '/api/v1/admin/users/status' && req.method === 'POST') {
    const body = await readJSON(req); const account = normalizeAccountKey(String(body.account || '').trim()); const status = String(body.status || '').trim();
    if (!account || !['active','pending','suspended'].includes(status)) return json(res, 400, { error: 'bad account/status' });
    const rec = loadAccount(account); if (!rec) return json(res, 404, { error: 'account not found' });
    if (account === ctx.account && status !== 'active') return json(res, 400, { error: 'self status lockout blocked' });
    if (isEnvAdminAccount(account) && status !== 'active') return json(res, 400, { error: 'env admin status lockout blocked' });
    rec.status = status; rec.updatedAt = Date.now(); saveAccount(account, rec);
    return json(res, 200, { ok: true, message: 'Nutzer ' + account + ' → ' + status, user: accountListItem(account, rec), users: listAccounts(), registration: registrationPublicConfig() });
  }
  if (u.pathname === '/api/v1/admin/users/role' && req.method === 'POST') {
    const body = await readJSON(req); const account = normalizeAccountKey(String(body.account || '').trim());
    if (typeof body.isAdmin !== 'boolean') return json(res, 400, { error: 'bad admin role value' });
    const makeAdmin = body.isAdmin;
    if (!account) return json(res, 400, { error: 'bad account' });
    if (account === ctx.account && !makeAdmin) return json(res, 400, { error: 'self admin removal blocked' });
    if (isEnvAdminAccount(account) && !makeAdmin) return json(res, 400, { error: 'env admin cannot be demoted here' });
    const rec = loadAccount(account); if (!rec) return json(res, 404, { error: 'account not found' });
    rec.isAdmin = makeAdmin; rec.updatedAt = Date.now(); saveAccount(account, rec);
    return json(res, 200, { ok: true, message: 'Nutzer ' + account + (makeAdmin ? ' ist jetzt Admin' : ' ist kein Admin mehr'), user: accountListItem(account, rec), users: listAccounts(), registration: registrationPublicConfig() });
  }
  if (u.pathname === '/api/v1/admin/users/delete' && req.method === 'POST') {
    const body = await readJSON(req); const account = normalizeAccountKey(String(body.account || '').trim());
    if (!account) return json(res, 400, { error: 'bad account' });
    if (account === ctx.account) return json(res, 400, { error: 'self delete blocked' });
    if (isEnvAdminAccount(account)) return json(res, 400, { error: 'env admin delete blocked' });
    const f = accountFile(account); if (!fs.existsSync(f)) return json(res, 404, { error: 'account not found' });
    fs.unlinkSync(f); deleteSyncData(account);
    return json(res, 200, { ok: true, message: 'Nutzer ' + account + ' gelöscht', users: listAccounts(), registration: registrationPublicConfig() });
  }
  return json(res, 404, { error: 'not found' });
}

const sharedDarkStyles = `<style>
*{box-sizing:border-box}html{scroll-behavior:smooth}html,body{min-height:100%;margin:0}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#000;color:#f5f5f7;letter-spacing:-.374px}.hidden{display:none!important}button,input{font:inherit}button{cursor:pointer}a{color:#2997ff;text-decoration:none}a:hover{text-decoration:underline}.page{min-height:100vh;background:#000}.glassNav{position:sticky;top:0;z-index:20;height:48px;display:flex;align-items:center;justify-content:space-between;padding:0 max(22px,calc((100vw - 980px)/2));background:rgba(0,0,0,.82);backdrop-filter:saturate(180%) blur(20px);border-bottom:1px solid rgba(255,255,255,.08)}.brand{display:flex;align-items:center;gap:10px;font-size:12px;color:#fff;line-height:48px}.brandDot{width:15px;height:15px;border-radius:50%;background:linear-gradient(145deg,#f5f5f7,#7d7d82);box-shadow:0 0 0 1px rgba(255,255,255,.16)}.navLinks{display:flex;align-items:center;gap:2px}.navLinks a,.navLinks button{min-height:32px;display:inline-flex;align-items:center;justify-content:center;border:0;background:transparent;color:rgba(255,255,255,.76);font-size:12px;line-height:1;padding:0 10px;border-radius:980px;text-decoration:none}.navLinks a.active,.navLinks button.active,.navLinks a:hover,.navLinks button:hover{background:rgba(255,255,255,.12);color:#fff;text-decoration:none}.navDrop{position:relative;display:inline-flex}.navDrop:after{content:"";position:absolute;left:-120px;right:-8px;top:100%;height:10px}.navMenu{position:absolute;top:calc(100% + 6px);right:0;z-index:40;min-width:150px;display:none;padding:6px;border-radius:14px;background:rgba(20,20,22,.96);border:1px solid rgba(255,255,255,.14);box-shadow:rgba(0,0,0,.36) 0 18px 42px;backdrop-filter:saturate(180%) blur(18px)}.navDrop:hover .navMenu,.navDrop:focus-within .navMenu{display:grid;gap:2px}.navMenu a{justify-content:flex-start!important;width:100%;padding:0 12px!important}.navMenu a.active{background:rgba(255,255,255,.12);color:#fff}.primary,.secondary,.ghost,.danger,.exportLink{min-height:42px;display:inline-flex;align-items:center;justify-content:center;text-align:center;vertical-align:middle;border-radius:10px;padding:0 18px;font-size:15px;line-height:1;font-weight:500;text-decoration:none;white-space:nowrap;border:1px solid transparent}.primary{background:#0071e3;color:#fff}.primary:hover{background:#147ce5;text-decoration:none}.secondary{background:#1d1d1f;color:#fff;border-color:rgba(255,255,255,.28)}.secondary:hover{text-decoration:none;background:#2a2a2d}.ghost{background:transparent;color:#2997ff;border-color:#2997ff}.ghost:hover{text-decoration:none;background:rgba(41,151,255,.10)}.danger{background:transparent;color:#ff9aa8;border-color:rgba(255,154,168,.50)}.exportLink{background:transparent;color:#2997ff;border-color:rgba(41,151,255,.55)}.pill{display:inline-flex;align-items:center;justify-content:center;min-height:30px;border-radius:980px;padding:0 12px;background:rgba(255,255,255,.08);color:#f5f5f7;font-size:12px;line-height:1}.card,.authCard{background:rgba(255,255,255,.07);border:0;border-radius:8px;padding:22px;box-shadow:rgba(0,0,0,.22) 3px 5px 30px}.muted{color:rgba(245,245,247,.68);line-height:1.48}.mini{font-size:12px;color:rgba(245,245,247,.52);line-height:1.45}.status{min-height:20px;color:rgba(245,245,247,.68);line-height:1.45}.ok{color:#7ee787}.warn{color:#ffd166}.tokenBox{display:block;white-space:pre-wrap;overflow-wrap:anywhere;background:#111113;border-radius:8px;padding:12px;color:#f5f5f7;border:1px solid rgba(255,255,255,.10)}@media(max-width:760px){.glassNav{padding:0 14px}.navLinks{gap:0;overflow:auto}.navLinks a,.navLinks button{padding:0 8px}.primary,.secondary,.ghost,.danger,.exportLink{width:100%}.card,.authCard{padding:18px}}
</style>`;

const landingPage = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ssh-vault2</title>${sharedDarkStyles}<style>
.landing{background:#000;color:#f5f5f7}.hero{min-height:calc(100vh - 48px);display:grid;place-items:center;padding:72px 22px 58px;background:radial-gradient(circle at 82% 16%,rgba(41,151,255,.22),transparent 32%),radial-gradient(circle at 18% 0%,rgba(255,255,255,.10),transparent 25%),#000}.heroInner{width:min(1120px,100%);display:grid;grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);gap:42px;align-items:center}.eyebrow{margin-bottom:22px}.hero h1{font-size:clamp(56px,8.6vw,112px);line-height:.98;letter-spacing:-.06em;margin:0;font-weight:650}.heroLead{font-size:clamp(20px,2.3vw,28px);line-height:1.2;letter-spacing:-.03em;color:rgba(245,245,247,.76);max-width:780px;margin:24px 0 0}.ctaRow{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:32px}.device{position:relative;min-height:440px;padding:20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.045));box-shadow:rgba(41,151,255,.20) 0 30px 110px,rgba(0,0,0,.60) 0 30px 90px;overflow:hidden}.device:before{content:"";position:absolute;inset:-90px -120px auto auto;width:260px;height:260px;border-radius:50%;background:rgba(41,151,255,.30);filter:blur(48px)}.terminal{position:relative;height:100%;min-height:400px;border-radius:12px;background:#050507;border:1px solid rgba(255,255,255,.12);padding:18px}.traffic{display:flex;gap:7px;margin-bottom:20px}.traffic span{width:12px;height:12px;border-radius:50%;display:block}.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}.termLine{font:14px/1.75 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9}.termLine b{color:#f5f5f7}.termLine i{color:#2997ff;font-style:normal}.termTable{margin-top:20px;border-top:1px solid rgba(255,255,255,.12)}.termRow{display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:42px;border-bottom:1px solid rgba(255,255,255,.10);font:13px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;color:rgba(245,245,247,.72)}.termRow b{font-weight:600;color:#fff}.section{padding:88px 22px;background:#000;color:#f5f5f7}.wrap{width:min(1100px,100%);margin:auto}.section h2{font-size:clamp(38px,5vw,64px);line-height:1.08;letter-spacing:-.045em;margin:0 0 16px;font-weight:650}.sectionIntro{font-size:21px;line-height:1.32;letter-spacing:-.024em;max-width:760px;margin:0;color:rgba(245,245,247,.72)}.featureStrip,.downloadList,.guide{margin-top:38px;border-top:1px solid rgba(255,255,255,.16)}.downloadChangelog{margin-top:24px;padding:18px 20px;border:1px solid rgba(41,151,255,.28);border-radius:18px;background:rgba(41,151,255,.08)}.downloadChangelog h3{margin:0 0 10px;font-size:19px}.downloadChangelog ul{margin:0;padding-left:20px;color:rgba(245,245,247,.78);line-height:1.55}.featureLine,.downloadRow,.guideStep{border-bottom:1px solid rgba(255,255,255,.12)}.featureLine{display:grid;grid-template-columns:240px 1fr;gap:34px;padding:28px 0}.featureLine h3{font-size:24px;line-height:1.14;letter-spacing:-.02em;margin:0;font-weight:600}.featureLine p{font-size:17px;line-height:1.47;margin:0;color:rgba(245,245,247,.68)}.downloadRow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:center;min-height:78px;padding:16px 0}.downloadRow b{font-size:15px;color:#f5f5f7}.downloadRow .mini{color:rgba(245,245,247,.54)}.guideNotice{margin-top:14px;padding:14px 16px;border-radius:14px;background:rgba(41,151,255,.10);border:1px solid rgba(41,151,255,.28);color:rgba(245,245,247,.82)}.guideNotice b{display:block;margin-bottom:8px;color:#f5f5f7}.guideNotice code{display:inline-block;margin-top:6px;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.16);color:#fff;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace}.guideNotice .mini{margin:8px 0 0;color:rgba(245,245,247,.54)}.guideStep{display:grid;grid-template-columns:46px minmax(0,1fr);gap:20px;padding:24px 0;scroll-margin-top:74px}.guideStep>div{min-width:0}.num{width:32px;height:32px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;background:#1d1d1f;color:#f5f5f7;border:1px solid rgba(255,255,255,.18);font-size:14px;line-height:1;font-weight:650}.guideStep h3{margin:2px 0 7px;font-size:22px;line-height:1.18;letter-spacing:-.02em}.guideStep p{margin:0;color:rgba(245,245,247,.66);font-size:16px;line-height:1.48}.guideStep ul{margin:12px 0 0;padding-left:20px;color:rgba(245,245,247,.66);font-size:15px;line-height:1.55}.guideStep li{margin:5px 0}.guideStep code{padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.14);font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff}.guideStep pre{margin:16px 0 18px;width:100%;min-width:0;max-width:100%;overflow:auto;padding:18px 20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.045));border:1px solid rgba(255,255,255,.14);box-shadow:inset 0 1px 0 rgba(255,255,255,.06);white-space:pre-wrap;box-sizing:border-box}.guideStep pre code{display:block;padding:0;border:0;background:transparent;color:#f5f5f7;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;tab-size:2;white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}.footer{padding:36px 22px;color:rgba(245,245,247,.56);font-size:12px;background:#000}.footer .wrap{display:flex;justify-content:space-between;gap:18px;border-top:1px solid rgba(255,255,255,.12);padding-top:18px}@media(max-width:860px){.hero{place-items:start;padding-top:54px}.heroInner{grid-template-columns:1fr}.device{min-height:320px}.terminal{min-height:300px}.featureLine,.downloadRow,.guideStep{grid-template-columns:1fr}.downloadRow{align-items:start}.footer .wrap{display:block}.section{padding:64px 18px}.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:auto}}@media(max-width:520px){.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:100%}}
</style></head><body><div class="page landing"><nav class="glassNav"><a class="brand" href="/"><span class="brandDot"></span><b>ssh-vault2</b></a><div class="navLinks"><a href="#download">Download</a><a href="#guide">Quickstart</a><span class="navDrop"><button type="button" aria-haspopup="true">Dokus ▾</button><span class="navMenu" role="menu"><a href="/desktop-guide" role="menuitem">Desktop-App</a><a href="/server-guide" role="menuitem">Server</a><a href="/web-guide" role="menuitem">Webseite</a></span></span><a href="/account">Konto</a></div></nav><main><section class="hero"><div class="heroInner"><div><span class="pill eyebrow">Desktop SSH & SFTP Client</span><h1>SSH. SFTP. Vault. Sync.</h1><p class="heroLead">Ein professioneller Desktop-Arbeitsplatz für Hosts, Terminal-Tabs, SFTP-Dateimanager und verschlüsselte Zugangsdaten.</p><div class="ctaRow"><a class="primary" href="#download">App herunterladen</a><a class="ghost" href="#guide">Quickstart lesen</a><a class="secondary" href="/account">Web-Konto öffnen</a></div></div><div class="device" aria-label="Produktvorschau"><div class="terminal"><div class="traffic"><span class="r"></span><span class="y"></span><span class="g"></span></div><div class="termLine"><b>ssh-vault2</b> connect production</div><div class="termLine"><i>✓</i> host key verified</div><div class="termLine"><i>✓</i> terminal tab ready</div><div class="termLine"><i>✓</i> SFTP local ↔ remote</div><div class="termLine"><i>✓</i> vault unlocked</div><div class="termTable"><div class="termRow"><b>production</b><span>ssh</span></div><div class="termRow"><b>backup-node</b><span>sftp</span></div><div class="termRow"><b>testclient</b><span>trusted</span></div><div class="termRow"><b>homelab</b><span>vault</span></div></div></div></div></div></section><section class="section"><div class="wrap"><h2>Für Menschen, die täglich auf Maschinen arbeiten.</h2><p class="sectionIntro">Die App bündelt Hostverwaltung, Terminal, SFTP und Vault in einer klaren Oberfläche für tägliche SSH-Arbeit.</p><div class="featureStrip"><div class="featureLine"><h3>SSH ohne Umwege</h3><p>Speichere Hosts mit Port, Benutzer und Authentifizierung. Öffne Verbindungen als Tabs und bestätige neue Host-Keys bewusst per Fingerprint.</p></div><div class="featureLine"><h3>SFTP integriert</h3><p>Wechsle zwischen lokalen und entfernten Dateien, lade Dateien oder ganze Ordner herunter und bleib im gleichen Arbeitsfluss.</p></div><div class="featureLine"><h3>Datensafe statt Klartext</h3><p>Passwörter und private Keys gehören in den lokalen Vault. Der Datensafe kann gesperrt werden; Sync-Daten bleiben verschlüsselt.</p></div></div></div></section><section id="download" class="section"><div class="wrap" id="downloads"><h2>Aktuelle Version</h2><p class="sectionIntro">Downloads werden geladen …</p></div></section><section id="guide" class="section"><div class="wrap"><h2>Quickstart.</h2><p class="sectionIntro">In wenigen Minuten von Download zur ersten sicheren SSH- und SFTP-Verbindung.</p><div class="guide"><div class="guideStep"><span class="num">1</span><div><h3>App herunterladen und starten</h3><p>Wähle im Downloadbereich das Paket für dein Betriebssystem. Windows nutzt den Installer, Linux das tar.gz-Archiv, macOS das ZIP mit der App.</p><div class="guideNotice"><b>Hinweis für macOS</b><span>Wenn macOS die aus dem Download stammende App blockiert, führe im Terminal im Ordner der App aus:</span><br><code>xattr -dr com.apple.quarantine ssh-vault2.app</code><p class="mini">Danach per Rechtsklick → Öffnen starten.</p></div></div></div><div class="guideStep"><span class="num">2</span><div><h3>Ersten Host anlegen</h3><p>Klicke auf <b>+ Host</b>, trage Name, Adresse, Port und Benutzer ein und wähle Passwort, SSH-Key, Agent oder einen Vault-Eintrag.</p></div></div><div class="guideStep"><span class="num">3</span><div><h3>SSH oder SFTP öffnen</h3><p>Starte eine Terminal-Verbindung mit <b>SSH verbinden</b> oder öffne den Dateimanager mit <b>SFTP öffnen</b>. Neue Host-Keys immer per Fingerprint prüfen.</p></div></div><div class="guideStep"><span class="num">4</span><div><h3>Secrets in den Datensafe legen</h3><p>Speichere Passwörter und private Keys im Vault statt im Hostprofil. Sperre den Datensafe, wenn du die App verlässt.</p></div></div><div class="guideStep"><span class="num">5</span><div><h3>Optional Sync aktivieren</h3><p>Lege im Web-Konto einen Sync-Token an und trage ihn in der App ein. Synchronisiert werden verschlüsselte Daten; Klartext-Secrets verlassen die App nicht.</p></div></div></div></div></section></main><footer class="footer"><div class="wrap"><span>ssh-vault2</span><span>Downloads, Quickstart und Konto für ssh-vault2.</span></div></footer></div><script>
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
async function loadDownloads(){const box=document.getElementById('downloads');try{const r=await fetch('/api/v1/releases');const j=await r.json();const v=j.versions&&j.versions[0];if(!v){box.innerHTML='<h2>Aktuelle Version</h2><p class="sectionIntro">Keine Downloads verfügbar.</p>';return}const changes=Array.isArray(v.changelog)?v.changelog:[];const changelog=changes.length?'<div class="downloadChangelog"><h3>Changelog</h3><ul>'+changes.map(function(x){return '<li>'+esc(x)+'</li>'}).join('')+'</ul></div>':'';box.innerHTML='<h2>Version '+esc(v.version)+'</h2><p class="sectionIntro">Wähle das Paket für dein Betriebssystem. Die App prüft signierte Checksums beim Update.</p>'+changelog+'<div class="downloadList">'+v.assets.map(function(a){return '<div class="downloadRow"><div><b>'+esc(a.name)+'</b><div class="mini">'+Math.round((a.size||0)/1024/1024*10)/10+' MB · SHA256 '+esc(a.sha256||'n/a')+'</div></div><a class="primary" href="'+esc(a.url)+'">Herunterladen</a></div>'}).join('')+'</div>'}catch(e){box.innerHTML='<h2>Aktuelle Version</h2><p class="sectionIntro">Downloads konnten nicht geladen werden.</p>'}}loadDownloads();
</script></body></html>`;

const desktopGuidePage = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ssh-vault2 Desktop-App-Anleitung</title>${sharedDarkStyles}<style>
.landing{background:#000;color:#f5f5f7}.hero{min-height:calc(100vh - 48px);display:grid;place-items:center;padding:72px 22px 58px;background:radial-gradient(circle at 82% 16%,rgba(41,151,255,.22),transparent 32%),radial-gradient(circle at 18% 0%,rgba(255,255,255,.10),transparent 25%),#000}.heroInner{width:min(1120px,100%);display:grid;grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);gap:42px;align-items:center}.eyebrow{margin-bottom:22px}.hero h1{font-size:clamp(56px,8.6vw,112px);line-height:.98;letter-spacing:-.06em;margin:0;font-weight:650}.heroLead{font-size:clamp(20px,2.3vw,28px);line-height:1.2;letter-spacing:-.03em;color:rgba(245,245,247,.76);max-width:780px;margin:24px 0 0}.ctaRow{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:32px}.device{position:relative;min-height:440px;padding:20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.045));box-shadow:rgba(41,151,255,.20) 0 30px 110px,rgba(0,0,0,.60) 0 30px 90px;overflow:hidden}.device:before{content:"";position:absolute;inset:-90px -120px auto auto;width:260px;height:260px;border-radius:50%;background:rgba(41,151,255,.30);filter:blur(48px)}.terminal{position:relative;height:100%;min-height:400px;border-radius:12px;background:#050507;border:1px solid rgba(255,255,255,.12);padding:18px}.traffic{display:flex;gap:7px;margin-bottom:20px}.traffic span{width:12px;height:12px;border-radius:50%;display:block}.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}.termLine{font:14px/1.75 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9}.termLine b{color:#f5f5f7}.termLine i{color:#2997ff;font-style:normal}.termTable{margin-top:20px;border-top:1px solid rgba(255,255,255,.12)}.termRow{display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:42px;border-bottom:1px solid rgba(255,255,255,.10);font:13px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;color:rgba(245,245,247,.72)}.termRow b{font-weight:600;color:#fff}.section{padding:88px 22px;background:#000;color:#f5f5f7}.wrap{width:min(1100px,100%);margin:auto}.section h2{font-size:clamp(38px,5vw,64px);line-height:1.08;letter-spacing:-.045em;margin:0 0 16px;font-weight:650}.sectionIntro{font-size:21px;line-height:1.32;letter-spacing:-.024em;max-width:760px;margin:0;color:rgba(245,245,247,.72)}.featureStrip,.downloadList,.guide{margin-top:38px;border-top:1px solid rgba(255,255,255,.16)}.downloadChangelog{margin-top:24px;padding:18px 20px;border:1px solid rgba(41,151,255,.28);border-radius:18px;background:rgba(41,151,255,.08)}.downloadChangelog h3{margin:0 0 10px;font-size:19px}.downloadChangelog ul{margin:0;padding-left:20px;color:rgba(245,245,247,.78);line-height:1.55}.featureLine,.downloadRow,.guideStep{border-bottom:1px solid rgba(255,255,255,.12)}.featureLine{display:grid;grid-template-columns:240px 1fr;gap:34px;padding:28px 0}.featureLine h3{font-size:24px;line-height:1.14;letter-spacing:-.02em;margin:0;font-weight:600}.featureLine p{font-size:17px;line-height:1.47;margin:0;color:rgba(245,245,247,.68)}.downloadRow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:center;min-height:78px;padding:16px 0}.downloadRow b{font-size:15px;color:#f5f5f7}.downloadRow .mini{color:rgba(245,245,247,.54)}.guideNotice{margin-top:14px;padding:14px 16px;border-radius:14px;background:rgba(41,151,255,.10);border:1px solid rgba(41,151,255,.28);color:rgba(245,245,247,.82)}.guideNotice b{display:block;margin-bottom:8px;color:#f5f5f7}.guideNotice code{display:inline-block;margin-top:6px;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.16);color:#fff;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace}.guideNotice .mini{margin:8px 0 0;color:rgba(245,245,247,.54)}.guideStep{display:grid;grid-template-columns:46px minmax(0,1fr);gap:20px;padding:24px 0;scroll-margin-top:74px}.guideStep>div{min-width:0}.num{width:32px;height:32px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;background:#1d1d1f;color:#f5f5f7;border:1px solid rgba(255,255,255,.18);font-size:14px;line-height:1;font-weight:650}.guideStep h3{margin:2px 0 7px;font-size:22px;line-height:1.18;letter-spacing:-.02em}.guideStep p{margin:0;color:rgba(245,245,247,.66);font-size:16px;line-height:1.48}.guideStep ul{margin:12px 0 0;padding-left:20px;color:rgba(245,245,247,.66);font-size:15px;line-height:1.55}.guideStep li{margin:5px 0}.guideStep code{padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.14);font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff}.guideStep pre{margin:16px 0 18px;width:100%;min-width:0;max-width:100%;overflow:auto;padding:18px 20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.045));border:1px solid rgba(255,255,255,.14);box-shadow:inset 0 1px 0 rgba(255,255,255,.06);white-space:pre-wrap;box-sizing:border-box}.guideStep pre code{display:block;padding:0;border:0;background:transparent;color:#f5f5f7;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;tab-size:2;white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}.footer{padding:36px 22px;color:rgba(245,245,247,.56);font-size:12px;background:#000}.footer .wrap{display:flex;justify-content:space-between;gap:18px;border-top:1px solid rgba(255,255,255,.12);padding-top:18px}@media(max-width:860px){.hero{place-items:start;padding-top:54px}.heroInner{grid-template-columns:1fr}.device{min-height:320px}.terminal{min-height:300px}.featureLine,.downloadRow,.guideStep{grid-template-columns:1fr}.downloadRow{align-items:start}.footer .wrap{display:block}.section{padding:64px 18px}.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:auto}}@media(max-width:520px){.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:100%}}
</style></head><body><div class="page landing"><nav class="glassNav"><a class="brand" href="/"><span class="brandDot"></span><b>ssh-vault2</b></a><div class="navLinks"><a href="/#download">Download</a><a href="/#guide">Quickstart</a><span class="navDrop"><button class="active" type="button" aria-haspopup="true">Dokus ▾</button><span class="navMenu" role="menu"><a class="active" href="/desktop-guide" role="menuitem">Desktop-App</a><a href="/server-guide" role="menuitem">Server</a><a href="/web-guide" role="menuitem">Webseite</a></span></span><a href="/account">Konto</a></div></nav><main><section id="desktop-guide" class="section"><div class="wrap"><h2>Ausführliche Desktop-App-Anleitung.</h2><p class="sectionIntro">Ausführliche Schritt-für-Schritt-Dokumentation für Einsteiger: installieren, ersten Host verbinden, SFTP nutzen, Datensafe einrichten, Sync aktivieren und typische Fehler selbst lösen.</p><div class="guide"><div class="guideStep"><span class="num">1</span><div><h3>Was diese App macht</h3><p>ssh-vault2 ist ein Desktop-Programm für tägliche SSH-Arbeit. Du speicherst Server, öffnest Terminal-Tabs, überträgst Dateien per SFTP und legst Passwörter oder private Keys verschlüsselt im lokalen Datensafe ab.</p><ul><li><b>Host:</b> ein Server oder Gerät, zu dem du dich verbinden willst.</li><li><b>SSH:</b> Terminal-Verbindung auf einen entfernten Rechner.</li><li><b>SFTP:</b> Dateiübertragung über SSH, ohne extra FTP-Server.</li><li><b>Vault/Datensafe:</b> verschlüsselte Ablage für Zugangsdaten.</li><li><b>Sync:</b> optionaler Abgleich verschlüsselter Daten über dein Web-Konto.</li></ul></div></div><div class="guideStep"><span class="num">2</span><div><h3>Welchen Download du brauchst</h3><p>Öffne die Startseite, gehe zu Download und wähle das Paket für dein Betriebssystem. Nimm immer die neueste Version, die oben angezeigt wird.</p><ul><li><b>Windows:</b> Datei mit <code>windows-amd64-installer.exe</code>.</li><li><b>Linux:</b> Datei mit <code>linux-amd64.tar.gz</code>.</li><li><b>macOS Apple Silicon:</b> Datei mit <code>darwin-arm64.zip</code>.</li><li>Wenn du unsicher bist: Windows-Nutzer nehmen den Installer, Linux-Nutzer das Archiv, Mac-Nutzer das ZIP.</li></ul></div></div><div class="guideStep"><span class="num">3</span><div><h3>Windows installieren</h3><p>Lade den Windows-Installer herunter und starte ihn mit Doppelklick. Windows kann beim ersten Start eine Sicherheitswarnung zeigen, weil die App nicht aus dem Microsoft Store kommt.</p><ul><li>Installer ausführen.</li><li>Installationsordner bestätigen.</li><li>App über Startmenü oder Desktop-Verknüpfung starten.</li><li>Wenn SmartScreen warnt: nur fortfahren, wenn Datei von dieser Seite stammt.</li><li>Nach dem Start in den Einstellungen prüfen, ob die angezeigte Version zur Downloadseite passt.</li></ul></div></div><div class="guideStep"><span class="num">4</span><div><h3>Linux installieren</h3><p>Lade das Linux-Archiv herunter, entpacke es und starte die enthaltene Binary. Du brauchst keine Systeminstallation, wenn du die App portabel nutzen willst.</p><ul><li><code>mkdir -p ~/Apps/ssh-vault2</code></li><li><code>tar -xzf ssh-vault2-*-linux-amd64.tar.gz -C ~/Apps/ssh-vault2</code></li><li><code>chmod +x ~/Apps/ssh-vault2/ssh-vault2</code></li><li><code>~/Apps/ssh-vault2/ssh-vault2</code></li><li>Optional eine Desktop-Verknüpfung anlegen, wenn dein Desktop das unterstützt.</li></ul></div></div><div class="guideStep"><span class="num">5</span><div><h3>macOS installieren</h3><p>Lade das macOS-ZIP herunter, entpacke es und verschiebe die App nach Programme. macOS kann die App beim ersten Start blockieren.</p><ul><li>ZIP entpacken.</li><li><code>ssh-vault2.app</code> nach Programme verschieben.</li><li>Wenn macOS blockiert: im Ordner der App <code>xattr -dr com.apple.quarantine ssh-vault2.app</code> ausführen.</li><li>Danach Rechtsklick auf die App und Öffnen wählen.</li><li>Hinweis: macOS-Builds können ohne Notarisierung zusätzliche Bestätigung verlangen.</li></ul></div></div><div class="guideStep"><span class="num">6</span><div><h3>Erster Start und Datensafe</h3><p>Beim ersten Start legst du deine lokale Arbeitsumgebung an. Wenn du Passwörter oder Keys speichern willst, richte sofort den Datensafe ein.</p><ul><li>Starke Datensafe-Passphrase wählen.</li><li>Passphrase nicht im gleichen Programm speichern.</li><li>Datensafe sperren, wenn du den Rechner verlässt.</li><li>Ohne entsperrten Datensafe werden gespeicherte Secrets nicht angezeigt und nicht für Verbindungen verwendet.</li></ul></div></div><div class="guideStep"><span class="num">7</span><div><h3>Ersten Host anlegen</h3><p>Klicke auf <b>+ Host</b> und trage die Verbindungsdaten ein. Für einen normalen Linux-Server brauchst du Adresse, Port, Benutzer und eine Authentifizierung.</p><ul><li><b>Name:</b> frei wählbar, z.B. <code>homeserver</code> oder <code>web01</code>.</li><li><b>Adresse:</b> IP oder DNS-Name, z.B. <code>server.example.org</code>.</li><li><b>Port:</b> meistens <code>22</code>.</li><li><b>Benutzer:</b> Linux-/SSH-Benutzer, z.B. <code>admin</code>.</li><li><b>Tags:</b> optional für Gruppen wie Produktion, Homelab oder Kunden.</li></ul></div></div><div class="guideStep"><span class="num">8</span><div><h3>Auth-Methode wählen</h3><p>Wähle die Methode, mit der dein Zielserver SSH erlaubt. Am sichersten ist meist SSH-Key oder Agent.</p><ul><li><b>Passwort:</b> einfach, aber nur nutzen, wenn der Server Passwort-Login erlaubt.</li><li><b>Key-Datei:</b> lokaler privater Schlüssel, z.B. <code>~/.ssh/id_ed25519</code>.</li><li><b>SSH-Agent:</b> nutzt bereits geladene Keys deines Betriebssystems.</li><li><b>Vault-Eintrag:</b> App holt Passwort oder Key aus dem Datensafe.</li><li>Wenn ein Key eine Passphrase hat, diese nicht mit dem Server-Passwort verwechseln.</li></ul></div></div><div class="guideStep"><span class="num">9</span><div><h3>Host-Key-Fingerprint prüfen</h3><p>Beim ersten Verbinden fragt die App nach dem Host-Key. Das schützt vor falschen oder manipulierten Servern.</p><ul><li>Fingerprint mit bekannter Quelle vergleichen, z.B. Server-Konsole, Admin-Doku oder Provider-Panel.</li><li>Nicht blind akzeptieren, wenn du den Server nicht kennst.</li><li>Wenn sich ein bekannter Host-Key später ändert, erst Ursache prüfen: Neuinstallation, DNS-Fehler oder Angriff möglich.</li><li>Nur nach Prüfung den neuen Fingerprint akzeptieren.</li></ul></div></div><div class="guideStep"><span class="num">10</span><div><h3>SSH-Terminal benutzen</h3><p>Wähle einen Host und klicke <b>SSH verbinden</b>. Jede Verbindung öffnet einen eigenen Tab. Du kannst mehrere Hosts gleichzeitig offen haben.</p><ul><li>Tab-Titel zeigt den Hostnamen.</li><li>Terminalgröße wird beim Fenster-Resize an den Server weitergegeben.</li><li>Schließe Sitzungen über das X am Tab.</li><li>Wenn Eingaben nicht erscheinen, Fokus ins Terminal setzen und Verbindung prüfen.</li><li>Bei Abbruch Meldung lesen: Auth-Fehler, Host-Key-Fehler und Netzwerkfehler sind unterschiedliche Ursachen.</li></ul></div></div><div class="guideStep"><span class="num">11</span><div><h3>SFTP-Dateimanager verwenden</h3><p>Mit <b>SFTP öffnen</b> startest du einen Dateimanager über dieselbe SSH-Verbindung. Links liegen lokale Dateien, rechts die Dateien auf dem Server.</p><ul><li>Doppelklick auf Ordner öffnet ihn.</li><li>Upload: lokale Datei oder Ordner auswählen und zum Server übertragen.</li><li>Download: Remote-Datei oder Ordner auswählen und lokal speichern.</li><li>Rechte ändern: Oktalwert wie <code>644</code> für Dateien oder <code>755</code> für Ordner nutzen.</li><li>Wenn ein Ordner leer wirkt, Benutzerrechte und Startpfad prüfen.</li></ul></div></div><div class="guideStep"><span class="num">12</span><div><h3>Vault-Einträge sauber pflegen</h3><p>Speichere Zugangsdaten im Vault, wenn du sie nicht jedes Mal eintippen willst. Der Host verweist dann auf den Vault-Eintrag.</p><ul><li>Pro Login einen eigenen Vault-Eintrag anlegen.</li><li>Einträge sinnvoll benennen, z.B. <code>web01-root-key</code>.</li><li>Alte Passwörter löschen oder ersetzen.</li><li>Private Keys nur in den Vault kopieren, wenn du den Datensafe wirklich nutzt.</li><li>Exportdateien wie Passwörter behandeln.</li></ul></div></div><div class="guideStep"><span class="num">13</span><div><h3>Sync einrichten</h3><p>Sync ist optional. Er gleicht Hosts und Vault-Daten verschlüsselt zwischen Geräten ab. Der Server sieht nur verschlüsselte Daten.</p><ul><li>Web-Konto öffnen und einloggen.</li><li>Sync-Token erzeugen und sofort kopieren.</li><li>In der App Sync-Server, Konto, Token und Sync-Passphrase eintragen.</li><li>Auf dem ersten Gerät mit vollständigen Daten einmal synchronisieren.</li><li>Auf weiteren Geräten erst Sync abrufen, bevor du neue leere Daten hochlädst.</li></ul></div></div><div class="guideStep"><span class="num">14</span><div><h3>Updates, Export und Backup</h3><p>Die App prüft neue Versionen über den Release-Feed. Vor größeren Änderungen solltest du zusätzlich exportieren.</p><ul><li>Updates nur aus der App oder von dieser Downloadseite installieren.</li><li>Bei manuellem Download SHA256SUMS vergleichen, wenn du maximale Sicherheit willst.</li><li>Vor Gerätewechsel verschlüsselten Export erstellen.</li><li>Export-Passphrase getrennt aufbewahren.</li><li>Nach Update App neu starten und Version in Einstellungen prüfen.</li></ul></div></div><div class="guideStep"><span class="num">15</span><div><h3>Fehler schnell eingrenzen</h3><p>Arbeite bei Problemen von einfach nach speziell. Die Meldung entscheidet, wo du suchst.</p><ul><li><b>Keine Verbindung:</b> Adresse, Port, VPN, Firewall und Internet prüfen.</li><li><b>Login fehlgeschlagen:</b> Benutzer, Passwort, Key-Datei und Key-Passphrase prüfen.</li><li><b>Host-Key geändert:</b> Server-Fingerprint extern prüfen, nicht blind akzeptieren.</li><li><b>SFTP kann nicht öffnen:</b> SSH-Login, Benutzerrechte und Zielpfad prüfen.</li><li><b>Sync schlägt fehl:</b> Token, Konto, Server-URL, Datensafe und Sync-Passphrase prüfen.</li></ul></div></div></div></div></section></main><footer class="footer"><div class="wrap"><span>ssh-vault2</span><span>Ausführliche Desktop-App-Anleitung für ssh-vault2.</span></div></footer></div></body></html>`;

const serverGuidePage = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ssh-vault2 Server-Anleitung</title>${sharedDarkStyles}<style>
.landing{background:#000;color:#f5f5f7}.hero{min-height:calc(100vh - 48px);display:grid;place-items:center;padding:72px 22px 58px;background:radial-gradient(circle at 82% 16%,rgba(41,151,255,.22),transparent 32%),radial-gradient(circle at 18% 0%,rgba(255,255,255,.10),transparent 25%),#000}.heroInner{width:min(1120px,100%);display:grid;grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);gap:42px;align-items:center}.eyebrow{margin-bottom:22px}.hero h1{font-size:clamp(56px,8.6vw,112px);line-height:.98;letter-spacing:-.06em;margin:0;font-weight:650}.heroLead{font-size:clamp(20px,2.3vw,28px);line-height:1.2;letter-spacing:-.03em;color:rgba(245,245,247,.76);max-width:780px;margin:24px 0 0}.ctaRow{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:32px}.device{position:relative;min-height:440px;padding:20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.045));box-shadow:rgba(41,151,255,.20) 0 30px 110px,rgba(0,0,0,.60) 0 30px 90px;overflow:hidden}.device:before{content:"";position:absolute;inset:-90px -120px auto auto;width:260px;height:260px;border-radius:50%;background:rgba(41,151,255,.30);filter:blur(48px)}.terminal{position:relative;height:100%;min-height:400px;border-radius:12px;background:#050507;border:1px solid rgba(255,255,255,.12);padding:18px}.traffic{display:flex;gap:7px;margin-bottom:20px}.traffic span{width:12px;height:12px;border-radius:50%;display:block}.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}.termLine{font:14px/1.75 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9}.termLine b{color:#f5f5f7}.termLine i{color:#2997ff;font-style:normal}.termTable{margin-top:20px;border-top:1px solid rgba(255,255,255,.12)}.termRow{display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:42px;border-bottom:1px solid rgba(255,255,255,.10);font:13px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;color:rgba(245,245,247,.72)}.termRow b{font-weight:600;color:#fff}.section{padding:88px 22px;background:#000;color:#f5f5f7}.wrap{width:min(920px,100%);margin:auto}.section h2{font-size:clamp(38px,5vw,64px);line-height:1.08;letter-spacing:-.045em;margin:0 0 16px;font-weight:650}.sectionIntro{font-size:21px;line-height:1.32;letter-spacing:-.024em;max-width:760px;margin:0;color:rgba(245,245,247,.72)}.featureStrip,.downloadList,.guide{margin-top:38px;border-top:1px solid rgba(255,255,255,.16)}.downloadChangelog{margin-top:24px;padding:18px 20px;border:1px solid rgba(41,151,255,.28);border-radius:18px;background:rgba(41,151,255,.08)}.downloadChangelog h3{margin:0 0 10px;font-size:19px}.downloadChangelog ul{margin:0;padding-left:20px;color:rgba(245,245,247,.78);line-height:1.55}.featureLine,.downloadRow,.guideStep{border-bottom:1px solid rgba(255,255,255,.12)}.featureLine{display:grid;grid-template-columns:240px 1fr;gap:34px;padding:28px 0}.featureLine h3{font-size:24px;line-height:1.14;letter-spacing:-.02em;margin:0;font-weight:600}.featureLine p{font-size:17px;line-height:1.47;margin:0;color:rgba(245,245,247,.68)}.downloadRow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:center;min-height:78px;padding:16px 0}.downloadRow b{font-size:15px;color:#f5f5f7}.downloadRow .mini{color:rgba(245,245,247,.54)}.guideNotice{margin-top:14px;padding:14px 16px;border-radius:14px;background:rgba(41,151,255,.10);border:1px solid rgba(41,151,255,.28);color:rgba(245,245,247,.82)}.guideNotice b{display:block;margin-bottom:8px;color:#f5f5f7}.guideNotice code{display:inline-block;margin-top:6px;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.16);color:#fff;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace}.guideNotice .mini{margin:8px 0 0;color:rgba(245,245,247,.54)}.guideStep{display:grid;grid-template-columns:46px minmax(0,1fr);gap:20px;padding:24px 0;scroll-margin-top:74px}.guideStep>div{min-width:0}.num{width:32px;height:32px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;background:#1d1d1f;color:#f5f5f7;border:1px solid rgba(255,255,255,.18);font-size:14px;line-height:1;font-weight:650}.guideStep h3{margin:2px 0 7px;font-size:22px;line-height:1.18;letter-spacing:-.02em}.guideStep p{margin:0;color:rgba(245,245,247,.66);font-size:16px;line-height:1.48}.guideStep ul{margin:12px 0 0;padding-left:20px;color:rgba(245,245,247,.66);font-size:15px;line-height:1.55}.guideStep li{margin:5px 0}.guideStep code{padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.14);font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff}.guideStep pre{margin:16px 0 18px;width:100%;min-width:0;max-width:100%;overflow:auto;padding:18px 20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.045));border:1px solid rgba(255,255,255,.14);box-shadow:inset 0 1px 0 rgba(255,255,255,.06);white-space:pre-wrap;box-sizing:border-box}.guideStep pre code{display:block;padding:0;border:0;background:transparent;color:#f5f5f7;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;tab-size:2;white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}.footer{padding:36px 22px;color:rgba(245,245,247,.56);font-size:12px;background:#000}.footer .wrap{display:flex;justify-content:space-between;gap:18px;border-top:1px solid rgba(255,255,255,.12);padding-top:18px}@media(max-width:860px){.hero{place-items:start;padding-top:54px}.heroInner{grid-template-columns:1fr}.device{min-height:320px}.terminal{min-height:300px}.featureLine,.downloadRow,.guideStep{grid-template-columns:1fr}.downloadRow{align-items:start}.footer .wrap{display:block}.section{padding:64px 18px}.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:auto}}@media(max-width:520px){.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:100%}}
</style></head><body><div class="page landing"><nav class="glassNav"><a class="brand" href="/"><span class="brandDot"></span><b>ssh-vault2</b></a><div class="navLinks"><a href="/#download">Download</a><a href="/#guide">Quickstart</a><span class="navDrop"><button class="active" type="button" aria-haspopup="true">Dokus ▾</button><span class="navMenu" role="menu"><a href="/desktop-guide" role="menuitem">Desktop-App</a><a class="active" href="/server-guide" role="menuitem">Server</a><a href="/web-guide" role="menuitem">Webseite</a></span></span><a href="/account">Konto</a></div></nav><main><section id="server-guide" class="section"><div class="wrap"><h2>Server-Anleitung.</h2><p class="sectionIntro">Ausführliche Installations- und Betriebsdokumentation: Voraussetzungen, Docker-Setup, Reverse-Proxy, Downloads, Konten, Sync, Backups, Updates und Fehlerdiagnose.</p><div class="guide"><div class="guideStep"><span class="num">1</span><div><h3>Was der Server macht</h3><p>Der ssh-vault2 Server ist kein SSH-Server. Er stellt die Webseite, Downloads, Konto-Verwaltung und Sync-API bereit. Die Desktop-App verbindet sich weiterhin direkt per SSH/SFTP zu deinen Zielservern.</p><ul><li><b>Webseite:</b> Download, Quickstart und Dokus.</li><li><b>Konto:</b> Registrierung, Login, Adminbereich, TOTP und Passwort-Reset.</li><li><b>Sync-API:</b> speichert verschlüsselte Sync-Blobs pro Konto.</li><li><b>Release-Feed:</b> liefert Versionen, Dateien, SHA256 und Changelog an Webseite und App.</li></ul></div></div><div class="guideStep"><span class="num">2</span><div><h3>Voraussetzungen</h3><p>Für eine eigene Installation brauchst du einen Linux-Host oder VPS. Docker ist der einfachste Weg, weil App-Code und Laufzeit zusammen ausgeliefert werden.</p><ul><li>Linux-Server mit Docker und Docker Compose.</li><li>DNS-Name, z.B. <code>ssh-vault.example.org</code>.</li><li>HTTPS-Reverse-Proxy, z.B. Caddy, Nginx Proxy Manager, Traefik oder Nginx.</li><li>Freier interner Port, Standard in dieser Doku: <code>18080</code>.</li><li>Persistenter Datenordner für Accounts, Sync-Daten, Downloads und Checksums.</li><li>Optional SMTP-Zugang, wenn Passwort-Reset per E-Mail funktionieren soll.</li></ul></div></div><div class="guideStep"><span class="num">3</span><div><h3>Projektordner vorbereiten</h3><p>Lege einen eigenen Ordner an. Dort liegen Compose-Datei, persistente Daten und Downloads. Der Ordner muss erhalten bleiben, wenn Container neu gebaut werden.</p><ul><li><code>sudo mkdir -p /opt/ssh-vault2-server/downloads</code></li><li><code>sudo mkdir -p /opt/ssh-vault2-server/data</code></li><li><code>sudo chown -R 988:988 /opt/ssh-vault2-server</code></li><li>UID/GID an deine Umgebung anpassen, wenn du einen anderen Container-User nutzt.</li><li>Ordner nicht auf tmpfs oder flüchtigem Speicher ablegen.</li></ul></div></div><div class="guideStep"><span class="num">4</span><div><h3>Auf diesem Server bauen und starten</h3><p><b>Wichtig:</b> Der Nutzer baut auf seinem eigenen Server. Compose baut aus <code>/opt/ssh-vault2-source</code>. Dort muss vorher das GitHub-Repo liegen.</p><p>Einmalig auf dem Server ausführen:</p><pre><code># Quellcode auf diesem Server holen
cd /tmp
git clone https://github.com/example-org/ssh-vault2.git ssh-vault2-source
sudo mv /tmp/ssh-vault2-source /opt/ssh-vault2-source
sudo chown -R $USER:$USER /opt/ssh-vault2-source

# Datenordner vorbereiten
sudo mkdir -p /opt/ssh-vault2-server/downloads /opt/ssh-vault2-server/data
sudo chown -R 988:988 /opt/ssh-vault2-server

# Compose-Datei aus dem Repo kopieren
sudo cp /opt/ssh-vault2-source/deployment/docker-compose.production.example.yaml /opt/ssh-vault2-server/compose.yaml
sudo nano /opt/ssh-vault2-server/compose.yaml</code></pre><p>In <code>nano</code> nur diese Werte ändern: Domain und Admin-Name.</p><pre><code>SSH_VAULT2_PUBLIC_URL: &quot;https://ssh-vault.example.org&quot;
SSH_VAULT2_ADMIN_ACCOUNTS: &quot;adminname&quot;</code></pre><p>Danach bauen und starten:</p><pre><code>sudo docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build
sudo docker ps
curl -fsS http://127.0.0.1:18080/healthz</code></pre><p>Was <code>--build</code> macht: Docker liest den Quellcode unter <code>/opt/ssh-vault2-source</code>, baut daraus das Image <code>ssh-vault2-server:1.2.26</code> und startet danach den Container.</p><p>Komplette Compose-Datei:</p><pre><code>services:
  ssh-vault2-server:
    build:
      context: /opt/ssh-vault2-source
      dockerfile: server/Dockerfile
    image: ssh-vault2-server:1.2.26
    container_name: ssh-vault2-server
    restart: unless-stopped
    user: &quot;988:988&quot;
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=64m,mode=1777
    ports:
      - &quot;127.0.0.1:18080:18080&quot;
    environment:
      HOST: &quot;0.0.0.0&quot;
      PORT: &quot;18080&quot;
      SSH_VAULT2_ROOT: &quot;/var/lib/ssh-vault2&quot;
      SSH_VAULT2_PUBLIC_URL: &quot;https://ssh-vault.example.org&quot;
      SSH_VAULT2_REGISTRATION_MODE: &quot;approval&quot;
      SSH_VAULT2_ADMIN_ACCOUNTS: &quot;adminname&quot;
    volumes:
      - /opt/ssh-vault2-server:/var/lib/ssh-vault2
    healthcheck:
      test:
        - CMD
        - node
        - -e
        - |
          fetch(&#x27;http://127.0.0.1:&#x27; + (process.env.PORT || 18080) + &#x27;/healthz&#x27;)
            .then((r) =&gt; process.exit(r.ok ? 0 : 1))
            .catch(() =&gt; process.exit(1))
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    networks:
      - ssh-vault2

networks:
  ssh-vault2:
    driver: bridge</code></pre><ul><li><b>build.context:</b> muss auf den geklonten GitHub-Code zeigen.</li><li><b>image:</b> ist der Name des lokal gebauten Images.</li><li><b>SSH_VAULT2_ROOT:</b> im Container immer <code>/var/lib/ssh-vault2</code> lassen.</li><li><b>volumes:</b> Host-Ordner <code>/opt/ssh-vault2-server</code> wird persistent gemountet.</li><li><b>ports:</b> <code>127.0.0.1</code> ist richtig, wenn Reverse-Proxy auf demselben Host läuft.</li></ul><p>Wenn dein Reverse-Proxy auf einem anderen Host läuft, ändere nur die Port-Zeile zu <code>0.0.0.0:18080:18080</code> und setze danach eine Firewall-Regel, die nur den Proxy erlaubt.</p></div></div><div class="guideStep"><span class="num">5</span><div><h3>Wichtige Umgebungsvariablen verstehen</h3><p>Die Variablen bestimmen, wie öffentlich der Server ist und wer Benutzer freigeben darf.</p><ul><li><b>build.context:</b> Pfad zum GitHub-Repo auf dem Server, Standard <code>/opt/ssh-vault2-source</code>.</li><li><b>image:</b> Name des lokal gebauten Images, z.B. <code>ssh-vault2-server:1.2.26</code>.</li><li><b>SSH_VAULT2_PUBLIC_URL:</b> öffentliche HTTPS-Adresse, wichtig für Links und sichere Cookies.</li><li><b>SSH_VAULT2_REGISTRATION_MODE:</b> <code>open</code>, <code>approval</code> oder <code>closed</code>.</li><li><b>SSH_VAULT2_ADMIN_ACCOUNTS:</b> kommagetrennte Admin-Konten oder Benutzernamen.</li><li><b>SSH_VAULT2_SMTP_HOST/USER/PASS:</b> nur nötig für Passwort-Reset-Mails.</li><li><b>SSH_VAULT2_ROOT:</b> Datenwurzel im Container, normalerweise nicht ändern.</li></ul></div></div><div class="guideStep"><span class="num">6</span><div><h3>Container starten und prüfen</h3><p>Nach dem Start muss der Healthcheck grün sein und die Startseite HTML liefern. Prüfe nicht nur, ob der Container läuft.</p><ul><li><code>docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --build</code></li><li><code>docker ps</code> zeigt den Container als running/healthy.</li><li><code>curl http://127.0.0.1:18080/healthz</code> liefert <code>{&quot;ok&quot;:true}</code>.</li><li><code>curl http://127.0.0.1:18080/api/v1/releases</code> liefert Versionen.</li><li><code>--build</code> nicht vergessen, sonst läuft eventuell altes Image weiter.</li></ul></div></div><div class="guideStep"><span class="num">7</span><div><h3>Reverse-Proxy und HTTPS</h3><p>Der Server sollte öffentlich nur per HTTPS erreichbar sein. Der Proxy leitet externen HTTPS-Traffic intern an Port 18080 weiter.</p><ul><li>DNS-A/AAAA auf deinen Server setzen.</li><li>Proxy-Host für Domain anlegen.</li><li>Ziel: <code>http://127.0.0.1:18080</code> oder Container-Netzwerkname.</li><li>Let’s Encrypt Zertifikat aktivieren.</li><li>WebSocket-Support nicht zwingend, aber unschädlich.</li><li>Nach Aktivierung <code>https://deine-domain/healthz</code> und Startseite testen.</li></ul></div></div><div class="guideStep"><span class="num">8</span><div><h3>Downloads und Release-Feed pflegen</h3><p>Die Webseite liest die verfügbaren Installationspakete aus dem Downloadordner und den Checksums. App-Updater und Webseite müssen dieselben Dateien sehen.</p><ul><li>Windows-, Linux- und macOS-Artefakte in <code>downloads/</code> ablegen.</li><li><code>SHA256SUMS.txt</code> aus den finalen Dateien erzeugen.</li><li>Wenn Signaturen genutzt werden: <code>SHA256SUMS.txt.sig</code> passend neu erstellen.</li><li><code>CHANGELOG.json</code> mit nutzerverständlichen Änderungen aktualisieren.</li><li>Danach <code>/api/v1/releases</code> und direkte Download-URLs prüfen.</li></ul></div></div><div class="guideStep"><span class="num">9</span><div><h3>Admin-Konto und Registrierung</h3><p>Nach dem ersten Start registrierst du ein Konto. Wenn dieses Konto in <code>SSH_VAULT2_ADMIN_ACCOUNTS</code> steht, sieht es den Adminbereich.</p><ul><li><code>open</code>: neue Konten werden sofort aktiv.</li><li><code>approval</code>: neue Konten warten auf Freigabe.</li><li><code>closed</code>: keine neue Registrierung, nur bestehende Nutzer.</li><li>Admins können Nutzer freigeben, sperren, löschen und Rollen setzen.</li><li>Für Admins TOTP aktivieren.</li></ul></div></div><div class="guideStep"><span class="num">10</span><div><h3>Sync-Sicherheit verstehen</h3><p>Der Server speichert nur verschlüsselte Blobs. Klartext-Hosts, Passwörter und private Keys sollen die Desktop-App nicht verlassen.</p><ul><li>Sync-Token wie Passwörter behandeln.</li><li>HTTPS ist Pflicht für echte Nutzung.</li><li>Rate-Limits aktiv lassen.</li><li>Tokens bei Verlust im Konto löschen.</li><li>Server-Backups schützen, obwohl Daten verschlüsselt sind.</li></ul></div></div><div class="guideStep"><span class="num">11</span><div><h3>Backup und Restore</h3><p>Backups müssen den gesamten Datenordner enthalten. Nur die Container-Image-Datei reicht nicht.</p><ul><li>Sichern: <code>data/accounts</code>, <code>data/sync</code>, <code>data/sync-backups</code>, <code>downloads</code>, <code>SHA256SUMS.txt</code>, Signatur und Changelog.</li><li>Vor Updates Snapshot oder Archiv erstellen.</li><li>Restore auf Testsystem prüfen.</li><li>Dateirechte nach Restore kontrollieren.</li><li>Backup verschlüsseln und getrennt vom Server lagern.</li></ul></div></div><div class="guideStep"><span class="num">12</span><div><h3>Server aktualisieren</h3><p>Bei Codeänderungen muss das Docker-Image neu gebaut werden. Ein Neustart allein kann alte UI ausliefern, wenn der Code im Image steckt.</p><ul><li>Neue Quellen holen oder Image bereitstellen.</li><li><code>docker build -t ssh-vault2-server:local -f server/Dockerfile .</code></li><li><code>docker compose -f /opt/ssh-vault2-server/compose.yaml up -d --force-recreate</code></li><li><code>/healthz</code>, <code>/api/v1/releases</code>, Startseite, Konto und Dokus prüfen.</li><li>Browser-Cache bei UI-Änderungen hart neu laden.</li></ul></div></div><div class="guideStep"><span class="num">13</span><div><h3>Monitoring und Logs</h3><p>Für Betrieb reichen oft Healthcheck, Containerstatus und HTTP-Logs. Bei Fehlern immer zuerst den konkreten Endpoint prüfen.</p><ul><li><code>docker logs ssh-vault2-server --tail 200</code></li><li><code>docker inspect ssh-vault2-server</code> für Healthstatus.</li><li>Proxy-Logs auf 502/504 prüfen.</li><li>Download-404: Dateiname, Rechte und Checksums prüfen.</li><li>Login-Probleme: Registration Mode, Accountstatus, TOTP und Rate-Limits prüfen.</li></ul></div></div><div class="guideStep"><span class="num">14</span><div><h3>Härtungs-Checkliste</h3><p>Vor öffentlicher Nutzung diese Punkte abhaken.</p><ul><li>Öffentlich nur HTTPS.</li><li>Admin-Konten mit TOTP.</li><li>Registrierung auf <code>approval</code> oder <code>closed</code>, wenn nicht offen gewünscht.</li><li>Regelmäßige verschlüsselte Backups.</li><li>SMTP-Passwörter als Secret-Datei, nicht im Git-Repo.</li><li>Downloads nur nach erfolgreichem Desktop-Smoke veröffentlichen.</li></ul></div></div></div></div></section></main><footer class="footer"><div class="wrap"><span>ssh-vault2</span><span>Server-Anleitung für ssh-vault2.</span></div></footer></div></body></html>`;

const webGuidePage = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ssh-vault2 Webseiten-Anleitung</title>${sharedDarkStyles}<style>
.landing{background:#000;color:#f5f5f7}.hero{min-height:calc(100vh - 48px);display:grid;place-items:center;padding:72px 22px 58px;background:radial-gradient(circle at 82% 16%,rgba(41,151,255,.22),transparent 32%),radial-gradient(circle at 18% 0%,rgba(255,255,255,.10),transparent 25%),#000}.heroInner{width:min(1120px,100%);display:grid;grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);gap:42px;align-items:center}.eyebrow{margin-bottom:22px}.hero h1{font-size:clamp(56px,8.6vw,112px);line-height:.98;letter-spacing:-.06em;margin:0;font-weight:650}.heroLead{font-size:clamp(20px,2.3vw,28px);line-height:1.2;letter-spacing:-.03em;color:rgba(245,245,247,.76);max-width:780px;margin:24px 0 0}.ctaRow{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:32px}.device{position:relative;min-height:440px;padding:20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,.045));box-shadow:rgba(41,151,255,.20) 0 30px 110px,rgba(0,0,0,.60) 0 30px 90px;overflow:hidden}.device:before{content:"";position:absolute;inset:-90px -120px auto auto;width:260px;height:260px;border-radius:50%;background:rgba(41,151,255,.30);filter:blur(48px)}.terminal{position:relative;height:100%;min-height:400px;border-radius:12px;background:#050507;border:1px solid rgba(255,255,255,.12);padding:18px}.traffic{display:flex;gap:7px;margin-bottom:20px}.traffic span{width:12px;height:12px;border-radius:50%;display:block}.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}.termLine{font:14px/1.75 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9}.termLine b{color:#f5f5f7}.termLine i{color:#2997ff;font-style:normal}.termTable{margin-top:20px;border-top:1px solid rgba(255,255,255,.12)}.termRow{display:flex;align-items:center;justify-content:space-between;gap:20px;min-height:42px;border-bottom:1px solid rgba(255,255,255,.10);font:13px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;color:rgba(245,245,247,.72)}.termRow b{font-weight:600;color:#fff}.section{padding:88px 22px;background:#000;color:#f5f5f7}.wrap{width:min(1100px,100%);margin:auto}.section h2{font-size:clamp(38px,5vw,64px);line-height:1.08;letter-spacing:-.045em;margin:0 0 16px;font-weight:650}.sectionIntro{font-size:21px;line-height:1.32;letter-spacing:-.024em;max-width:760px;margin:0;color:rgba(245,245,247,.72)}.featureStrip,.downloadList,.guide{margin-top:38px;border-top:1px solid rgba(255,255,255,.16)}.downloadChangelog{margin-top:24px;padding:18px 20px;border:1px solid rgba(41,151,255,.28);border-radius:18px;background:rgba(41,151,255,.08)}.downloadChangelog h3{margin:0 0 10px;font-size:19px}.downloadChangelog ul{margin:0;padding-left:20px;color:rgba(245,245,247,.78);line-height:1.55}.featureLine,.downloadRow,.guideStep{border-bottom:1px solid rgba(255,255,255,.12)}.featureLine{display:grid;grid-template-columns:240px 1fr;gap:34px;padding:28px 0}.featureLine h3{font-size:24px;line-height:1.14;letter-spacing:-.02em;margin:0;font-weight:600}.featureLine p{font-size:17px;line-height:1.47;margin:0;color:rgba(245,245,247,.68)}.downloadRow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:18px;align-items:center;min-height:78px;padding:16px 0}.downloadRow b{font-size:15px;color:#f5f5f7}.downloadRow .mini{color:rgba(245,245,247,.54)}.guideNotice{margin-top:14px;padding:14px 16px;border-radius:14px;background:rgba(41,151,255,.10);border:1px solid rgba(41,151,255,.28);color:rgba(245,245,247,.82)}.guideNotice b{display:block;margin-bottom:8px;color:#f5f5f7}.guideNotice code{display:inline-block;margin-top:6px;padding:4px 7px;border-radius:7px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.16);color:#fff;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace}.guideNotice .mini{margin:8px 0 0;color:rgba(245,245,247,.54)}.guideStep{display:grid;grid-template-columns:46px minmax(0,1fr);gap:20px;padding:24px 0;scroll-margin-top:74px}.guideStep>div{min-width:0}.num{width:32px;height:32px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;background:#1d1d1f;color:#f5f5f7;border:1px solid rgba(255,255,255,.18);font-size:14px;line-height:1;font-weight:650}.guideStep h3{margin:2px 0 7px;font-size:22px;line-height:1.18;letter-spacing:-.02em}.guideStep p{margin:0;color:rgba(245,245,247,.66);font-size:16px;line-height:1.48}.guideStep ul{margin:12px 0 0;padding-left:20px;color:rgba(245,245,247,.66);font-size:15px;line-height:1.55}.guideStep li{margin:5px 0}.guideStep code{padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.14);font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff}.guideStep pre{margin:16px 0 18px;width:100%;min-width:0;max-width:100%;overflow:auto;padding:18px 20px;border-radius:18px;background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.045));border:1px solid rgba(255,255,255,.14);box-shadow:inset 0 1px 0 rgba(255,255,255,.06);white-space:pre-wrap;box-sizing:border-box}.guideStep pre code{display:block;padding:0;border:0;background:transparent;color:#f5f5f7;font:13px/1.65 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;tab-size:2;white-space:pre-wrap;overflow-wrap:anywhere;min-width:0}.footer{padding:36px 22px;color:rgba(245,245,247,.56);font-size:12px;background:#000}.footer .wrap{display:flex;justify-content:space-between;gap:18px;border-top:1px solid rgba(255,255,255,.12);padding-top:18px}@media(max-width:860px){.hero{place-items:start;padding-top:54px}.heroInner{grid-template-columns:1fr}.device{min-height:320px}.terminal{min-height:300px}.featureLine,.downloadRow,.guideStep{grid-template-columns:1fr}.downloadRow{align-items:start}.footer .wrap{display:block}.section{padding:64px 18px}.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:auto}}@media(max-width:520px){.ctaRow .primary,.ctaRow .ghost,.ctaRow .secondary{width:100%}}
</style></head><body><div class="page landing"><nav class="glassNav"><a class="brand" href="/"><span class="brandDot"></span><b>ssh-vault2</b></a><div class="navLinks"><a href="/#download">Download</a><a href="/#guide">Quickstart</a><span class="navDrop"><button class="active" type="button" aria-haspopup="true">Dokus ▾</button><span class="navMenu" role="menu"><a href="/desktop-guide" role="menuitem">Desktop-App</a><a href="/server-guide" role="menuitem">Server</a><a class="active" href="/web-guide" role="menuitem">Webseite</a></span></span><a href="/account">Konto</a></div></nav><main><section id="web-guide" class="section"><div class="wrap"><h2>Webseiten-Anleitung.</h2><p class="sectionIntro">Ausführliche Anleitung für Nutzer und Admins: Konto anlegen, anmelden, Sync-Token erzeugen, Desktop-App verbinden, TOTP nutzen, Daten exportieren und Probleme lösen.</p><div class="guide"><div class="guideStep"><span class="num">1</span><div><h3>Was du auf der Webseite findest</h3><p>Die Webseite ist die zentrale Anlaufstelle für normale Nutzer und Admins. Du kannst die App herunterladen, die Dokus lesen, ein Konto verwalten und Sync-Tokens erzeugen.</p><ul><li><b>Download:</b> aktuelle Pakete für Windows, Linux und macOS.</li><li><b>Quickstart:</b> kurzer Einstieg für die Desktop-App.</li><li><b>Dokus:</b> ausführliche Desktop-, Server- und Webseiten-Anleitungen.</li><li><b>Konto:</b> Login, Registrierung, Tokens, TOTP, Import/Export und Adminbereich.</li></ul></div></div><div class="guideStep"><span class="num">2</span><div><h3>Konto anlegen</h3><p>Öffne Konto und wähle Registrieren. Du brauchst E-Mail, Benutzername und Passwort. Je Servereinstellung ist dein Konto sofort aktiv oder wartet auf Admin-Freigabe.</p><ul><li><b>E-Mail:</b> wird für Konto und Passwort-Reset genutzt.</li><li><b>Benutzername:</b> kann später ebenfalls zum Login genutzt werden.</li><li><b>Passwort:</b> mindestens 12 Zeichen, besser eine lange Passphrase.</li><li><b>Freigabe:</b> bei Approval-Modus kann Sync erst nach Aktivierung genutzt werden.</li></ul></div></div><div class="guideStep"><span class="num">3</span><div><h3>Anmelden</h3><p>Du kannst dich mit Benutzername oder E-Mail anmelden. Wenn TOTP aktiv ist, fragt die Seite den Code erst nach korrektem Passwort ab.</p><ul><li>Benutzername/E-Mail eintragen.</li><li>Passwort eingeben.</li><li>Bei TOTP sechsstelligen Code aus Authenticator-App eingeben.</li><li>Bei Fehlern erst Tippfehler, dann Accountstatus prüfen.</li><li>Auf fremden Geräten danach immer ausloggen.</li></ul></div></div><div class="guideStep"><span class="num">4</span><div><h3>Sync-Token erzeugen</h3><p>Ein Sync-Token verbindet Desktop-App und Konto. Der Token wird beim Erzeugen nur einmal vollständig angezeigt.</p><ul><li>Im Konto auf neuen Sync-Token klicken.</li><li>Token sofort kopieren.</li><li>Token in der Desktop-App unter Sync eintragen.</li><li>Pro Gerät möglichst eigenen Token verwenden.</li><li>Wenn ein Token verloren geht: im Konto löschen und neu erzeugen.</li></ul></div></div><div class="guideStep"><span class="num">5</span><div><h3>Desktop-App mit Web-Konto verbinden</h3><p>In der Desktop-App brauchst du Server-Adresse, Konto, Token und Sync-Passphrase. Die Sync-Passphrase verschlüsselt deine Daten zusätzlich.</p><ul><li>Server-URL exakt eintragen, z.B. <code>https://ssh-vault.example.org</code>.</li><li>Konto/E-Mail wie im Web-Konto verwenden.</li><li>Sync-Token aus dem Web-Konto einfügen.</li><li>Sync-Passphrase merken; ohne sie kann ein neues Gerät die Daten nicht entschlüsseln.</li><li>Erstes Gerät mit Daten zuerst hochladen, neue Geräte zuerst herunterladen lassen.</li></ul></div></div><div class="guideStep"><span class="num">6</span><div><h3>TOTP aktivieren</h3><p>TOTP schützt dein Web-Konto zusätzlich. Du brauchst eine Authenticator-App auf Smartphone oder Desktop.</p><ul><li>Im Konto TOTP einrichten wählen.</li><li>QR-Code scannen oder Secret manuell eintragen.</li><li>Sechsstelligen Code eingeben und aktivieren.</li><li>Authenticator-Backup oder Recovery-Strategie sichern.</li><li>Zum Deaktivieren brauchst du Passwort und aktuellen TOTP-Code.</li></ul></div></div><div class="guideStep"><span class="num">7</span><div><h3>Passwort, E-Mail und Benutzername ändern</h3><p>Im Konto kannst du deine Daten ändern. Dafür fragt die Seite das aktuelle Passwort ab, damit niemand mit offener Sitzung allein kritische Daten ändert.</p><ul><li>Neuen Benutzernamen eindeutig wählen.</li><li>Neue E-Mail muss noch frei sein.</li><li>Nach Passwortwechsel können alte Sitzungen und Tokens ungültig werden.</li><li>Änderungen danach in der Desktop-App prüfen, wenn Sync betroffen ist.</li></ul></div></div><div class="guideStep"><span class="num">8</span><div><h3>Daten exportieren und importieren</h3><p>Export ist für Backup, Migration oder Support gedacht. Behandle Exportdateien wie vertrauliche Daten.</p><ul><li>Export im Konto herunterladen.</li><li>Datei verschlüsselt und geschützt speichern.</li><li>Import nur aus eigener vertrauenswürdiger Quelle ausführen.</li><li>Vor Import klären, ob vorhandene Sync-Daten überschrieben werden dürfen.</li><li>Nach Import Sync-Status und Desktop-App prüfen.</li></ul></div></div><div class="guideStep"><span class="num">9</span><div><h3>Adminbereich verstehen</h3><p>Nur Admins sehen den Adminbereich. Dort wird geregelt, wer den Server nutzen darf.</p><ul><li><b>Freigeben:</b> pending Nutzer aktivieren.</li><li><b>Sperren:</b> Nutzer temporär blockieren, Daten bleiben erhalten.</li><li><b>Admin machen:</b> Nutzer erhält Verwaltungsrechte.</li><li><b>Löschen:</b> Konto und Sync-Daten entfernen.</li><li><b>Registrierung:</b> auf offen, Freigabe oder geschlossen setzen.</li></ul></div></div><div class="guideStep"><span class="num">10</span><div><h3>Passwort-Reset per E-Mail</h3><p>Passwort vergessen funktioniert nur, wenn der Server SMTP eingerichtet hat. Die Antwort bleibt absichtlich allgemein, damit niemand Konten erraten kann.</p><ul><li>E-Mail eintragen.</li><li>Wenn ein aktives Konto existiert, kommt ein Reset-Link.</li><li>Link zeitnah nutzen, da er abläuft.</li><li>Nach Reset in Desktop-App ggf. neuen Sync-Token eintragen.</li><li>Wenn keine Mail kommt: Spamordner und Admin/Server-SMTP prüfen.</li></ul></div></div><div class="guideStep"><span class="num">11</span><div><h3>Sicherheit für normale Nutzer</h3><p>Sync-Tokens und Exporte sind sensibel. Teile sie nicht in Chats, Tickets oder Screenshots.</p><ul><li>Nur HTTPS-Adresse verwenden.</li><li>Passwortmanager nutzen.</li><li>TOTP aktivieren.</li><li>Tokens pro Gerät getrennt halten.</li><li>Bei Geräteverlust Token löschen und Passwort ändern.</li></ul></div></div><div class="guideStep"><span class="num">12</span><div><h3>Typische Probleme lösen</h3><p>Viele Webprobleme sind Loginstatus, Freigabe, Token oder Cache.</p><ul><li><b>Registrierung fehlt:</b> Server steht auf <code>closed</code>.</li><li><b>Konto wartet:</b> Admin muss freigeben.</li><li><b>Login falsch:</b> Benutzername/E-Mail, Passwort, TOTP und Status prüfen.</li><li><b>Sync geht nicht:</b> Token neu erzeugen und App-Einstellungen prüfen.</li><li><b>Downloads fehlen:</b> Seite neu laden; Admin prüft Release-Feed und Downloadordner.</li></ul></div></div></div></div></section></main><footer class="footer"><div class="wrap"><span>ssh-vault2</span><span>Webseiten-Anleitung für ssh-vault2.</span></div></footer></div></body></html>`;

const accountPage = `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ssh-vault2 Konto</title>${sharedDarkStyles}<style>
.authHero{min-height:calc(100vh - 52px);display:grid;grid-template-columns:minmax(0,1fr) 430px;gap:36px;align-items:center;width:min(1120px,100%);margin:auto;padding:56px 22px}.heroCopy h1{font-size:clamp(42px,6vw,76px);line-height:1.02;letter-spacing:-1.8px;margin:0 0 18px;font-weight:700}.heroCopy p{font-size:21px;line-height:1.32;color:rgba(245,245,247,.70);max-width:650px;margin:0}.heroPills{display:flex;gap:10px;flex-wrap:wrap;margin-top:28px}.modeGrid{display:grid;grid-template-columns:1fr 1fr;gap:8px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.08);border-radius:999px;padding:5px;margin:20px 0}.modeGrid button{border:0;border-radius:999px;padding:12px;color:rgba(245,245,247,.66);background:transparent}.modeGrid button.active{background:#f5f5f7;color:#1d1d1f;box-shadow:rgba(0,0,0,.24) 0 8px 24px}label{display:block;font-weight:650;font-size:13px;margin:14px 0 7px;color:#f5f5f7}input{width:100%;height:48px;border:0;border-radius:14px;background:rgba(255,255,255,.08);color:#fff;padding:0 14px;outline:1px solid rgba(255,255,255,.12)}input::placeholder{color:rgba(245,245,247,.36)}input:focus{outline:2px solid #2997ff;background:rgba(255,255,255,.12)}#submitBtn{width:100%;margin-top:18px}#resetBox .primary,#changePasswordBtn,#changeEmailBtn,#changeUsernameBtn,#importBtn,#totpSetup .primary,#totpDisable .ghost{width:100%;margin-top:18px}.authCard #authMsg{margin:12px 0 2px}.authLinks{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;margin-top:4px}.authCard .linkBtn{align-self:flex-start}.linkBtn{border:0;background:transparent;color:#2997ff;padding:8px 0}.authLinks .linkBtn{padding:8px 0}.totpBox{padding:12px;border-radius:18px;background:rgba(41,151,255,.10);border:1px solid rgba(41,151,255,.20);margin-top:12px}.qrBox{display:inline-block;background:#fff;border-radius:10px;padding:10px;margin:8px 0 12px}.qrBox svg{display:block;width:180px;height:180px}.securityGrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-top:18px}.accountSecurity .securityGrid{grid-template-columns:1fr}.securityGroup{min-width:0}.securityGroup h3{margin:0 0 6px;font-size:19px}.filePicker{min-height:58px;border:1px dashed rgba(255,255,255,.22);border-radius:14px;background:rgba(255,255,255,.055);display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;padding:12px;text-align:center}.filePicker input{position:absolute;inline-size:1px;block-size:1px;opacity:0;pointer-events:none}.filePickerLabel{min-height:38px;display:inline-flex;align-items:center;justify-content:center;border-radius:10px;padding:0 16px;background:#1d1d1f;color:#fff;border:1px solid rgba(255,255,255,.28);cursor:pointer}.fileName{color:rgba(245,245,247,.64);font-size:13px}.dash{width:min(1440px,100%);margin:0 auto;padding:34px 22px}.dashHead{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;margin-bottom:22px}.dashHead h1{font-size:44px;letter-spacing:-1px;line-height:1.08;margin:0}.dashGrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:start}.cardStack{display:flex;flex-direction:column;gap:16px;min-width:0;align-self:start}.tokenListScroll{max-height:270px;overflow:auto;padding:0 4px 8px 0;scrollbar-gutter:stable;scrollbar-color:#3a3a3c #050506;scrollbar-width:thin}.tokenListScroll::-webkit-scrollbar{width:10px}.tokenListScroll::-webkit-scrollbar-track{background:#050506;border-radius:999px}.tokenListScroll::-webkit-scrollbar-thumb{background:#3a3a3c;border-radius:999px;border:2px solid #050506}.tokenListScroll::-webkit-scrollbar-thumb:hover{background:#5a5a5f}.span2{grid-column:1/-1}.tokenRow,.userRow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:12px 0;border-top:1px solid rgba(255,255,255,.10)}.tokenMeta{font-size:12px;color:rgba(245,245,247,.54);line-height:1.45}.actions{display:flex;gap:8px;flex-wrap:wrap}.actions button,.actions a{width:auto}.exportLink{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;background:#0071e3;color:#fff;text-decoration:none;min-height:42px;padding:0 16px;font-weight:650}.userStatus{display:inline-flex;border-radius:999px;padding:4px 9px;background:rgba(255,255,255,.10);font-size:12px}.userStatus.active{background:rgba(46,160,67,.18);color:#7ee787}.userStatus.pending{background:rgba(255,209,102,.16);color:#ffd166}.userStatus.suspended{background:rgba(255,69,92,.14);color:#ffb7c2}.footerNote{font-size:12px;color:rgba(245,245,247,.44);margin-top:20px}@media(max-width:1060px){.securityGrid{grid-template-columns:1fr}}@media(max-width:860px){.authHero{grid-template-columns:1fr;padding-top:34px}.dashGrid{grid-template-columns:1fr}.dashHead{align-items:stretch;flex-direction:column}.heroCopy h1{font-size:42px}.tokenRow,.userRow{grid-template-columns:1fr}}
</style></head><body><div class="page"><nav class="glassNav"><a class="brand" href="/"><span class="brandDot"></span><b>ssh-vault2 Sync</b></a><div class="navLinks"><a href="/">Landing</a><button id="navAccount" class="active" onclick="showPanel('account')">Konto</button><button id="navAdmin" class="adminOnly" onclick="showPanel('admin')">Admin</button><button id="navLogout" class="hidden" onclick="logout()">Logout</button></div></nav>
<div id="auth" class="authHero"><section class="heroCopy"><span class="pill">Dark Sync Portal</span><h1>Deine Hosts.<br>Synchronisiert.<br>Verschlüsselt.</h1><p>Sichere deine SSH-Profile, Vaults und Verbindungen verschlüsselt über alle Geräte hinweg.</p><div class="heroPills"><span class="pill">Ende-zu-Ende verschlüsselt</span><span class="pill">Geräteübergreifender Sync</span><span class="pill" id="regPill">Konto bereit</span></div></section><section class="authCard"><h2 id="authTitle">Einloggen</h2><p class="authLead" id="authLead">Willkommen zurück. TOTP fragen wir erst ab, wenn dein Konto es wirklich aktiviert hat.</p><div class="modeGrid"><button id="loginTab" class="active" onclick="setMode('login')">Login</button><button id="registerTab" onclick="setMode('register')">Registrieren</button></div><div id="credentialFields"><label id="accountLabel">Benutzername oder E-Mail</label><input id="account" name="username" autocomplete="username" placeholder="Benutzername oder E-Mail"><div id="registerUsernameBox" class="hidden"><label>Benutzername</label><input id="username" name="username" autocomplete="username" placeholder="z.B. alex"></div><label>Passwort</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="mindestens 12 Zeichen"></div><div id="totpLoginBox" class="totpBox hidden"><label for="totpChallenge">TOTP Code</label><div id="totpLoginMount"></div><p class="mini">TOTP ist für dieses Konto aktiv. Bitte Code eingeben.</p><button class="linkBtn" onclick="setMode('login')">Zurück zu Benutzername & Passwort</button></div><button id="submitBtn" class="primary" onclick="submitAuth()">Einloggen</button><p id="authMsg" class="status warn"></p><div class="authLinks"><button id="modeSwitch" class="linkBtn" onclick="toggleMode()">Noch kein Konto? Registrieren</button><button id="forgotBtn" class="linkBtn" onclick="forgotPassword()">Passwort vergessen?</button></div><div id="resetBox" class="totpBox hidden"><h3>Passwort zurücksetzen</h3><p class="mini">Öffne den Link aus der E-Mail oder füge den Reset-Token ein.</p><label>Reset-Token</label><input id="resetToken" autocomplete="off" spellcheck="false" data-bwignore="true" data-lpignore="true" data-1p-ignore><label>Neues Passwort</label><input id="resetPassword" type="password" autocomplete="new-password" placeholder="mindestens 12 Zeichen"><button class="primary" onclick="resetPassword()">Neues Passwort speichern</button><p id="resetMsg" class="status"></p></div></section></div>
<main id="app" class="dash hidden"><header class="dashHead"><div><h1>Mein Konto</h1><p id="hello" class="muted"></p></div><div class="actions"><a class="exportLink" href="/api/v1/self/export" target="_blank">Eigene Daten exportieren</a><button class="ghost" onclick="document.getElementById('importFile').click()">Daten importieren</button><button class="ghost" onclick="loadMe()">Aktualisieren</button></div></header><section id="accountPanel" class="dashGrid"><section class="cardStack"><section class="card"><h2>Status</h2><p id="accountStatus" class="muted"></p><p id="syncStatus" class="muted"></p><p id="registrationStatus" class="muted"></p></section><section class="card"><h2>TOTP</h2><p id="totpStatus" class="muted"></p><button id="setupTotpBtn" class="secondary" onclick="setupTotp()">TOTP einrichten</button><div id="totpSetup" class="hidden"><p class="mini">Secret in Authenticator-App eintragen:</p><code class="tokenBox" id="totpSecret"></code><div id="totpQr" class="qrBox" aria-label="TOTP QR Code"></div><p class="mini" id="otpauth"></p><label>Bestätigungscode</label><input id="totpEnableCode" inputmode="numeric" maxlength="6" autocomplete="off" data-bwignore="true" data-lpignore="true" data-1p-ignore><button class="primary" onclick="enableTotp()">TOTP aktivieren</button></div><div id="totpDisable"><label>Passwort</label><input id="totpDisablePassword" type="password"><label>TOTP Code</label><input id="totpDisableCode" inputmode="numeric" maxlength="6" autocomplete="off" data-bwignore="true" data-lpignore="true" data-1p-ignore><button class="ghost" onclick="disableTotp()">TOTP deaktivieren</button></div><p id="totpMsg" class="status"></p></section><section class="card accountSecurity"><h2>E-Mail & Passwort</h2><p class="muted">Einmal aktuelles Passwort eingeben, dann E-Mail oder Passwort ändern.</p><label>Aktuelles Passwort</label><input id="accountPassword" type="password" name="current-password" autocomplete="current-password"><div class="securityGrid"><div class="securityGroup"><h3>Benutzername ändern</h3><p class="muted">Dein Benutzername bleibt unabhängig von der E-Mail und kann ebenfalls zum Login genutzt werden.</p><label>Benutzername</label><input id="usernameNew" autocomplete="username"><button id="changeUsernameBtn" class="secondary" onclick="changeUsername()">Benutzername ändern</button><p id="usernameMsg" class="status"></p></div><div class="securityGroup"><h3>E-Mail ändern</h3><p class="muted">E-Mail-Adressen dürfen nur einmal vorkommen. Danach meldest du dich mit neuer E-Mail oder Benutzername an.</p><label>Neue E-Mail</label><input id="emailNew" type="email" autocomplete="email"><button id="changeEmailBtn" class="secondary" onclick="changeEmail()">E-Mail ändern</button><p id="emailMsg" class="status"></p></div><div class="securityGroup"><h3>Passwort ändern</h3><p class="muted">Ändert nur dein Webkonto-Passwort. Sync-Tokens bleiben separat verwaltbar.</p><label>Neues Passwort</label><input id="newPassword" type="password" autocomplete="new-password"><button id="changePasswordBtn" class="secondary" onclick="changePassword()">Passwort ändern</button><p id="passMsg" class="status"></p></div></div></section></section><section class="cardStack"><section class="card"><h2>Sync-Token</h2><p class="muted">Neue Tokens werden einmalig angezeigt. Aktive Tokens kannst du löschen.</p><button class="primary" onclick="rotateToken()">Neuen Sync-Token erzeugen</button><p id="tokenMsg" class="status"></p><div id="tokenList"></div></section><section class="card"><h2>Daten importieren</h2><p class="muted">Importiert die verschlüsselten Sync-Daten aus einem Web-Konto-Export in dieses Konto. Vorhandene Sync-Daten werden vorher gesichert.</p><div class="filePicker"><label class="filePickerLabel" for="importFile">Datei auswählen</label><span id="importFileName" class="fileName">Keine Datei ausgewählt</span><input id="importFile" type="file" accept="application/json,.json" onchange="updateImportFileName()"></div><button id="importBtn" class="secondary" onclick="importData()">Export-Datei importieren</button><p id="importMsg" class="status"></p></section><section class="card"><h2>Gefahrenzone</h2><div class="actions"><button class="danger" onclick="deleteSync()">Sync-Daten löschen</button><button class="danger" onclick="deleteAccount()">Konto löschen</button></div><p id="dangerMsg" class="status"></p></section></section></section><section id="adminPanel" class="dashGrid hidden"><section class="card span2"><h2>Admin Panel</h2><p class="muted">Benutzer anzeigen, freigeben, sperren, Admin-Rechte vergeben oder Registrierung steuern.</p><h3>Registrierung</h3><p id="adminRegistrationStatus" class="muted"></p><div class="actions"><button class="ghost" data-reg="open">Erlauben</button><button class="ghost" data-reg="approval">Mit Freigabe</button><button class="danger" data-reg="closed">Verbieten</button></div><h3>Benutzer</h3><div id="adminUsers"></div><p id="adminMsg" class="status"></p></section></section><p class="footerNote">Server speichert Passworthashes, Tokenhashes und verschlüsselte Sync-Daten. Klartext-Hosts bleiben clientseitig.</p></main></div>
<script src="/assets/qrcode.js?v=1.0.36"></script><script>
const $=id=>document.getElementById(id);let mode='login',profile=null,pendingTotpSecret='',serverConfig={registration:{mode:'open',enabled:true,approvalRequired:false}};function humanSize(n){n=Number(n||0);const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?Math.round(n*10)/10:n)+' '+u[i]}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function api(path,opts={}){const r=await fetch(path,{headers:{'Content-Type':'application/json'},...opts});const j=await r.json().catch(()=>({error:'bad json'}));if(!r.ok){const e=new Error(j.error||r.statusText);e.data=j;throw e}return j}function dt(s){return s?new Date(s).toLocaleString():'—'}function applyConfig(c){if(c){serverConfig={...serverConfig,...c,registration:c.registration||serverConfig.registration,login:c.login||serverConfig.login}}const r=serverConfig.registration||{};$('regPill').textContent=r.enabled?'Konto bereit':'Login aktiv';$('registerTab').disabled=!r.enabled;$('registerTab').style.opacity=r.enabled?'1':'.42'}async function loadConfig(){try{applyConfig(await api('/api/v1/self/config'))}catch{}}
function setMode(m){if(m==='register'&&!serverConfig.registration?.enabled){$('authMsg').textContent='Registrierung ist derzeit deaktiviert.';return}mode=m;$('loginTab').classList.toggle('active',m==='login');$('registerTab').classList.toggle('active',m==='register');$('authTitle').textContent=m==='login'?'Einloggen':'Konto anlegen';$('authLead').textContent=m==='login'?'Willkommen zurück. TOTP fragen wir erst ab, wenn dein Konto es wirklich aktiviert hat.':(serverConfig.registration?.approvalRequired?'Dein Konto wird mit E-Mail und Benutzername angelegt und wartet danach auf Admin-Freigabe.':'Erstelle dein Konto mit E-Mail und Benutzername.');$('submitBtn').textContent=m==='login'?'Einloggen':'Konto erstellen';$('accountLabel').textContent=m==='login'?'Benutzername oder E-Mail':'E-Mail';$('account').type=m==='login'?'text':'email';$('account').placeholder=m==='login'?'Benutzername oder E-Mail':'name@example.com';$('registerUsernameBox').classList.toggle('hidden',m!=='register');$('modeSwitch').textContent=m==='login'?'Noch kein Konto? Registrieren':'Schon Konto? Einloggen';$('forgotBtn').classList.toggle('hidden',m!=='login');$('credentialFields').classList.remove('hidden');$('totpLoginBox').classList.add('hidden');$('totpLoginMount').innerHTML='';$('authMsg').textContent=''}function toggleMode(){setMode(mode==='login'?'register':'login')}function showPanel(name){$('accountPanel').classList.toggle('hidden',name!=='account');$('adminPanel').classList.toggle('hidden',name!=='admin');$('navAccount').classList.toggle('active',name==='account');$('navAdmin').classList.toggle('active',name==='admin');if(name==='admin')loadAdmin()}async function forgotPassword(){try{const email=$('account').value.trim();if(!email){$('authMsg').textContent='Bitte E-Mail eintragen.';return}const j=await api('/api/v1/self/password/forgot',{method:'POST',body:JSON.stringify({email})});$('authMsg').textContent=j.message}catch(e){$('authMsg').textContent=e.message}}async function resetPassword(){try{const j=await api('/api/v1/self/password/reset',{method:'POST',body:JSON.stringify({token:$('resetToken').value,newPassword:$('resetPassword').value})});$('resetMsg').textContent=j.message;$('password').value='';$('resetPassword').value='';setMode('login')}catch(e){$('resetMsg').textContent=e.message}}function initResetLink(){const q=new URLSearchParams(location.search);const t=q.get('reset');const e=q.get('email');if(e)$('account').value=e;if(t){$('resetToken').value=t;$('resetBox').classList.remove('hidden');$('authMsg').textContent='Reset-Link erkannt. Neues Passwort setzen.';history.replaceState(null,'','/account')}}
function showToken(j,target='tokenMsg'){if(j.token) $(target).innerHTML='<span class="ok">'+esc(j.message||'OK')+'</span><code class="tokenBox">'+esc(j.token)+'</code>';else $(target).textContent=j.message||'OK'}function renderTokens(tokens){const list=$('tokenList');tokens=tokens||profile?.tokens||[];list.innerHTML='<h3>Aktive Sync-Tokens</h3>'+(tokens.length?'<div class="tokenListScroll">'+tokens.map(t=>'<div class="tokenRow"><div><b>'+esc(t.label||'Sync-Token')+'</b><div class="tokenMeta">ID: '+esc(t.id)+'<br>Erstellt: '+esc(dt(t.createdAtText))+'<br>Zuletzt benutzt: '+esc(dt(t.lastUsedAtText))+'</div></div><button class="danger" data-id="'+esc(t.id)+'">Löschen</button></div>').join('')+'</div>':'<p class="muted">Keine aktiven Tokens.</p>');list.querySelectorAll('button[data-id]').forEach(b=>b.addEventListener('click',()=>deleteToken(b.dataset.id)))}
function render(j){profile=j.profile;applyConfig(j);document.body.classList.toggle('isAdmin',!!profile.isAdmin);$('auth').classList.add('hidden');$('app').classList.remove('hidden');$('navLogout').classList.remove('hidden');const displayName=profile.username?'@'+profile.username:profile.account;$('hello').textContent=displayName+' · '+profile.account+' · '+profile.status+(profile.isAdmin?' · Admin':'');$('accountStatus').textContent='Benutzername: '+(profile.username?'@'+profile.username:'—')+' · E-Mail: '+profile.account+' · Erstellt: '+dt(profile.createdAtText)+' · Geändert: '+dt(profile.updatedAtText)+' · Tokens: '+(profile.tokenCount||0);const s=j.sync||{};$('syncStatus').textContent=s.hasSync?'Sync-Daten vorhanden · '+humanSize(s.size||0)+' · '+dt(s.updatedAtText):'Keine Sync-Daten auf Server';$('registrationStatus').textContent='Registrierung: '+(serverConfig.registration?.mode||'open');$('emailNew').value=profile.account.includes('@')?profile.account:'';$('usernameNew').value=profile.username||'';$('totpStatus').textContent=profile.totpEnabled?'TOTP ist aktiv.':'TOTP ist nicht aktiv.';$('totpDisable').classList.toggle('hidden',!profile.totpEnabled);$('setupTotpBtn').classList.toggle('hidden',!!profile.totpEnabled);renderTokens(profile.tokens)}async function submitAuth(){try{const body={account:$('account').value,password:$('password').value};if(mode==='register')body.username=$('username').value;const challengeTotp=$('totpChallenge');if(mode==='login'&&challengeTotp)body.totp=challengeTotp.value;const j=await api(mode==='login'?'/api/v1/self/login':'/api/v1/self/register',{method:'POST',body:JSON.stringify(body)});if(j.pending){$('authMsg').textContent=j.message;return}render(j);if(mode==='register')showToken(j)}catch(e){$('authMsg').textContent=e.message;if(e.data?.totpRequired){$('credentialFields').classList.add('hidden');$('totpLoginBox').classList.remove('hidden');$('totpLoginMount').innerHTML='<input id="totpChallenge" inputmode="numeric" maxlength="6" autocomplete="off" data-bwignore="true" data-lpignore="true" data-1p-ignore placeholder="123456">';$('totpChallenge').focus()}}}async function loadMe(){try{render(await api('/api/v1/self/me'))}catch{}}async function logout(){await api('/api/v1/self/logout',{method:'POST'}).catch(()=>{});location.reload()}async function rotateToken(){const j=await api('/api/v1/self/token',{method:'POST',body:'{}'});render(j);showToken(j)}async function deleteToken(id){if(!confirm('Token löschen?'))return;const j=await api('/api/v1/self/tokens/delete',{method:'POST',body:JSON.stringify({id})});render(j);$('tokenMsg').textContent=j.message}async function changePassword(){try{const j=await api('/api/v1/self/password',{method:'POST',body:JSON.stringify({currentPassword:$('accountPassword').value,newPassword:$('newPassword').value})});render(j);showToken(j,'passMsg');$('accountPassword').value='';$('newPassword').value=''}catch(e){$('passMsg').textContent=e.message}}async function changeUsername(){try{const j=await api('/api/v1/self/username',{method:'POST',body:JSON.stringify({username:$('usernameNew').value,password:$('accountPassword').value})});render(j);$('accountPassword').value='';$('usernameMsg').textContent=j.message}catch(e){$('usernameMsg').textContent=e.message}}async function changeEmail(){try{const j=await api('/api/v1/self/email',{method:'POST',body:JSON.stringify({email:$('emailNew').value,password:$('accountPassword').value})});render(j);$('accountPassword').value='';$('emailMsg').textContent=j.message}catch(e){$('emailMsg').textContent=e.message}}function updateImportFileName(){const f=$('importFile').files?.[0];$('importFileName').textContent=f?f.name:'Keine Datei ausgewählt'}async function importData(){try{const f=$('importFile').files[0];if(!f){$('importMsg').textContent='Bitte Export-Datei auswählen.';return}const text=await f.text();const j=await api('/api/v1/self/import',{method:'POST',body:text});render(j);$('importFile').value='';$('importMsg').textContent=j.message+(j.backup?' Vorherige Sync-Daten wurden gesichert.':'')}catch(e){$('importMsg').textContent=e.message}}async function setupTotp(){const j=await api('/api/v1/self/totp/setup',{method:'POST',body:'{}'});pendingTotpSecret=j.secret;$('totpSetup').classList.remove('hidden');$('totpSecret').textContent=j.secret;$('otpauth').textContent=j.otpauth;try{const qr=qrcode(0,'M');qr.addData(j.otpauth);qr.make();$('totpQr').innerHTML=qr.createSvgTag(4,4)}catch(e){$('totpQr').textContent='QR konnte nicht erstellt werden.'}$('totpMsg').textContent=''}async function enableTotp(){try{const j=await api('/api/v1/self/totp/enable',{method:'POST',body:JSON.stringify({secret:pendingTotpSecret,code:$('totpEnableCode').value})});pendingTotpSecret='';$('totpSecret').textContent='';$('otpauth').textContent='';$('totpQr').innerHTML='';render(j);$('totpSetup').classList.add('hidden');$('totpEnableCode').value='';$('totpMsg').textContent=j.message}catch(e){$('totpMsg').textContent=e.message}}async function disableTotp(){try{const j=await api('/api/v1/self/totp/disable',{method:'POST',body:JSON.stringify({password:$('totpDisablePassword').value,code:$('totpDisableCode').value})});render(j);$('totpDisablePassword').value='';$('totpDisableCode').value='';$('totpMsg').textContent=j.message}catch(e){$('totpMsg').textContent=e.message}}async function deleteSync(){if(!confirm('Eigene Sync-Daten löschen?'))return;const j=await api('/api/v1/self/sync/delete',{method:'POST',body:'{}'});render(j);$('dangerMsg').textContent=j.message}async function deleteAccount(){const p=prompt('Passwort eingeben, um Konto endgültig zu löschen');if(!p)return;const j=await api('/api/v1/self/delete',{method:'POST',body:JSON.stringify({password:p})});$('dangerMsg').textContent=j.message;setTimeout(()=>location.reload(),800)}async function loadAdmin(){try{const j=await api('/api/v1/admin/users');renderAdmin(j)}catch(e){$('adminMsg').textContent=e.message}}
function renderAdmin(data){const users=Array.isArray(data)?data:(data.users||[]);const reg=(data.registration||serverConfig.registration||{});if($('adminRegistrationStatus'))$('adminRegistrationStatus').textContent='Aktueller Modus: '+(reg.mode||'open');document.querySelectorAll('button[data-reg]').forEach(b=>{b.classList.toggle('active',b.dataset.reg===reg.mode);b.onclick=()=>adminRegistration(b.dataset.reg)});$('adminUsers').innerHTML=users.map(u=>{const protectedAdmin=u.isEnvAdmin||u.account===profile?.account;const roleButton=protectedAdmin?'<span class="pill">geschützt</span>':'<button class="ghost" data-role="'+(u.isAdmin?'0':'1')+'" data-account="'+esc(u.account)+'">'+(u.isAdmin?'Admin entziehen':'Admin machen')+'</button>';const deleteButton=protectedAdmin?'<span class="pill">nicht löschbar</span>':'<button class="danger" data-delete="'+esc(u.account)+'">Löschen</button>';return '<div class="userRow"><div><b>'+esc(u.account)+'</b> '+(u.username?'<span class="pill">@'+esc(u.username)+'</span> ':'')+'<span class="userStatus '+esc(u.status)+'">'+esc(u.status)+'</span> '+(u.isAdmin?'<span class="pill">Admin</span>':'')+(u.isEnvAdmin?'<span class="pill">Env</span>':'')+'<div class="mini">Tokens: '+(u.tokenCount||0)+' · TOTP: '+(u.totpEnabled?'ja':'nein')+' · Sync: '+(u.sync?.hasSync?'ja':'nein')+' · geändert: '+esc(dt(u.updatedAtText))+'</div></div><div class="actions"><button class="ghost" data-action="active" data-account="'+esc(u.account)+'">Freigeben</button><button class="ghost" data-action="suspended" data-account="'+esc(u.account)+'">Sperren</button>'+roleButton+deleteButton+'</div></div>'}).join('')||'<p class="muted">Keine Nutzer.</p>';$('adminUsers').querySelectorAll('button[data-action]').forEach(b=>b.onclick=()=>adminStatus(b.dataset.account,b.dataset.action));$('adminUsers').querySelectorAll('button[data-role]').forEach(b=>b.onclick=()=>adminRole(b.dataset.account,b.dataset.role==='1'));$('adminUsers').querySelectorAll('button[data-delete]').forEach(b=>b.onclick=()=>adminDelete(b.dataset.delete))}
async function adminRegistration(mode){const j=await api('/api/v1/admin/settings/registration',{method:'POST',body:JSON.stringify({mode})});serverConfig.registration=j.registration;$('adminMsg').textContent=j.message;renderAdmin(j)}
async function adminStatus(account,status){const j=await api('/api/v1/admin/users/status',{method:'POST',body:JSON.stringify({account,status})});$('adminMsg').textContent=j.message;renderAdmin(j)}
async function adminRole(account,isAdmin){const j=await api('/api/v1/admin/users/role',{method:'POST',body:JSON.stringify({account,isAdmin})});$('adminMsg').textContent=j.message;renderAdmin(j)}
async function adminDelete(account){if(!confirm('Nutzer '+account+' löschen?'))return;const j=await api('/api/v1/admin/users/delete',{method:'POST',body:JSON.stringify({account})});$('adminMsg').textContent=j.message;renderAdmin(j)}loadConfig();setMode('login');initResetLink();loadMe();
</script></body></html>`;

migrateAllLegacyTotpSecrets();

http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url || '/', `http://${req.headers.host}`);
    if (req.method === 'OPTIONS') { const pub = u.pathname === '/healthz' || u.pathname === '/api/v1/releases' || u.pathname === '/SHA256SUMS.txt' || u.pathname === '/SHA256SUMS.txt.sig' || u.pathname.startsWith('/downloads/'); return send(res, 204, '', pub ? publicCorsHeaders() : { ...apiCorsHeaders(req), 'Access-Control-Allow-Methods': 'GET,PUT,POST,OPTIONS', 'Access-Control-Allow-Headers': 'content-type,x-sync-token' }); }
    if (u.pathname === '/' || u.pathname === '/index.html') return html(res, 200, landingPage);
    if (u.pathname === '/assets/qrcode.js') return send(res, 200, fs.readFileSync(path.join(appDir, 'qrcode.js'), 'utf8'), { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
    if (u.pathname === '/desktop-guide' || u.pathname === '/desktop-guide/') return html(res, 200, desktopGuidePage);
    if (u.pathname === '/server-guide' || u.pathname === '/server-guide/') return html(res, 200, serverGuidePage);
    if (u.pathname === '/web-guide' || u.pathname === '/web-guide/') return html(res, 200, webGuidePage);
    if (u.pathname === '/account' || u.pathname === '/account/') return html(res, 200, accountPage);
    if (u.pathname.startsWith('/api/v1/admin/')) { if (!requireCookieAPICSRF(req, res)) return; return await handleAdminAPI(req, res, u); }
    if (u.pathname.startsWith('/api/v1/self/')) { if (!requireCookieAPICSRF(req, res)) return; return await handleSelfAPI(req, res, u); }
    if (u.pathname === '/healthz') return json(res, 200, { ok: true, service: 'ssh-vault2', version: serverVersion }, publicCorsHeaders());
    if (u.pathname === '/api/v1/releases') { const vs = versions(); return json(res, 200, { version: vs[0]?.version || serverVersion, serverVersion, changelog: vs[0]?.changelog || [], versions: vs, files: files(), unsigned: [] }, publicCorsHeaders()); }
    if (u.pathname === '/SHA256SUMS.txt') return sendFile(res, releaseFile('SHA256SUMS.txt'), { 'Content-Type': 'text/plain', ...publicCorsHeaders() });
    if (u.pathname === '/SHA256SUMS.txt.sig') return sendFile(res, releaseFile('SHA256SUMS.txt.sig'), { 'Content-Type': 'text/plain', ...publicCorsHeaders() });
    if (u.pathname.startsWith('/downloads/')) { const name = decodeURIComponent(u.pathname.slice('/downloads/'.length)); const item = downloadFile(name); if (!item) return json(res, 404, { error: 'not found' }); return sendFile(res, item.f, { 'Content-Type': 'application/octet-stream', ...publicCorsHeaders() }); }
    if (u.pathname.startsWith('/api/v1/accounts/')) return await handleAppAccount(req, res, u);
    if (u.pathname.startsWith('/api/v1/sync/')) return await handleSync(req, res, u);
    json(res, 404, { error: 'not found' });
  } catch (e) { json(res, e.statusCode || 500, { error: String(e.message || e) }); }
}).listen(port, process.env.HOST || '0.0.0.0', () => console.log(`ssh-vault2 server ${serverVersion} on ${process.env.HOST || '0.0.0.0'}:${port}`));
