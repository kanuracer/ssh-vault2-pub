import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

test('frontend does not rehydrate backend secrets into long-lived state', () => {
  assert.doesNotMatch(app, /setVaultDraft\(\{\.\.\.vaultDraft,\s*privateKey:key\}\)/);
  assert.match(app, /scrubVaultCredential/, 'vault credentials must be scrubbed before entering long-lived renderer state');
  assert.doesNotMatch(app, /setVaultDraft\(\{\.\.\.v\}\)/, 'editing vault entries must not copy saved secret fields back into draft state');
  assert.doesNotMatch(app, /setVaultDraft\(savedEntry \? \{\.\.\.savedEntry\} : emptyVault\)/, 'import refresh must not copy saved secret fields back into draft state');
  assert.doesNotMatch(app, /<textarea[^>]+value=\{vaultDraft\.privateKey/);
  assert.match(app, /privateKeySaved/);
});

test('frontend redacts secret-looking error details before rendering', () => {
  assert.match(app, /redactSecrets/, 'frontend must centralize secret redaction');
  assert.match(app, /Authorization:\\s\*Bearer/i, 'redactor must cover bearer tokens');
  assert.match(app, /password\|token\|autoPassphrase\|passphrase\|privateKey/, 'redactor must cover common secret keys');
  assert.match(app, /BEGIN\[\\s\\S\]\*\?PRIVATE KEY/, 'redactor must cover PEM private keys');
  assert.doesNotMatch(app, /details:raw\b/, 'sync notices must not store raw unredacted error details');
  assert.doesNotMatch(app, /const msg = String\(e\);\s*\n\s*if \(!msg\.includes/, 'auto-sync must redact errors before showing them');
});

test('frontend clears transient passphrases and login codes on all exits', () => {
  assert.match(app, /finally \{\s*setLocalVaultPass\(''\);\s*\}/, 'local vault passphrase must clear after unlock/encrypt attempts');
  assert.match(app, /setAccountLogin\(prev => \(\{\.\.\.prev, password:'', totp:''\}\)\)/, 'sync login password must clear on success and failure');
  assert.match(app, /closeTotpDialog/, 'TOTP dialog close/cancel must clear code state');
  assert.match(app, /syncPassRef\.current = '';\s*setSyncPass\(''\);/, 'saved sync passphrase must clear from refs/state after use');
  assert.match(app, /clearDraftSecrets/, 'host/vault draft secret fields must clear on cancel/lock');
});

test('frontend binds SSH trust to displayed fingerprint and cleans runtime error wrappers', () => {
  assert.match(app, /const text = cleanError\(err\);/, 'host-key prompt must parse cleaned runtime errors, not raw JSON wrappers');
  assert.match(app, /API\.TrustSSHHost\(hostID,\s*fingerprint\)/);
  assert.match(app, /Host-Key Fingerprint fehlt/);
});

test('frontend validates sync endpoints before login and save', () => {
  assert.match(app, /validSyncEndpoint/);
  assert.match(app, /Sync-Server muss HTTPS nutzen/);
});

test('frontend offers only newer update versions and no rollback wording', () => {
  assert.ok(app.includes("compatibleVersions = (r: ReleaseIndex | null): ReleaseVersion[] => releaseVersions(r).filter"));
  assert.ok(app.includes("semverGreater(v.version, info?.version || '0.0.0')"));
  assert.match(app, /Nur neuere Versionen/);
  assert.doesNotMatch(app, /Rollback/i);
  assert.doesNotMatch(app, /ältere Version/);
});

test('vault unlock refreshes sync refs and starts pull-first auto-sync', () => {
  assert.match(app, /syncCfgRef\.current = c;\s*syncPassRef\.current = '';\s*setSyncCfg\(c\);\s*setSyncPass\(''\);/);
  assert.match(app, /syncReady\(c, ''\)\) void autoSync\('vault-unlock'\)/);
  assert.match(app, /reason\.startsWith\('vault-'\)/);
});

test('settings lives in host sidebar footer, not main tabs', () => {
  const tabs = app.match(/<div className="viewTabs" role="tablist">([\s\S]*?)<\/div>\s*<\/header>/)?.[1] || '';
  assert.doesNotMatch(tabs, /Einstellungen/);
  assert.match(app, /className="sidebarFooter"/);
  assert.match(app, /className="settingsGear"/);
  assert.match(app, />⚙<\/span>/);
  assert.match(app, /setView\('settings'\)/);
});

test('updates live inside settings, not as a main workspace tab', () => {
  const tabs = app.match(/<div className="viewTabs" role="tablist">([\s\S]*?)<\/div>\s*<\/header>/)?.[1] || '';
  assert.doesNotMatch(tabs, /Updates/);
  assert.doesNotMatch(app, /view==='updates'/);
  assert.match(app, /className="settingsCard updateSettingsCard"/);
  assert.match(app, /<h3>Updates<\/h3>/);
  assert.match(app, /onClick=\{checkUpdates\}/);
  assert.match(app, /onClick=\{installSelectedUpdate\}/);
});

test('startup update check is shown beside sidebar version and opens update settings', () => {
  assert.match(app, /checkUpdatesOnStartup\(i\)/);
  assert.match(app, /updateSettingsRef = useRef<HTMLElement \| null>\(null\)/);
  assert.match(app, /function openUpdateSettings\(\)/);
  assert.match(app, /className="versionMeta"/);
  assert.match(app, /className=\{`updateBadge/);
  assert.match(app, /onClick=\{openUpdateSettings\}/);
  assert.match(app, /updateSettingsRef\.current\?\.scrollIntoView/);
});

test('sftp supports multiple tabs without closing the previous connection', () => {
  assert.match(app, /type SftpTab = \{id:string; hostID:string; title:string; remotePath:string; remote:FileEntry\[\]; selectedRemote:string\}/);
  assert.match(app, /const \[sftpTabs, setSftpTabs\] = useState<SftpTab\[\]>\(\[\]\)/);
  assert.match(app, /const \[activeSftp, setActiveSftp\] = useState\(''\)/);
  assert.match(app, /function switchSftpTab\(tab: SftpTab\)/);
  assert.match(app, /async function closeSftpTab\(id: string/);
  assert.match(app, /className="tabs sessionTabs sftpTabs"/);
  assert.match(app, /setSftpTabs\(prev => \[\.\.\.prev, tab\]\)/);
  assert.doesNotMatch(app, /if \(oldId && oldId !== r\.id\)/);
});
