import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const cssBlock = (selector) => {
  const start = css.indexOf(selector + '{');
  assert.notEqual(start, -1, `${selector} block missing`);
  const end = css.indexOf('}', start);
  return css.slice(start, end + 1);
};

test('sidebar footer keeps settings, version and sync in one row with sync as separate icon button', () => {
  const footer = cssBlock('.sidebarFooter');
  assert.match(source, /className="sidebarFooter"/, 'footer missing');
  assert.match(source, /className="footerSyncCluster"/, 'version and sync must be wrapped as one tight cluster');
  assert.match(source, /className="versionMeta"/, 'version button missing');
  assert.match(source, /className=\{`syncFooterButton \$\{syncFooterState\}`\}/, 'sync status must be a separate icon button');
  assert.match(source, /aria-label=\{syncFooterTitle\}/, 'sync icon must expose readable status');
  assert.match(source, /syncFooterState === 'locked' \? <span className="syncLockIcon"/, 'locked state must render a lock icon');
  assert.match(source, /<span className="syncCompositeIcon"/, 'sync state must render dot + circular arrows');
  assert.doesNotMatch(source, /syncFooterBadge/, 'sync status must not be inside the version button');
  assert.doesNotMatch(source, /footerBadges/, 'version button must not contain a second row of footer badges');
  assert.match(footer, /display:flex;/, 'footer must use one-row flex button bar');
  assert.match(footer, /gap:4px;/, 'settings and version cluster must use normal button spacing');
  assert.match(footer, /overflow:hidden;/, 'footer controls must remain inside the sidebar');
  assert.match(css, /\.footerSyncCluster\{[^}]*gap:6px!important/, 'version and sync must be separate readable controls');
  assert.doesNotMatch(footer, /flex-direction:column/, 'footer must not stack buttons into two rows');
});

test('sync footer state is derived from real sync readiness, Datensafe lock and running state', () => {
  assert.match(source, /const \[syncRunning, setSyncRunning\] = useState\(false\)/, 'sync running must be real React state');
  assert.match(source, /syncRunning \? 'syncing'/, 'syncing state missing');
  assert.match(source, /const syncVaultLocked = syncSecretsLocked\(syncCfg, syncPass\) && localVault\.configured && !localVault\.unlocked/, 'locked-vault state must require actual Datensafe lock');
  assert.match(source, /const syncCanRun = syncReady\(syncCfg, syncPass\) && !syncVaultLocked/, 'sync can run must exclude locked Datensafe');
  assert.match(source, /syncVaultLocked \? 'locked'/, 'footer state must use actual Datensafe lock');
  assert.match(source, /!syncCanRun \? 'waiting'/, 'not-ready state missing');
  assert.match(source, /setSyncRunning\(true\); try \{ const c = await saveSync\(false\)/, 'manual sync actions must set running state');
  assert.match(source, /finally \{ autoSyncBusy\.current = false; setSyncRunning\(false\); \}/, 'auto sync must clear running state');
});
