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

test('sync footer lock state follows real local Datensafe lock, not just saved sync secrets', () => {
  assert.match(source, /const syncVaultLocked = syncSecretsLocked\(syncCfg, syncPass\) && localVault\.configured && !localVault\.unlocked/, 'lock icon must require a configured but locked local Datensafe');
  assert.match(source, /const syncCanRun = syncReady\(syncCfg, syncPass\) && !syncVaultLocked/, 'runnable sync must be blocked only while Datensafe is actually locked');
  assert.match(source, /syncVaultLocked \? 'locked'/, 'footer state must use syncVaultLocked');
  assert.doesNotMatch(source, /syncSecretsLocked\(syncCfg, syncPass\) \? 'locked'/, 'footer must not show lock merely because secrets are stored');
});

test('sync footer click routes lock to Datensafe unlock and sync states to sync settings', () => {
  assert.match(source, /function openLocalVaultUnlock\(\)/, 'Datensafe unlock route missing');
  assert.match(source, /setShowLocalVaultPrompt\(true\)/, 'lock click must open the unlock dialog');
  assert.match(source, /function openSyncSettings\(\)/, 'sync settings route missing');
  assert.match(source, /const syncActionsRef = useRef<HTMLDivElement \| null>\(null\)/, 'sync action-row ref missing');
  assert.match(source, /\(syncActionsRef\.current \|\| syncSettingsRef\.current\)\?\.scrollIntoView\(\{ behavior:'smooth', block:'center' \}\)/, 'sync click must scroll to the sync action buttons');
  assert.match(source, /<div className="row" ref=\{syncActionsRef\}><button onClick=\{\(\)=>saveSync\(true\)\}>Auto-Sync speichern<\/button><button className="primary" onClick=\{pushSync\}>Jetzt hochladen<\/button><button onClick=\{pullSync\}>Vom Server laden<\/button><\/div>/, 'sync action buttons must own the scroll target');
  assert.match(source, /function handleSyncFooterClick\(\) \{ if \(syncFooterState === 'locked'\) openLocalVaultUnlock\(\); else openSyncSettings\(\); \}/, 'sync footer button must choose destination by state');
  assert.match(source, /onClick=\{handleSyncFooterClick\}/, 'sync footer button must use the state-aware click handler');
});

test('sync footer visual is lock for Datensafe and true circular sync with centered state dot', () => {
  assert.match(source, /syncFooterState === 'locked' \? <span className="syncLockIcon"/, 'locked state must render a lock icon');
  assert.match(source, /<span className="syncCompositeIcon"/, 'sync states must render a composite icon');
  assert.match(source, /<circle className="syncStatusDot" cx="20" cy="20" r="4\.8"\/>/, 'sync icon must include a centered state-colored status dot');
  assert.match(source, /<svg className="syncGlyph" viewBox="0 0 40 40"/, 'sync icon must use an SVG two-arrow sync glyph');
  assert.match(source, /<circle className="syncGlyphRing" cx="20" cy="20" r="13"\/>/, 'sync icon must use a true SVG circle ring, not an oval-looking arc');
});

test('sync footer button is pulled away from right divider and stays close to version pill', () => {
  const footer = cssBlock('.sidebarFooter');
  assert.match(source, /className="footerSyncCluster"/, 'version and sync must share a dedicated cluster');
  assert.match(footer, /display:flex/, 'footer must be a normal button bar');
  assert.match(footer, /gap:4px/, 'settings and version controls use equal-width geometry without pushing sync out');
  assert.match(footer, /width:100%/, 'footer must use full available row width for centering');
  assert.match(footer, /max-width:100%/, 'footer max-width must preserve centering');
  assert.match(footer, /margin-right:0/, 'footer row must not use asymmetric right margin');
  assert.match(cssBlock('.footerSyncCluster'), /gap:6px!important/, 'version and sync should be separate readable controls');
  assert.match(footer, /margin-left:0/, 'footer row must be centered as a single control group');
  assert.match(footer, /transform:translateX\(6px\)/, 'footer row compensates asymmetric sidebar padding to center the group');
  assert.match(css, /\.sidebarFooter \.syncFooterButton\{width:40px!important;min-width:40px!important;max-width:40px!important;flex:0 0 40px!important;justify-content:center!important;padding-left:0!important;overflow:hidden!important;margin-left:0!important\}/, 'sync button must stay 40px wide without overlapping the version pill');
  assert.match(css, /\.sidebarFooter \.syncFooterButton\{width:40px!important;min-width:40px!important;max-width:40px!important;flex:0 0 40px!important;justify-content:center!important;padding-left:0!important;overflow:hidden!important;margin-left:0!important\}/, 'sync glyph must stay inside the unchanged 40px button');
  assert.match(cssBlock('.versionMeta'), /justify-content:center/, 'version pill must not use space-between before the sync button');
  assert.match(cssBlock('.updateBadge'), /margin-left:0/, 'badge must not use auto margin that creates a visible gap');
  assert.doesNotMatch(css, /syncFooterButton\{[^}]*margin-left:-/, 'sync button must not overlap or intrude into the version pill');
  assert.match(source, /<span className="syncLockIcon" aria-hidden="true"><\/span>/, 'locked sync button must use CSS icon, not emoji font');
  assert.match(css, /syncLockIcon\{[^}]*width:22px[^}]*height:22px/s, 'CSS lock icon must use a 22px wrapper for optical centering');
  assert.match(css, /syncLockIcon::before\{[^}]*box-sizing:border-box[^}]*left:5px[^}]*top:3px[^}]*border:2px solid currentColor/s, 'CSS lock shackle must render centered on Windows');
  assert.match(css, /syncLockIcon::after\{[^}]*box-sizing:border-box[^}]*left:4px[^}]*top:10px[^}]*border:2px solid currentColor/s, 'CSS lock body must render centered on Windows');
  assert.match(css, /syncCompositeIcon\{[^}]*transform:none/, 'sync icon wrapper stays centered inside the normal 40px button');
  assert.match(css, /\.syncGlyphRing,\.syncGlyphHead\{[^}]*stroke:currentColor[^}]*stroke-width:3\.2/s, 'sync glyph must use a true circular ring with arrowheads');
  assert.doesNotMatch(css, /syncArrow/, 'old single reload-style syncArrow CSS must be removed');
  assert.match(css, /syncStatusDot\{[^}]*fill:#ef4444[^}]*stroke:#071020[^}]*stroke-width:2/s, 'sync status dot must be rendered inside the SVG center');
  assert.match(css, /syncFooterButton\.ok \.syncStatusDot\{fill:#24ff78/, 'ok sync status dot must be green');
  assert.match(css, /syncFooterButton\.error \.syncStatusDot\{fill:#ff3b3b/, 'error sync status dot must be red');
});
