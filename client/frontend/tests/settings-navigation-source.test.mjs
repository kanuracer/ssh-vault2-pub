import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');

test('settings use grouped category navigation instead of one long scroll list', () => {
  assert.match(app, /type SettingsPanel = 'appearance'\|'updates'\|'securitySync'\|'knownHosts'\|'transfer'/, 'settings panels must be explicit, typed, and user-task grouped');
  assert.match(app, /className="settings settingsShell"/, 'settings view must use the compact shell');
  assert.match(app, /<nav className="settingsNav" aria-label="Einstellungsbereiche">/, 'settings need a visible category nav');
  assert.match(app, /settingsPanel==='appearance'/, 'appearance settings must be panel-scoped');
  assert.match(app, /settingsPanel==='updates'/, 'updates settings must be panel-scoped');
  assert.match(app, /settingsPanel==='securitySync'/, 'datensafe, account, and sync settings must be in one panel');
  assert.match(app, /settingsPanel==='knownHosts'/, 'known-host settings must be panel-scoped');
  assert.match(app, /settingsPanel==='transfer'/, 'local transfer settings must be panel-scoped');
  assert.doesNotMatch(app, /\['vault','Datensafe'/, 'Datensafe must not be a separate top-level tab');
  assert.doesNotMatch(app, /\['account','Sync-Konto'/, 'Sync-Konto must not be a separate top-level tab');
  assert.doesNotMatch(app, /\['sync','Sync'/, 'Sync must not be a separate top-level tab');
  assert.match(app, /\['securitySync','Sicherheit & Sync'/, 'merged top-level tab must be user-facing');
  assert.match(app, /settingsPanel==='securitySync'[\s\S]*<h4>Lokaler Datensafe<\/h4>[\s\S]*<h4>Sync-Konto<\/h4>[\s\S]*<h4>Verschlüsselter Sync<\/h4>/, 'merged panel must keep all three subsections');
  assert.doesNotMatch(app, /\['import','\.ssh\/config'/, 'ssh config import must not be a separate nav tile');
  assert.match(app, /settingsPanel==='transfer'[\s\S]*\.ssh\/config importieren/, 'ssh config import belongs inside Export/Import');
});

test('deep links open the merged security and sync category before scrolling', () => {
  assert.match(app, /function openUpdateSettings\(\) \{ setSettingsPanel\('updates'\);/, 'update badge must open update category');
  assert.match(app, /function openSyncSettings\(\) \{ setSettingsPanel\('securitySync'\);/, 'sync footer must open merged security/sync category');
  assert.match(app, /function openLocalVaultSettings\(\) \{ setSettingsPanel\('securitySync'\);/, 'datensafe prompt must open merged security/sync category');
  assert.match(app, /function openLocalVaultUnlock\(\)[\s\S]*setSettingsPanel\('securitySync'\)/, 'datensafe unlock must open merged security/sync category');
});

test('settings navigation is compact, sticky, left aligned, and responsive', () => {
  assert.match(css, /\.settingsNav\{[\s\S]*grid-template-columns:repeat\(5,minmax\(0,1fr\)\)/, 'settings nav must use a stable five-tab desktop row');
  assert.match(css, /\.settingsNav\{[\s\S]*width:calc\(100% \+ 20px\)[\s\S]*padding:0 0 10px[\s\S]*margin:0 0 0 -20px[\s\S]*background:transparent/, 'settings nav must compensate the real 20px desktop visual inset seen in app screenshots');
  assert.match(css, /@media \(max-width: 980px\)\{\.settingsNav\{grid-template-columns:repeat\(auto-fit,minmax\(124px,1fr\)\);width:100%;margin:0\}\}/, 'settings nav must wrap on small screens without any offset');
  assert.match(css, /\.settingsNav\{[\s\S]*position:sticky/, 'settings nav must stay reachable while panel content scrolls');
  assert.match(css, /\.settingsNavButton\{[\s\S]*width:100%!important[\s\S]*max-width:none!important/, 'category buttons must fill their grid cell, not collapse to text width');
  assert.match(css, /\.settingsNavButton\{[\s\S]*padding:6px 2px/, 'category labels must sit nearly flush with the tab edge');
  assert.match(css, /\.settingsNavButton\{[\s\S]*min-height:42px/, 'category buttons must stay compact');
  assert.match(css, /\.settingsPanel \.settingsCard\{max-width:none\}/, 'active panel card should align to the settings nav width');
});

test('settings nav is visually integrated, not dashboard-card noisy', () => {
  assert.match(css, /\.settingsNavButton\.active\{[\s\S]*background:#12213a[\s\S]*border-color:#3f6fa8[\s\S]*box-shadow:inset 0 2px 0 #63a8ff/, 'active category should use subtle app-native accent, not a hard white outline');
  assert.doesNotMatch(css, /\.settingsNavButton\.active\{[^}]*border-color:#63a8ff/, 'active category border should not be the loud bright-blue/white-ish outline');
  assert.match(css, /\.settingsSubsection\{[\s\S]*border-top:1px solid #3a4d6f[\s\S]*padding-top:18px/, 'merged subsections need a visible internal separator, not a barely visible hairline');
  assert.match(css, /\.settingsSubsection h4\{[\s\S]*padding-bottom:8px[\s\S]*border-bottom:1px solid #2f4263[\s\S]*color:#f6f9ff[\s\S]*font-size:16\.5px[\s\S]*font-weight:800/, 'subsection headings must be clearly readable and visually separated');
  assert.match(css, /\.settingsSubsection label\{color:#c7d6ea;font-weight:800\}/, 'settings labels must have strong contrast on the dark card background');
});

test('export import tab uses short meta text', () => {
  assert.match(app, /\['transfer','Export\/Import','Dateien \+ SSH'\]/, 'Export/Import meta must stay short and include ssh config import');
});
