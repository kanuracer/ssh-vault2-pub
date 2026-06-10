import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');

test('rdp empty state shows only guidance and no RDP öffnen button', () => {
  const rdpBlock = app.match(/\{view==='rdp'[\s\S]*?\{view==='sftp'/)?.[0] || '';
  assert.match(rdpBlock, /Host wählen und RDP öffnen\./, 'RDP tab should still explain what to do');
  assert.doesNotMatch(rdpBlock, />RDP öffnen<|\{connectingRDP\?'Verbinde…':'RDP öffnen'\}/, 'RDP tab empty state must not render a central RDP öffnen button');
  assert.doesNotMatch(rdpBlock, /<button[^>]*onClick=\{\(\)=>connectRDP\(\)\}/, 'RDP tab empty state must not keep the connectRDP button');
});

test('host menu exposes a tag filter button and filters the visible host list', () => {
  assert.match(app, /const \[tagFilterOpen, setTagFilterOpen\] = useState\(false\)/, 'host tag filter popover state is required');
  assert.match(app, /const \[visibleTags, setVisibleTags\] = useState<string\[\]>\(storedVisibleTags\)/, 'visible tag selection state must initialize from persisted storage');
  assert.match(app, /const visibleTagsStorageKey = 'sshv\.visibleTags'/, 'visible tag filter must have a stable localStorage key');
  assert.match(app, /localStorage\.setItem\(visibleTagsStorageKey, JSON\.stringify\(visibleTags\)\)/, 'visible tag filter changes must be persisted');
  assert.match(app, /const availableHostTags = .*hosts\.flatMap\(h => h\.tags \|\| \[\]\)/s, 'available tags must be derived from host tags');
  assert.match(app, /const filteredHosts = .*hosts\.filter/s, 'host list must render filteredHosts, not raw hosts');
  assert.match(app, /className="[^"]*hostAddRow[^"]*"[\s\S]*className="[^"]*hostFilterButton[^"]*"/, 'tag filter must sit in the same row as + Host');
  assert.match(app, /className="[^"]*hostFilterButton[^"]*"[\s\S]*aria-label=\{`?Tags anzeigen/, 'tag filter must be an icon button with accessible label');
  assert.doesNotMatch(app, /className="[^"]*hostFilterButton[^"]*"[^>]*>\s*Tags/, 'tag filter must not render as wide text button');
  assert.match(css, /\.hostAddRow\{[^}]*display:flex[^}]*gap:/s, '+ Host and tag filter must share a flex row');
  assert.match(css, /\.hostFilterButton\{[^}]*width:42px[^}]*height:42px/s, 'tag filter icon button must match + Host height');
  assert.match(app, /className="tagFilterMenu"/s, 'tag filter menu must exist');
  assert.match(app, /filteredHosts\.map\(h =>/, 'host list must map filteredHosts');
  assert.doesNotMatch(app, /<div className="hosts">\{hosts\.map\(h =>/, 'host list must not render all hosts when filters are active');
});

test('tag filter menu stays inside the sidebar and uses normal app buttons', () => {
  assert.match(css, /\.tagFilterMenu\{[^}]*width:min\(338px,calc\(100vw - 32px\)\)/, 'tag filter menu must be wide enough for German labels without forcing min-width overflow');
  assert.match(css, /\.tagFilterMenu\{[^}]*overflow:hidden/, 'tag filter menu must clip its own surface, not leak controls over the sidebar');
  assert.doesNotMatch(css, /\.tagFilterMenu\{[^}]*min-width:320px/, 'tag filter menu must not use the old overflow-causing minimum width');
  assert.match(css, /\.tagFilterActions\{[^}]*display:grid[^}]*grid-template-columns:132px 132px[^}]*justify-content:center[^}]*gap:16px[^}]*padding:0[^}]*transform:translateX\(-20px\)/s, 'tag action buttons must be compensated left after Windows visual QA');
  assert.match(css, /\.tagFilterActions button\{[^}]*flex:0 0 132px[^}]*width:132px[^}]*max-width:132px[^}]*padding:8px 6px[^}]*white-space:nowrap[^}]*overflow:hidden/s, 'tag action labels must stay inside centered fixed-width buttons');
  assert.match(css, /\.tagFilterActions button\{[^}]*border-radius:10px[^}]*background:#11182b[^}]*border-color:#263452/s, 'tag filter actions must look like normal app buttons, not dominant blue pills');
  assert.doesNotMatch(css, /\.tagFilterActions button\{[^}]*border-radius:999px/, 'tag filter actions must not use pill styling');
  assert.match(css, /\.app\.theme-liquid-glozzy [^{]*\.tagFilterMenu[\s\S]*background:linear-gradient/, 'liquid theme must include tag filter menu surface');
  assert.match(css, /\.app\.theme-light [^{]*\.tagFilterMenu[\s\S]*background:#ffffff/, 'light theme must include tag filter menu surface');
  assert.match(css, /\.app\.theme-github-gray \.tagFilterMenu/, 'github-gray theme must style tag filter menu');
  assert.match(css, /\.app\.theme-matrix-green \.tagFilterMenu/, 'matrix theme must style tag filter menu');
});

test('all themes keep workspace tab container transparent without a strip', () => {
  const viewTabContainerRules = [...css.matchAll(/([^{}]*\.viewTabs(?!\s+button)[^{}]*)\{([^}]*)\}/g)].map(m => `${m[1]}{${m[2]}}`);
  assert.ok(viewTabContainerRules.length > 0, 'viewTabs container CSS rules must exist');
  for (const rule of viewTabContainerRules) {
    const bg = rule.match(/background:([^;!]+)/)?.[1]?.trim();
    if (bg) assert.match(bg, /^(transparent|none)$/i, `viewTabs container paints unwanted strip: ${rule}`);
  }
  assert.match(css, /\.viewTabs\{[^}]*background:transparent/, 'base viewTabs must stay transparent');
});


test('rdp host editor exposes per-host keyboard layout', () => {
  assert.match(app, /type RDPKeyboardLayout = 'en-US'\|'de-DE'/, 'RDP keyboard layout type must support US and German layouts');
  assert.match(app, /const rdpKeyboardLayoutOf = \(host\?: HostConfig\): RDPKeyboardLayout/, 'RDP keyboard layout normalization helper is required');
  assert.match(app, /rdpKeyboardLayout:'en-US'/, 'new RDP hosts should default to US keyboard layout');
  assert.match(app, /RDP Tastatur/, 'host editor must show keyboard layout selector');
  assert.match(app, /<option value="de-DE">Deutsch \/ DE<\/option>/, 'German RDP keyboard option is required');
  assert.match(app, /rdpKeyboardLayout:rdpKeyboardLayoutOf\(draft\)/, 'saved RDP hosts must persist selected keyboard layout');
});
