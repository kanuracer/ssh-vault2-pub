import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const cssBlock = (selector) => {
  const start = css.indexOf(selector + '{');
  assert.notEqual(start, -1, `${selector} block missing`);
  const end = css.indexOf('}', start);
  return css.slice(start, end + 1);
};

test('host menu footer uses one-row bounded pill/card styling', () => {
  const footer = cssBlock('.sidebarFooter');
  const controls = cssBlock('.sidebarFooter .settingsGear,\n.sidebarFooter .versionMeta,\n.sidebarFooter .syncFooterButton');
  assert.match(app, /className="sidebarFooter"/);
  assert.match(app, /className="settingsGear"/);
  assert.match(app, /className="footerSyncCluster"/, 'footer needs a dedicated tight version/sync cluster');
  assert.match(app, /className="versionMeta"/);
  assert.match(app, /className=\{`syncFooterButton \$\{syncFooterState\}`\}/, 'sync indicator must be separate from version button');
  assert.match(footer, /display:flex;/, 'footer must be a normal one-row button bar, not a grid with optical dead space');
  assert.match(footer, /gap:4px;/, 'settings to version cluster needs modest button spacing');
  assert.match(footer, /width:100%;/);
  assert.match(footer, /max-width:100%;/);
  assert.match(footer, /margin-left:0;/, 'footer row must be centered as a single control group');
  assert.match(footer, /margin-right:0;/);
  assert.match(footer, /overflow:hidden;/, 'footer must not leak controls outside the sidebar');
  assert.match(footer, /transform:translateX\(6px\);/, 'footer row compensates asymmetric sidebar padding to center the group');
  assert.doesNotMatch(footer, /flex-direction:column/, 'footer must not stack settings/version/sync');
  assert.match(controls, /height:42px!important;/, 'all footer controls must keep stable touch height');
  assert.match(cssBlock('.footerSyncCluster'), /gap:6px!important/, 'version and sync must be separate readable controls');
  assert.match(cssBlock('.footerSyncCluster .versionMeta'), /width:145px!important/, 'version pill must match the settings button width');
  assert.match(cssBlock('.footerSyncCluster .versionMeta'), /flex:0 0 145px!important/, 'version pill must stay exactly as wide as settings');
  assert.match(cssBlock('.footerSyncCluster .versionMeta'), /padding-right:6px!important/, 'version pill uses symmetric compact padding for centered content');
  assert.match(cssBlock('.versionMeta'), /justify-content:center/, 'version pill content must be visually centered');
  assert.match(cssBlock('.versionMeta>span:first-child'), /overflow:visible/, 'version text must remain fully readable');
  assert.match(css, /\.sidebarFooter \.syncFooterButton\{width:40px!important;min-width:40px!important;max-width:40px!important;flex:0 0 40px!important;justify-content:center!important;padding-left:0!important;overflow:hidden!important;margin-left:0!important\}/, 'footer sync button must stay a separate normal 40px control');
  assert.match(app, /<span className="syncLockIcon" aria-hidden="true"><\/span>/, 'locked sync button must use CSS icon, not emoji font');
  assert.match(css, /syncLockIcon\{[^}]*width:22px[^}]*height:22px/s, 'CSS lock icon must use a 22px wrapper for optical centering');
  assert.match(css, /syncLockIcon::before\{[^}]*box-sizing:border-box[^}]*left:5px[^}]*top:3px[^}]*border:2px solid currentColor/s, 'CSS lock shackle must render centered on Windows');
  assert.match(css, /syncLockIcon::after\{[^}]*box-sizing:border-box[^}]*left:4px[^}]*top:10px[^}]*border:2px solid currentColor/s, 'CSS lock body must render centered on Windows');
  assert.match(css, /syncCompositeIcon\{[^}]*transform:none/, 'sync icon wrapper stays centered inside the normal 40px button');
  assert.match(app, /<circle className="syncGlyphRing" cx="20" cy="20" r="13"\/>/, 'sync glyph must use a true SVG circle, not an oval-looking arc');
  assert.match(css, /\.syncGlyphRing,\.syncGlyphHead\{[^}]*stroke:currentColor[^}]*stroke-width:3\.2/s, 'sync glyph must use a true circular ring with arrowheads');
  assert.doesNotMatch(css, /syncArrow/, 'old single reload-style syncArrow CSS must be removed');
  assert.match(app, /<circle className="syncStatusDot" cx="20" cy="20" r="4\.8"\/>/, 'sync status dot must sit in the middle of the circle');
  assert.match(css, /syncStatusDot\{[^}]*fill:#ef4444[^}]*stroke:#071020[^}]*stroke-width:2/s, 'sync status dot must be rendered inside the SVG center');
  assert.match(css, /syncFooterButton\.ok \.syncStatusDot\{fill:#24ff78/, 'ok sync status dot must be green');
  assert.match(css, /syncFooterButton\.error \.syncStatusDot\{fill:#ff3b3b/, 'error sync status dot must be red');
  assert.match(cssBlock('.updateBadge'), /max-width:34px/, 'update badge must be compact inside the version card');
  assert.match(cssBlock('.updateBadge'), /margin-left:0/, 'update badge must not auto-push inside the version pill');
  assert.match(cssBlock('.updateBadge'), /padding:3px 6px/, 'short status badge must fit inside compact equal-width version card');
  assert.match(css, /\.sidebarFooter \.syncFooterButton\{width:40px!important;min-width:40px!important;max-width:40px!important;flex:0 0 40px!important;justify-content:center!important;padding-left:0!important;overflow:hidden!important;margin-left:0!important\}/, 'footer sync button must keep its 40px width without overlapping the version pill');
  assert.match(css, /@media\(max-height:820px\)\{[\s\S]*\.sidebar\{padding-bottom:18px!important\}/, 'compact Windows/RDP work areas need modest bottom safe space');
  assert.match(app, /updateStatus==='available' \? 'neu'/, 'sidebar update badge must use a short label');
  assert.match(app, /updateStatus==='checking' \? '↻' : updateStatus==='available' \? 'neu' : updateStatus==='error' \? '!' : '✓'/, 'sidebar footer badge must use only short labels');
});

test('tag filter menu action buttons are centered inside the popover', () => {
  const actions = cssBlock('.tagFilterActions');
  const actionButton = cssBlock('.tagFilterActions button');
  assert.match(cssBlock('.tagFilterMenu'), /width:min\(338px,calc\(100vw - 32px\)\)/, 'filter menu must be wide enough for centered German action labels');
  assert.match(cssBlock('.tagFilterMenu'), /padding:16px 28px/, 'filter menu needs real right/left breathing room');
  assert.match(actions, /display:grid/, 'filter menu actions should use exact centered columns');
  assert.match(actions, /grid-template-columns:132px 132px/, 'filter action columns must be equal fixed widths');
  assert.match(actions, /justify-content:center/, 'filter menu actions must be visually centered');
  assert.match(actions, /gap:16px/, 'filter actions need enough internal gap while preserving right padding');
  assert.match(actions, /padding:0/, 'filter actions must not add asymmetric row padding');
  assert.match(actions, /transform:translateX\(-20px\)/, 'Windows visual QA needs the action row compensated 20px left');
  assert.match(actionButton, /flex:0 0 132px/, 'filter action buttons should have a bounded centered width');
  assert.match(actionButton, /width:132px/, 'filter action buttons should not stretch to the popover edges');
  assert.match(actionButton, /max-width:132px/, 'filter action buttons should stay symmetric in the row');
  assert.match(actionButton, /padding:8px 6px/, 'German filter action labels must fit with stronger right breathing room');
  assert.match(actionButton, /font-size:12px/, 'filter action labels use compact readable text to preserve right padding');
});

test('collapsed settings gear stays one compact bottom button, not a stretched rail hitbox', () => {
  assert.match(app, /className="settingsGear compact"/, 'collapsed sidebar must render the compact gear class');
  assert.match(cssBlock('.settingsGear'), /flex:0 0 145px!important/, 'expanded settings button should keep the same fixed width as the version button');
  assert.match(cssBlock('.sidebar.collapsed .collapsedRail .settingsGear.compact'), /flex:0 0 42px!important/, 'collapsed gear must stay fixed size');
  assert.match(cssBlock('.settingsGear.compact'), /border-radius:14px!important/, 'collapsed gear must keep rounded-rectangle radius');
  assert.doesNotMatch(cssBlock('.settingsGear.compact'), /border-radius:999px!important;/, 'collapsed gear must not become circular');
});
