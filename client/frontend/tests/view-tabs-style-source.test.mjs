import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');

test('workspace view buttons live in the toolbar action slot', () => {
  assert.match(app, /<header className="toolbar">[\s\S]*?<div><b>\{selHost\?\.name[\s\S]*?<div className="viewTabs" role="tablist">[\s\S]*?data-view="terminal"[\s\S]*?data-view="vault"[\s\S]*?<\/div>\s*<\/header>/, 'view tabs must sit inside the toolbar beside the host title');
  assert.doesNotMatch(app, /<\/header>\s*<div className="viewTabs" role="tablist">/, 'view tabs must not render as their own row below the toolbar');
});

test('workspace view buttons use the old right-side action layout', () => {
  assert.match(css, /\.toolbar\{[^}]*flex-wrap:nowrap/, 'toolbar must keep host title and view tabs on the same row');
  assert.match(css, /\.toolbar\{[^}]*background:transparent/, 'toolbar must not paint a dark strip behind workspace tabs');
  assert.match(css, /\.toolbar\{[^}]*border-bottom:0/, 'toolbar separator must not appear as a dark tab strip');
  assert.match(css, /\.toolbar\{[^}]*box-shadow:none/, 'toolbar must not shadow a strip behind workspace tabs');
  assert.match(css, /\.toolbar\{[^}]*min-height:0/, 'toolbar must shrink to content instead of leaving a dark band');
  assert.match(css, /\.toolbar>div:first-child\{[^}]*flex:0 1 280px/, 'host title must leave room for tabs in the old action area');
  assert.match(css, /\.viewTabs\{[^}]*justify-content:flex-end/, 'view tabs must align to the right action area');
  assert.match(css, /\.viewTabs\{[^}]*flex:1 1 auto/, 'view tabs must use the remaining toolbar action area');
  assert.match(css, /\.viewTabs\{[^}]*flex-wrap:nowrap/, 'all four workspace tabs must stay on one toolbar row');
  assert.match(css, /\.viewTabs button\{[^}]*max-width:124px/, 'workspace tab buttons must be narrow enough to fit Terminal/SFTP/RDP/Vault on one row');
  assert.match(css, /\.viewTabs\{[^}]*background:transparent/, 'view tabs must not create a separate full-width strip');
  assert.match(css, /\.viewTabs\{[^}]*border-bottom:0/, 'view tabs must not draw a strip separator');
  assert.doesNotMatch(css, /\.viewTabs\{[^}]*padding:3px 14px 13px/, 'view tabs must not use the old separate-row padding');
});
