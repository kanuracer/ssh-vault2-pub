import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');
const server = readFileSync(new URL('../../../server/server.mjs', import.meta.url), 'utf8');

test('updates card renders selected release changelog', () => {
  assert.match(app, /const selectedChangelog = \(\) =>/, 'selected version changelog must be normalized in the renderer');
  assert.match(app, /className="changelogBox"/, 'updates card must render a dedicated changelog box');
  assert.match(app, /Changelog \{selectedVersion\}/, 'changelog must be scoped to selected version');
  assert.doesNotMatch(app, /Changelog lesen/, 'settings page must not render extra install instructions');
  assert.match(css, /\.changelogBox\{[\s\S]*max-width:760px[\s\S]*border:1px solid #2f5d8f/, 'changelog box must align with package/update controls');
});

test('current update state is reduced to one exact sentence', () => {
  assert.match(app, />Du bist auf dem neusten Stand\.</, 'current state must keep only the requested sentence');
  assert.doesNotMatch(app, /Keine neuere kompatible Version verfügbar\./, 'redundant no-newer-version text must be removed');
  assert.doesNotMatch(app, /Nur neuere Versionen: prüfen/, 'long update workflow hint must be removed');
  assert.doesNotMatch(app, /Du bist auf dem neuesten Stand\. Nur neuere Versionen werden angeboten\./, 'old verbose status must be removed');
});

test('release API lists only app artifacts, not release metadata files', () => {
  assert.match(server, /function isReleaseAssetName\(f\)/, 'server must centralize release asset filename filtering');
  assert.match(server, /\^ssh-vault2-\\d\+\\\.\\d\+\\\.\\d\+-/, 'release assets must be versioned ssh-vault2 files only');
  assert.match(server, /names\.filter\(isReleaseAssetName\)/, 'download listing must use the strict artifact filter');
  assert.doesNotMatch(server, /f !== 'SHA256SUMS\.txt' && f !== 'SHA256SUMS\.txt\.sig'/, 'metadata denylist is incomplete and must not drive release listing');
});
