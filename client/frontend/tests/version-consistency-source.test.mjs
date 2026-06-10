import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const root = new URL('../../', import.meta.url);
const appservice = readFileSync(new URL('appservice.go', root), 'utf8');
const server = readFileSync(new URL('../server/server.mjs', root), 'utf8');
const pkg = JSON.parse(readFileSync(new URL('frontend/package.json', root), 'utf8'));
const config = readFileSync(new URL('build/config.yml', root), 'utf8');
const winInfo = readFileSync(new URL('build/windows/info.json', root), 'utf8');
const darwinInfo = readFileSync(new URL('build/darwin/Info.plist', root), 'utf8');

const re = /\b\d+\.\d+\.\d+\b/g;
const versionsIn = (text) => [...new Set((text.match(re) || []).filter(v => v.startsWith('1.')))].sort();

test('desktop app version sources stay in sync', () => {
  const appVersion = appservice.match(/const appVersion = "([^"]+)"/)?.[1];
  const serverVersion = server.match(/const serverVersion = '([^']+)'/)?.[1];
  const configVersion = config.match(/info:\n(?:.*\n)*?\s+version:\s*['"]?([0-9.]+)/)?.[1];
  const windowsProductVersion = winInfo.match(/"ProductVersion"\s*:\s*"([0-9.]+)"/)?.[1];
  const darwinBundleVersion = darwinInfo.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([0-9.]+)<\/string>/)?.[1];

  assert.ok(appVersion, 'appservice.go must define appVersion');
  assert.equal(appVersion, pkg.version, 'frontend package version must match binary appVersion');
  assert.equal(appVersion, serverVersion, 'download server version must match binary appVersion');
  assert.equal(appVersion, configVersion, 'Wails build config version must match binary appVersion');
  assert.equal(appVersion, windowsProductVersion, 'Windows installer metadata must match binary appVersion');
  assert.equal(appVersion, darwinBundleVersion, 'macOS bundle metadata must match binary appVersion');
});

test('no stale intermediate version remains in binary/app installer version files', () => {
  const files = { appservice, config, winInfo, darwinInfo };
  for (const [name, text] of Object.entries(files)) {
    assert.deepEqual(versionsIn(text), [pkg.version], `${name} should contain only current release version ${pkg.version}`);
  }
});
