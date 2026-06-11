import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const app = fs.readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

test('terminal right click opens first-click paste context menu', () => {
  assert.match(app, /type TerminalContextMenu\s*=\s*\{x:number;y:number;sessionId:string\}/, 'terminal context menu state type is required');
  assert.match(app, /const \[termCtx, setTermCtx\] = useState<TerminalContextMenu \| null>\(null\)/, 'terminal context menu state is required');
  assert.match(app, /function openTerminalMenu\(e: MouseEvent<HTMLDivElement> \| globalThis\.MouseEvent, sessionId: string\)/, 'terminal right-click handler must support React and native events');
  assert.match(app, /e\.preventDefault\(\);\s*e\.stopPropagation\(\);[\s\S]*setTermCtx\(\{x:Math\.max/, 'terminal right-click must suppress WebView native menu and open custom menu immediately');
  assert.match(app, /const contextMenuHandler = \(e: globalThis\.MouseEvent\) => openTerminalMenu\(e, id\);/, 'terminal must register a native capture-phase contextmenu handler before xterm can swallow the event');
  assert.match(app, /el\.addEventListener\('contextmenu', contextMenuHandler, \{capture:true\}\)/, 'terminal context menu must listen in capture phase on the terminal container');
  assert.match(app, /contextMenuHandler\?: \(e: globalThis\.MouseEvent\) => void/, 'terminal record must keep native contextmenu handler for cleanup');
  assert.match(app, /bracketedPaste\?: boolean/, 'terminal record must track remote bracketed paste mode');
  assert.match(app, /pasteHandler\?: \(e: globalThis\.ClipboardEvent\) => void/, 'terminal record must keep native paste handler for cleanup');
  assert.match(app, /keyDownHandler\?: \(e: globalThis\.KeyboardEvent\) => void/, 'terminal record must keep native Ctrl+V keydown handler for cleanup');
  assert.match(app, /existing\.contextMenuHandler[\s\S]*removeEventListener\('contextmenu', existing\.contextMenuHandler, \{capture:true\}\)/, 'remount cleanup must remove the native capture listener');
  assert.match(app, /async function pasteTerminalClipboard\(sessionId: string\)/, 'terminal paste action is required');
  assert.match(app, /navigator\.clipboard\.readText\(\)/, 'paste action should read OS clipboard text');
  assert.match(app, /async function writeSSHPasteText\(sessionId: string, text: string\)/, 'paste action should use SSH paste helper');
  assert.match(app, /normalizeTerminalPasteText\(text\)/, 'paste helper must normalize CRLF code blocks');
  assert.match(app, /rec\?\.bracketedPaste[\s\S]*\\x1b\[200~/, 'multiline paste should use bracketed paste when the remote shell enables it');
  assert.match(app, /normalized\.replace\(\/\\n\/g, '\\r'\)/, 'multiline fallback should send terminal CR line endings');
  assert.match(app, /el\.addEventListener\('paste', pasteHandler, \{capture:true\}\)/, 'native paste must be intercepted before xterm bulk-pastes unsafely');
  assert.match(app, /el\.addEventListener\('keydown', keyDownHandler, \{capture:true\}\)/, 'Ctrl+V keydown must be intercepted before xterm/WebView can drop it');
  assert.match(app, /if \(isTerminalPasteShortcut\(e\)\)/, 'terminal keydown handler must detect Ctrl/Cmd+V paste shortcut');
  assert.match(app, /await writeSSHPasteText\(sessionId, text\)/, 'context-menu paste must route through paste helper');
  assert.match(app, /async function copyTerminalSelection\(sessionId: string\)/, 'terminal copy action is required');
  assert.match(app, /terms\.current\[sessionId\]\?\.term\.getSelection\(\)/, 'copy action should read the active xterm selection');
  assert.match(app, /navigator\.clipboard\.writeText\(selection\)/, 'copy action should write selected terminal text to OS clipboard');
  assert.match(app, /onContextMenu=\{e=>openTerminalMenu\(e,s\.id\)\}/, 'terminal pane must route contextmenu to the custom menu');
  assert.match(app, /termCtx && <div className="contextMenu terminalContextMenu"/, 'terminal paste menu must render with normal context-menu styling');
  assert.match(app, />Kopieren<\/button>/, 'menu must expose Kopieren on first right-click');
  assert.match(app, />Einfügen<\/button>/, 'menu must expose Einfügen on first right-click');
});
