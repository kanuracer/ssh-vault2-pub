import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const renderer = readFileSync(new URL('../src/rdpWebglRenderer.ts', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/style.css', import.meta.url), 'utf8');

test('RDP connect uses current viewer size instead of fixed host defaults', () => {
  assert.match(source, /function\s+rdpViewerSize\s*\(/, 'missing rdpViewerSize helper');
  assert.match(source, /API\.ConnectRDP\(hostID,\s*size\.width,\s*size\.height\)/, 'ConnectRDP must use measured viewer size');
  assert.doesNotMatch(source, /API\.ConnectRDP\(hostID,\s*Number\(\(h as any\)\?\.rdpWidth/, 'ConnectRDP still uses stored fixed RDP width');
});

test('RDP primary open stays inside ssh-vault2 and does not launch external clients', () => {
  assert.match(source, /async function\s+connectRDP\s*\(hostID = selected\)/, 'missing in-app RDP open helper');
  assert.match(source, /API\.ConnectRDP\(hostID,\s*size\.width,\s*size\.height\)/, 'RDP öffnen must call the in-app RDP backend');
  assert.doesNotMatch(source, /OpenNativeRDP|openNativeRDP|connectEmbeddedRDP|RDP eingebettet|Eingebettetes RDP|Eingebettete RDP|eingebetteten RDP|RDP läuft eingebettet/, 'external/native RDP launcher and fallback wording must not remain in frontend');
  assert.doesNotMatch(source, /<div className="actions"><button disabled=\{!selected\} onClick=\{\(\)=>beginEditHost\(\)\}>Host bearbeiten<\/button><button className="primary" disabled=\{connectingSSH\|\|!selected\} onClick=\{\(\)=>connectSSH\(\)\}>/, 'host header action buttons must stay removed');
  assert.match(source, /onDoubleClick=\{\(\) => hostProtocol\(h\) === 'rdp' \? connectRDPHost\(h\.id\)/, 'RDP host double-click should open in-app RDP');
  assert.match(source, /<div className="empty rdpEmpty"><span>Host wählen und RDP öffnen\.<\/span><\/div>/, 'empty RDP workspace must keep only guidance text');
  assert.doesNotMatch(source, /<div className="empty rdpEmpty"><span>Host wählen und RDP öffnen\.<\/span><button/, 'empty RDP workspace must not expose a duplicate RDP öffnen button');
});

test('RDP Smart Autoscale exposes scaling modes and persists the selected mode', () => {
  assert.match(source, /type\s+RDPScaleMode\s*=\s*'smart'\|'sharp'\|'fit'\|'original'/, 'missing RDPScaleMode union');
  assert.doesNotMatch(source, /localStorage\.getItem\('sshv\.rdpScaleMode'\)/, 'RDP scale mode must be stored on the host, not globally in localStorage');
  assert.match(source, /const rdpScaleModeOf = \(host\?: HostConfig\)/, 'missing per-host RDP scale helper');
  assert.match(source, /rdpScaleModeOf\(selHost\)/, 'RDP toolbar must read selected host scale mode');
  assert.match(source, /rdpScaleMode:\s*e\.target\.value as RDPScaleMode/, 'Host editor must save RDP scale mode on the host');
  assert.match(source, />Smart Auto</, 'Smart Auto option missing');
  assert.match(source, />Fit \/ Autoscale</, 'Fit / Autoscale option missing');
  assert.match(source, />Originalgröße</, 'Original size option missing');
});

test('RDP active session reconnects only for sharp/smart modes, while fit mode only scales locally', () => {
  assert.match(source, /function\s+scheduleRDPResizeReconnect\s*\(/, 'missing RDP resize reconnect scheduler');
  assert.match(source, /const scaleMode = rdpScaleModeOf\(host\)/, 'resize scheduler must read host-specific RDP scale mode');
  assert.match(source, /if \(scaleMode === 'fit' \|\| scaleMode === 'original'\) return;/, 'fit/original must not reconnect');
  assert.match(source, /window\.addEventListener\('resize',\s*onResize\)/, 'window resize handler missing');
  assert.match(source, /ResizeObserver\(\(\)\s*=>\s*scheduleRDPResizeReconnect/, 'RDP pane ResizeObserver missing');
});

test('RDP canvas has separate CSS classes for smart, fit, sharp and original modes', () => {
  assert.match(source, /className=\{`rdpWorkspace rdpScale-\$\{rdpScaleModeOf\(selHost\)\}`\}/, 'workspace should expose host-specific scale mode class');
  assert.doesNotMatch(source, /className="rdpToolbar"/, 'RDP scaling controls must not be rendered in the RDP viewer');
  assert.doesNotMatch(css, /\.rdpToolbar/, 'RDP scaling toolbar CSS must not remain in the viewer');
  assert.match(source, /className="editorLabel compactSelect">RDP Skalierung/, 'RDP scaling should remain available in the host editor');
  assert.match(css, /\.rdpScale-smart \.rdpCanvasWrap canvas\{[^}]*width:100%/, 'smart mode should autoscale canvas');
  assert.match(css, /\.rdpScale-fit \.rdpCanvasWrap canvas\{[^}]*width:100%/, 'fit mode should autoscale canvas');
  assert.match(css, /\.rdpScale-sharp \.rdpCanvasWrap canvas\{[^}]*width:100%/, 'sharp mode should fill viewer after reconnect');
  assert.match(css, /\.rdpScale-original \.rdpCanvasWrap\{[^}]*overflow:auto/, 'original mode should scroll');
  assert.match(css, /\.rdpScale-original \.rdpCanvasWrap canvas\{[^}]*width:auto/, 'original mode should not stretch canvas');
});

test('RDP canvas intrinsic size follows binary render endpoint/frame dimensions and does not force 1280x800', () => {
  assert.doesNotMatch(source, /Math\.max\(canvas\.width \|\| 0, frame\.left \+ frame\.width, 1280\)/, 'canvas width must not force 1280 minimum');
  assert.doesNotMatch(source, /Math\.max\(canvas\.height \|\| 0, frame\.top \+ frame\.height, 800\)/, 'canvas height must not force 800 minimum');
  assert.doesNotMatch(source, /if \(!el\.width\) el\.width = 1280;/, 'new RDP canvas must not start at fixed 1280 width');
  assert.doesNotMatch(source, /if \(!el\.height\) el\.height = 800;/, 'new RDP canvas must not start at fixed 800 height');
  assert.match(renderer, /this\.canvas\.width = this\.surfaceWidth/, 'WebGL renderer should size canvas from binary frame surface width');
  assert.match(renderer, /this\.canvas\.height = this\.surfaceHeight/, 'WebGL renderer should size canvas from binary frame surface height');
  assert.match(renderer, /gl\.texImage2D\(gl\.TEXTURE_2D, 0, gl\.RGBA, this\.surfaceWidth, this\.surfaceHeight/, 'WebGL texture should allocate to backend surface size');
});

test('RDP open replaces an existing session for the same host instead of stacking duplicate canvases', () => {
  assert.match(source, /const existing = rdpSessions\.find\(x => x\.hostId === hostID\)/, 'connectRDP should find existing session for host');
  assert.match(source, /await closeRDP\(existing\.id\)/, 'connectRDP should close existing session before opening another');
});

test('RDP double-click is guarded synchronously per host before React state updates', () => {
  assert.match(source, /const rdpOpeningHosts = useRef<Set<string>>\(new Set\(\)\)/, 'missing synchronous per-host RDP open guard');
  assert.match(source, /if \(rdpOpeningHosts\.current\.has\(hostID\)\) return;/, 'connectRDP must reject duplicate in-flight opens for same host');
  assert.match(source, /rdpOpeningHosts\.current\.add\(hostID\)/, 'connectRDP must lock host before async API call');
  assert.match(source, /rdpOpeningHosts\.current\.delete\(hostID\)/, 'connectRDP must unlock host in finally');
});

test('RDP status events only update known sessions and must not resurrect closed stale sessions', () => {
  assert.doesNotMatch(source, /offRdpStatus[\s\S]*\? prev\.map\(x => x\.id === st\.id \? st : x\) : \[\.\.\.prev, st\]/, 'rdp status handler must not append unknown/stale sessions');
  assert.match(source, /offRdpStatus[\s\S]*setRdpSessions\(prev => prev\.map\(x => x\.id === st\.id \? st : x\)\)/, 'rdp status handler should only update already-known sessions');
});

test('RDP closed or missing backend session removes stale canvas state', () => {
  assert.match(source, /dropRDPClientSession\(st\.id\)/, 'closed RDP status should drop local stale session');
  assert.match(source, /function\s+dropRDPClientSession\s*\(id: string\)/, 'missing local stale RDP drop helper');
  assert.match(source, /closeRDPRenderStream\(id\)/, 'dropping an RDP session should close its binary render stream');
  assert.match(source, /delete rdpRenderers\.current\[id\]/, 'dropping an RDP session should clear its WebGL renderer');
  assert.match(source, /RDP-Session nicht gefunden[\s\S]*dropRDPClientSession\(id\)/, 'mouse/key backend-missing errors should remove stale RDP session');
});

test('RDP WebGL renderer preserves top-left RDP dirty-rect orientation', () => {
  assert.doesNotMatch(renderer, /surfaceHeight\s*-\s*frame\.top\s*-\s*frame\.height/, 'texSubImage2D y offset must not flip top-origin RDP coordinates');
  assert.match(renderer, /const y = Math\.max\(0,\s*frame\.top\)/, 'WebGL upload should use top-origin frame.top directly');
  assert.match(renderer, /-1,\s*-1,\s*0,\s*1[\s\S]*1,\s*-1,\s*1,\s*1[\s\S]*-1,\s*1,\s*0,\s*0[\s\S]*1,\s*1,\s*1,\s*0/, 'quad UVs should display texture row zero at the visual top');
});

test('RDP render path uses binary WebSocket plus WebGL instead of Wails/base64 canvas copies', () => {
  assert.match(source, /import \{ RDPWebGLRenderer, parseRDPBinaryFrame(?:, type RDPBinaryFrame)? \} from '\.\/rdpWebglRenderer'/, 'frontend must import WebGL RDP renderer');
  assert.match(source, /const rdpRenderers = useRef<Record<string, RDPWebGLRenderer>>/, 'missing per-session WebGL renderer store');
  assert.match(source, /const rdpRenderStreams = useRef<Record<string, WebSocket>>/, 'missing per-session binary WebSocket store');
  assert.match(source, /API\.RDPRenderEndpoint\(id\)/, 'frontend must request binary render endpoint');
  assert.match(source, /new WebSocket\(endpoint\.url\)/, 'RDP render stream should stay raw-only until a real low-CPU codec path exists');
  assert.doesNotMatch(source, /formats=raw,jpeg|formats=.*jpeg/, 'RDP render stream must not opt in to JPEG after the 1.2.53 2fps regression');
  assert.match(source, /ws\.binaryType = 'arraybuffer'/, 'RDP render WebSocket must receive binary frames');
  assert.match(source, /const isFullRDPFrame = \(frame: RDPBinaryFrame\)/, 'missing full-frame detector for render queue coalescing');
  assert.match(source, /rdpRenderStreams\.current\[id\] !== ws/, 'stale WebSocket messages should be ignored');
  assert.match(source, /if \(isFullRDPFrame\(frame\)\) \{[\s\S]*rdpRenderFrameQueues\.current\[id\] = \[frame\]/, 'full snapshots should replace stale queued frames');
  assert.match(source, /const lastFullRDPFrameIndex = \(frames: RDPBinaryFrame\[\]\)/, 'missing full-frame queue scan helper compatible with current TS target');
  assert.match(source, /const lastFull = lastFullRDPFrameIndex\(frames\)/, 'RAF should discard frames older than latest full snapshot');
  assert.match(source, /renderer\.presentBatch\(renderFrames\)/, 'RDP render should upload queued frames as a batch and draw once per RAF');
  assert.match(renderer, /presentBatch\(frames: RDPBinaryFrame\[\]\)/, 'WebGL renderer should expose batch presentation');
  assert.doesNotMatch(renderer, /createImageBitmap|image\/jpeg|BlobPart|private batchSerial/, 'WebGL render path must stay synchronous raw RGBA after the JPEG 2fps regression');
  assert.match(renderer, /presentBatch\(frames: RDPBinaryFrame\[\]\) \{\s*if \(!frames\.length\) return;\s*for \(const frame of frames\) this\.upload\(frame\);\s*this\.draw\(\);/s, 'visible canvas should upload raw frames synchronously and draw once per RAF');
  assert.doesNotMatch(source, /q\.push\(parseRDPBinaryFrame\(ev\.data as ArrayBuffer\)\)/, 'binary frames must not grow an unbounded stale queue');
  assert.doesNotMatch(source, /for \(const frame of frames\) renderer\.present\(frame\)/, 'RAF must not draw every queued frame');
  assert.doesNotMatch(source, /RDPFramePayload|rgbaBase64|unzlibSync|decodeRDPFrameRGBA|new ImageData|putImageData|rdp:frames|rdp:frame/, 'legacy Wails/base64/2D canvas render path must not remain');
});

test('RDP keyboard and context-menu paste use cliprdr state instead of texttyping-only paste', () => {
  assert.match(source, /function\s+rdpPaste\s*\(id: string, ev: ReactClipboardEvent<HTMLCanvasElement>\)/, 'missing RDP paste event helper');
  assert.match(source, /async function\s+prepareRDPClipboardText\s*\(id: string, text\?: string\)/, 'missing RDP clipboard staging helper');
  assert.match(source, /API\.RDPClipboardText\(\)/, 'Ctrl+V must use Wails backend clipboard fallback because WebView navigator.clipboard can be denied');
  assert.match(source, /navigator\.clipboard\.readText\(\)/, 'Ctrl+V should still try browser clipboard first');
  assert.match(source, /API\.RDPStageClipboardText\(id, payload\)/, 'RDP text paste must stage clipboard through backend cliprdr');
  assert.match(source, /if \(action === 'rightdown'\) void prepareRDPClipboardText\(id\)/, 'right-click must refresh cliprdr before remote context-menu paste');
  assert.match(source, /async function\s+sendRDPRemotePasteShortcut\s*\(id: string/, 'missing remote paste shortcut helper');
  assert.match(source, /await API\.RDPKey\(id, 'ControlLeft', true\);[\s\S]*await API\.RDPKey\(id, keyCode, true\);[\s\S]*await API\.RDPKey\(id, keyCode, false\);[\s\S]*await API\.RDPKey\(id, 'ControlLeft', false\)/, 'explicit paste helper must send remote Ctrl+V after cliprdr staging');
  assert.doesNotMatch(source, /API\.RDPTypeText\(id, payload\)/, 'Ctrl+V must not be only Unicode texttyping; cliprdr must be the primary paste path');
  assert.match(source, /suppressed\.add\(ev\.code\)/, 'Ctrl+V must suppress the later V keyup because V down is handled manually');
  assert.match(source, /ev\.preventDefault\(\); ev\.stopPropagation\(\);[\s\S]*ev\.key\.toLowerCase\(\) === 'v'/, 'RDP Ctrl+V must stay inside canvas');
  assert.match(source, /onPaste=\{e=>rdpPaste\(s\.id,e\)\}/, 'RDP canvas must handle paste events');
  assert.match(source, /void API\.RDPKey\(id, ev\.code, down\)/, 'normal keys must still use RDPKey');
  assert.doesNotMatch(source, /rdpKey[\s\S]{0,500}CloseRDP|rdpKey[\s\S]{0,500}closeRDP/, 'RDP key path must not close tabs');
});



test('RDP file clipboard stages browser paste/drop files through backend cliprdr', () => {
  assert.match(source, /function\s+rdpFileDrop\s*\(id: string/, 'missing RDP file drop handler');
  assert.match(source, /API\.RDPStageClipboardFiles\(id, payload\)/, 'file paste/drop must stage files in backend for cliprdr');
  assert.match(source, /if \(await stageRDPClipboardFiles\(id, files\)\) await sendRDPRemotePasteShortcut\(id\)/, 'file paste/drop must trigger remote Ctrl+V after staging files');
  assert.match(source, /onDrop=\{e=>rdpFileDrop\(s\.id,e\)\}/, 'RDP canvas must accept file drops');
  assert.match(source, /clipboardData\.files/, 'RDP paste should accept clipboard files');
});

test('RDP folder drop recursively stages relative paths instead of flat FileList names', () => {
  assert.match(source, /async function\s+collectRDPClipboardFiles\s*\(dt: DataTransfer\)/, 'missing RDP recursive drop collector');
  assert.match(source, /webkitGetAsEntry/, 'RDP folder drop must recurse browser directory entries');
  assert.match(source, /relPath:\s*rel \|\| file\.name/, 'RDP folder drop must preserve collected relative paths');
  assert.match(source, /stageRDPClipboardFiles\(id, files\)/, 'RDP drop must stage collected relative file items');
  assert.match(source, /name:\s*f\.relPath \|\| f\.file\.name \|\| 'clipboard-file'/, 'RDP staging payload must use relative path, not only file.name');
  assert.doesNotMatch(source, /const files = ev\.dataTransfer\?\.files;[\s\S]{0,160}stageRDPClipboardFiles\(id, files\)/, 'RDP drop must not rely only on flat dataTransfer.files');
});

test('RDP rendering avoids Wails frame events and mousemove is throttled', () => {
  assert.doesNotMatch(source, /const rdpPaintFrames = useRef/, 'RDP dirty frames should not queue full-canvas repaint handles');
  assert.doesNotMatch(source, /paintRDPVisibleRect|putImageData|new ImageData/, 'RDP rendering should use WebGL binary frames, not 2D canvas dirty-rect copies');
  assert.match(source, /rdpRenderFrameQueues = useRef<Record<string, RDPBinaryFrame\[\]>>/, 'RDP render should queue dirty frames until RAF');
  assert.match(source, /renderer\.presentBatch\(renderFrames\)/, 'visible canvas should batch queued WebGL uploads and draw once per RAF');
  assert.match(source, /const rdpMouseMoves = useRef<Record<string, \{x:number; y:number; frame\?:number; timer\?:number; lastSent\?:number\}>>\(\{\}\)/, 'missing throttled RDP mousemove state');
  assert.match(source, /function\s+rdpMouseMove\s*\(id: string/, 'missing RDP mousemove helper');
  assert.match(source, /Math\.max\(0, 16 - \(now - \(rec\.lastSent \|\| 0\)\)\)/, 'mousemove should be limited to about 60fps for low input lag');
  assert.match(source, /API\.RDPMouse\(id, 'move', rec\.x, rec\.y, 0\)/, 'mousemove should send latest point once per frame');
  assert.match(source, /onWheel=\{e=>\{e\.preventDefault\(\); rdpMouse\(s\.id,'wheel',e, e\.deltaY < 0 \? 120 : -120\)\}\}/, 'canvas wheel must forward signed wheel delta to backend');
});
