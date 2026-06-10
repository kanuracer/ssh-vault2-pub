import { useEffect, useRef, useState } from 'react';
import type { DragEvent, MouseEvent, KeyboardEvent as ReactKeyboardEvent, ClipboardEvent as ReactClipboardEvent } from 'react';
import { Events } from '@wailsio/runtime';
import { RDPWebGLRenderer, parseRDPBinaryFrame, type RDPBinaryFrame } from './rdpWebglRenderer';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import * as API from '../bindings/github.com/example-org/ssh-vault2/appservice';
import type { AppInfo, FileEntry, HostConfig, LocalVaultStatus, ReleaseAsset, ReleaseIndex, ReleaseVersion, SessionState, SyncAccountRequest, SyncConfig, VaultCredential } from '../bindings/github.com/example-org/ssh-vault2/models';
import './style.css';

const defaultSyncServer = 'https://ssh-vault.example.org';
const normalizeEndpoint = (v = '') => {
  const endpoint = v.trim().replace(/\/$/, '');
  return (!endpoint || endpoint === 'https://ssh-vault.example.org' || endpoint === 'https://192.0.2.117:18080') ? defaultSyncServer : endpoint;
};
const validSyncEndpoint = (v = '') => {
  try {
    const u = new URL(normalizeEndpoint(v));
    return u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost','127.0.0.1','::1'].includes(u.hostname));
  } catch { return false; }
};
const emptyHost: HostConfig = { id: '', protocol:'ssh', name: '', address: '', port: 22, username: '', authMode: 'key', keyPath: '', password: '', vaultId: '', tags: [], rdpEnabled:false, rdpPort:3389, rdpUsername:'', rdpPassword:'', rdpDomain:'', rdpWidth:1280, rdpHeight:800, rdpScaleMode:'smart', rdpKeyboardLayout:'en-US' } as any;
const hostProtocol = (h: HostConfig): 'ssh'|'rdp' => ((h as any).protocol === 'rdp' || (h as any).rdpEnabled) ? 'rdp' : 'ssh';
const hostUserLabel = (h: HostConfig) => hostProtocol(h) === 'rdp' ? ((h as any).rdpUsername || h.username || 'rdp') : (h.username || 'ssh');
const hostPortLabel = (h: HostConfig) => hostProtocol(h) === 'rdp' ? ((h as any).rdpPort || 3389) : (h.port || 22);
const fmt = (n: number) => n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
const redactSecrets = (input = '') => String(input)
  .replace(/-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/g, '<private-key-redacted>')
  .replace(/Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Authorization: Bearer <token-redacted>')
  .replace(/([\"']?)(password|token|autoPassphrase|passphrase|privateKey)\1\s*[:=]\s*([\"']?)[^,\"'\s}]+\3/gi, '$1$2$1: <secret-redacted>');
const cleanError = (e: unknown) => {
  const raw = redactSecrets(String(e));
  const json = raw.match(/\{.*\}/s)?.[0];
  if (json) { try { return redactSecrets(JSON.parse(json).message || raw); } catch {} }
  return raw.replace(/^Error:\s*/, '');
};
type SyncNotice = { kind:'info'|'success'|'warning'|'error'; title:string; message:string; action?:'unlockVault'; details?:string };
const syncInfo = (message: string): SyncNotice => ({ kind:'info', title:'Sync-Status', message });
const syncNoticeFromText = (message = ''): SyncNotice => {
  const clean = cleanError(message);
  const details = clean !== message ? redactSecrets(message) : undefined;
  if (/Lokaler Tresor gesperrt|Datensafe entsperren|gesperrt/i.test(clean)) return { kind:'warning', title:'Sync wartet auf Datensafe', message: clean.includes('Lokaler Tresor gesperrt') ? 'Der lokale Datensafe ist gesperrt. Entsperre ihn, damit die Synchronisierung weiterläuft.' : clean, action:'unlockVault', details };
  if (/Fehler|fehlgeschlagen|ungültig|failed|error/i.test(clean)) return { kind:'error', title:'Sync fehlgeschlagen', message: clean, details };
  if (/gestoppt|nötig|zuerst|prüfen/i.test(clean)) return { kind:'warning', title:'Sync braucht Aufmerksamkeit', message: clean };
  if (/OK|gespeichert|eingerichtet|geladen|hochgeladen|deaktiviert/i.test(clean)) return { kind:'success', title:'Sync OK', message: clean };
  return syncInfo(clean);
};
const friendlySyncError = (e: unknown, reason = ''): SyncNotice => {
  const raw = redactSecrets(String(e));
  const message = cleanError(e);
  if (/Lokaler Tresor gesperrt/i.test(message)) return { kind:'warning', title:'Auto-Sync pausiert', message:'Der lokale Datensafe ist gesperrt. Entsperre ihn, damit die Synchronisierung weiterläuft.', action:'unlockVault', details: raw };
  return { kind:'error', title: reason ? `Auto-Sync fehlgeschlagen (${reason})` : 'Sync fehlgeschlagen', message, details: raw !== message ? raw : undefined };
};
const semverGreater = (a = '', b = '') => {
  const A = a.split('.').map(Number), B = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (A[i] || 0) - (B[i] || 0); if (d) return d > 0; }
  return false;
};
const parentRemote = (p = '/') => { const clean = (p || '/').replace(/\/+$/, '') || '/'; if (clean === '/') return '/'; return clean.slice(0, clean.lastIndexOf('/')) || '/'; };
const parentLocal = (p = '') => { if (!p) return p; const sep = p.includes('\\') ? '\\' : '/'; const clean = p.replace(/[\\/]+$/, ''); const idx = clean.lastIndexOf(sep); if (idx <= 0) return clean; return clean.slice(0, idx); };
const syncReady = (c: SyncConfig, pass: string) => !!(c.enabled && validSyncEndpoint(c.endpoint) && c.account && ((c as any).tokenSaved || c.token) && (((c as any).autoPassphraseSaved && !pass) || (pass && pass.length >= 10)));
const syncSecretsLocked = (c: SyncConfig, pass = '') => !!(c.enabled && (((c as any).tokenSaved && !c.token) || ((c as any).autoPassphraseSaved && !pass)));
const syncStatusText = (c: SyncConfig, pass = '') => !c.enabled
  ? 'Sync aus — lokal zuerst.'
  : syncSecretsLocked(c, pass)
    ? 'Auto-Sync aktiv — Token/Passphrase gespeichert, Datensafe gesperrt.'
    : 'Auto-Sync aktiv — Daten bleiben serverseitig verschlüsselt.';
const syncTokenPlaceholder = (c: SyncConfig) => ((c as any).tokenSaved && !c.token) ? 'Token gespeichert — Datensafe entsperren' : '';
const syncPassPlaceholder = (c: SyncConfig, pass = '') => ((c as any).autoPassphraseSaved && !pass) ? 'Passphrase gespeichert — Datensafe entsperren' : 'wird lokal verschlüsselt gespeichert';
const syncNotReadyText = (c: SyncConfig, pass = '') => !validSyncEndpoint(c.endpoint)
  ? 'Sync-Server muss HTTPS nutzen (HTTP nur localhost/127.0.0.1).'
  : syncSecretsLocked(c, pass)
    ? 'Datensafe entsperren: Sync-Token/Passphrase sind gespeichert, aber gesperrt.'
    : 'Sync aktivieren + Token + Passphrase (mind. 10 Zeichen) nötig.';
const safeChildName = (name = '') => { const clean = name.trim(); if (!clean || clean === '.' || clean === '..' || /[\\/]/.test(clean)) throw new Error('Name darf keine Pfadsegmente oder Separatoren enthalten.'); return clean; };
const joinLocal = (dir: string, name: string) => dir.replace(/[\\/]+$/, '') + (dir.includes('\\') ? '\\' : '/') + safeChildName(name);
const joinRemote = (dir: string, name: string) => (dir === '/' ? '/' : dir.replace(/\/+$/, '') + '/') + safeChildName(name);
const fmtDate = (ms?: number) => ms ? new Date(ms).toLocaleString() : '—';
const dirName = (p = '') => { const sep = p.includes('\\') ? '\\' : '/'; const clean = p.replace(/[\\/]+$/, ''); const idx = clean.lastIndexOf(sep); return idx > 0 ? clean.slice(0, idx) : (sep === '/' ? '/' : clean); };
const ownerLabel = (e: FileEntry) => (e as any).owner ? `${(e as any).owner} [${(e as any).uid ?? '?'}]` : (typeof (e as any).uid === 'number' ? `[${(e as any).uid}]` : '—');
const groupLabel = (e: FileEntry) => (e as any).group ? `${(e as any).group} [${(e as any).gid ?? '?'}]` : (typeof (e as any).gid === 'number' ? `[${(e as any).gid}]` : '—');
const modeToOctal = (m = '') => {
  if (m.length < 10) return '';
  const vals = [[1,2,3],[4,5,6],[7,8,9]].map(([r,w,x]) => (m[r] === 'r' ? 4 : 0) + (m[w] === 'w' ? 2 : 0) + (m[x] !== '-' ? 1 : 0)).join('');
  const special = (m[3] === 's' || m[3] === 'S' ? 4 : 0) + (m[6] === 's' || m[6] === 'S' ? 2 : 0) + (m[9] === 't' || m[9] === 'T' ? 1 : 0);
  return `${special}${vals}`;
};

const octalClean = (v = '') => v.replace(/[^0-7]/g, '').slice(0, 4);
const octalNorm = (v = '', fallback = '0644') => (octalClean(v) || fallback).padStart(4, '0').slice(-4);
const octalHasBit = (octal: string, row: number, bit: number) => ((parseInt(octalNorm(octal)[row + 1] || '0', 8) || 0) & [4,2,1][bit]) !== 0;
const setOctalBit = (octal: string, row: number, bit: number, on: boolean) => {
  const chars = octalNorm(octal).split(''); const idx = row + 1; const mask = [4,2,1][bit]; let d = parseInt(chars[idx] || '0', 8) || 0;
  d = on ? (d | mask) : (d & ~mask); chars[idx] = String(d); return chars.join('');
};
const octalSpecial = (octal: string, bit: number) => ((parseInt(octalNorm(octal)[0] || '0', 8) || 0) & [4,2,1][bit]) !== 0;
const setOctalSpecial = (octal: string, bit: number, on: boolean) => { const chars = octalNorm(octal).split(''); const mask = [4,2,1][bit]; let d = parseInt(chars[0] || '0', 8) || 0; d = on ? (d | mask) : (d & ~mask); chars[0] = String(d); return chars.join(''); };
const octalWithDirX = (octal: string) => { let o = octalNorm(octal); for (let r=0;r<3;r++) if (octalHasBit(o,r,0)) o = setOctalBit(o,r,2,true); return o; };
const fileIcon = (f: FileEntry) => f.type === 'directory' ? '📁' : '📄';
const emptyVault: VaultCredential = { id:'', name:'', username:'', authMode:'password', password:'', keyPath:'', privateKey:'' };
const scrubVaultCredential = (v: VaultCredential): VaultCredential => ({...v, password:'', privateKey:''});
const scrubHostConfig = (h: HostConfig): HostConfig => ({...h, password:'', privateKey:'', rdpPassword:''});
const emptyLocalVaultStatus: LocalVaultStatus = { configured:false, unlocked:false, encryptedValues:0, plaintextSecrets:0, message:'Lokaler Tresor noch nicht geprüft.' };
type AppTheme = 'default'|'github-gray'|'matrix-green'|'liquid-glozzy'|'light';
const themeOptions: {value: AppTheme; label: string}[] = [
  {value:'default', label:'ssh-vault Dark'},
  {value:'liquid-glozzy', label:'Liquid Glozzy'},
  {value:'light', label:'Light'},
  {value:'github-gray', label:'GitHub Gray'},
  {value:'matrix-green', label:'Matrix Grün'},
];
type FileEditorState = {side:'local'|'remote'; path:string; name:string; content:string; original:string; status:string; saving:boolean};
type ExternalDropItem = {relPath:string;file?:File;kind:'file'|'directory'};
type TerminalChunk = string | Uint8Array;
type TerminalPayload = {seq: number; data: TerminalChunk};
type TerminalContextMenu = {x:number;y:number;sessionId:string};
type TerminalRecord = {term: Terminal; fit: FitAddon; el: HTMLDivElement; cols?: number; rows?: number; resizeSeq?: number; resizeObserver?: ResizeObserver; resizeTimer?: number; resizeFrame?: number; altScreen?: boolean; bracketedPaste?: boolean; altScanTail?: string; altRefreshTimer?: number; expectedSeq?: number; seqBuffer?: Record<number, TerminalChunk>; seqGapTimer?: number; contextMenuHandler?: (e: globalThis.MouseEvent) => void; pasteHandler?: (e: globalThis.ClipboardEvent) => void};
type RDPAudioRecord = {ctx: AudioContext; nextTime: number};
type SftpTab = {id:string; hostID:string; title:string; remotePath:string; remote:FileEntry[]; selectedRemote:string};
type RDPScaleMode = 'smart'|'sharp'|'fit'|'original';
type RDPKeyboardLayout = 'en-US'|'de-DE';
const isFullRDPFrame = (frame: RDPBinaryFrame) => frame.left === 0 && frame.top === 0 && frame.width === frame.surfaceWidth && frame.height === frame.surfaceHeight;
const lastFullRDPFrameIndex = (frames: RDPBinaryFrame[]) => { for (let i = frames.length - 1; i >= 0; i--) if (isFullRDPFrame(frames[i])) return i; return -1; };
const rdpScaleModeOf = (host?: HostConfig): RDPScaleMode => { const m = (host as any)?.rdpScaleMode; return m === 'sharp' || m === 'fit' || m === 'original' ? m : 'smart'; };
const rdpKeyboardLayoutOf = (host?: HostConfig): RDPKeyboardLayout => ((host as any)?.rdpKeyboardLayout === 'de-DE' ? 'de-DE' : 'en-US');
const storedTheme = (): AppTheme => { const t = localStorage.getItem('sshv.theme'); if (t === 'apple-liquid') { localStorage.setItem('sshv.theme','liquid-glozzy'); return 'liquid-glozzy'; } return t === 'github-gray' || t === 'matrix-green' || t === 'liquid-glozzy' || t === 'light' ? t : 'default'; };
const visibleTagsStorageKey = 'sshv.visibleTags';
const storedVisibleTags = (): string[] => {
  try {
    const parsed = JSON.parse(localStorage.getItem(visibleTagsStorageKey) || '[]');
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string' && x.trim().length > 0) : [];
  } catch { return []; }
};
const terminalTheme = (theme: AppTheme) => theme === 'github-gray'
  ? { background: '#1c2128', foreground: '#adbac7', cursor: '#539bf5', selectionBackground: '#373e47' }
  : theme === 'liquid-glozzy'
    ? { background: '#08111f', foreground: '#eef6ff', cursor: '#7bc6ff', selectionBackground: '#244b78', black: '#050812', red: '#ff6961', green: '#4fe374', yellow: '#ffd60a', blue: '#7bc6ff', magenta: '#da8fff', cyan: '#7ee7ff', white: '#dbe7ff', brightBlack: '#6d7f9c', brightRed: '#ff8a83', brightGreen: '#75f0a0', brightYellow: '#ffe071', brightBlue: '#9dd7ff', brightMagenta: '#e6b0ff', brightCyan: '#a5f0ff', brightWhite: '#ffffff' }
  : theme === 'light'
    ? { background: '#f8fafc', foreground: '#0f172a', cursor: '#2563eb', selectionBackground: '#bfdbfe', black: '#0f172a', red: '#dc2626', green: '#16a34a', yellow: '#ca8a04', blue: '#2563eb', magenta: '#9333ea', cyan: '#0891b2', white: '#f8fafc', brightBlack: '#64748b', brightRed: '#ef4444', brightGreen: '#22c55e', brightYellow: '#eab308', brightBlue: '#3b82f6', brightMagenta: '#a855f7', brightCyan: '#06b6d4', brightWhite: '#ffffff' }
  : theme === 'matrix-green'
    ? { background: '#020804', foreground: '#8cff9b', cursor: '#b7ffbf', selectionBackground: '#114d20', black: '#001f08', red: '#ff5f5f', green: '#39ff14', yellow: '#c6ff4a', blue: '#00b7ff', magenta: '#9dff6b', cyan: '#00ff9c', white: '#d6ffd9', brightBlack: '#0b3d16', brightRed: '#ff8080', brightGreen: '#69ff5f', brightYellow: '#dcff78', brightBlue: '#63d7ff', brightMagenta: '#bcff9b', brightCyan: '#5dffbf', brightWhite: '#ffffff' }
    : { background: '#070812', foreground: '#dbe7ff', cursor: '#8bc2ff', selectionBackground: '#1d375f' };

function App() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [hosts, setHosts] = useState<HostConfig[]>([]);
  const [vault, setVault] = useState<VaultCredential[]>([]);
  const [vaultDraft, setVaultDraft] = useState<VaultCredential>(emptyVault);
  const [selectedVault, setSelectedVault] = useState<string>('');
  const [selected, setSelected] = useState<string>('');
  const [draft, setDraft] = useState<HostConfig>(emptyHost);
  const [editing, setEditing] = useState(false);
  const [sessions, setSessions] = useState<SessionState[]>([]);
  const [activeSession, setActiveSession] = useState<string>('');
  const [rdpSessions, setRdpSessions] = useState<SessionState[]>([]);
  const [activeRdp, setActiveRdp] = useState<string>('');
  const [view, setView] = useState<'terminal'|'sftp'|'rdp'|'vault'|'settings'>('terminal');
  const [tagFilterOpen, setTagFilterOpen] = useState(false);
  const [visibleTags, setVisibleTags] = useState<string[]>(storedVisibleTags);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('sshv.sidebarCollapsed') === '1');
  const [theme, setTheme] = useState<AppTheme>(storedTheme);
  const [sftpId, setSftpId] = useState<string>('');
  const [sftpTabs, setSftpTabs] = useState<SftpTab[]>([]);
  const [activeSftp, setActiveSftp] = useState('');
  const [remotePath, setRemotePath] = useState<string>('/');
  const [localPath, setLocalPath] = useState<string>('');
  const [remote, setRemote] = useState<FileEntry[]>([]);
  const [local, setLocal] = useState<FileEntry[]>([]);
  const [release, setRelease] = useState<ReleaseIndex | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string>('');
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const [versionMenuOpen, setVersionMenuOpen] = useState(false);
  const [installingUpdate, setInstallingUpdate] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<'unknown'|'checking'|'available'|'current'|'error'>('unknown');
  const [updateAvailableVersion, setUpdateAvailableVersion] = useState('');
  const [syncCfg, setSyncCfg] = useState<SyncConfig>({enabled:false, endpoint:'', account:'', token:'', includeKeys:true});
  const [syncPass, setSyncPass] = useState('');
  const [accountLogin, setAccountLogin] = useState<SyncAccountRequest>({endpoint:defaultSyncServer, username:'', password:'', label:'', totp:''});
  const [showTotpDialog, setShowTotpDialog] = useState(false);
  const [accountTotp, setAccountTotp] = useState('');
  const [accountMsg, setAccountMsg] = useState('Noch nicht eingeloggt.');
  const [accountLoginBusy, setAccountLoginBusy] = useState(false);
  const [localVault, setLocalVault] = useState<LocalVaultStatus>(emptyLocalVaultStatus);
  const [localVaultPass, setLocalVaultPass] = useState('');
  const [localVaultMsg, setLocalVaultMsg] = useState('Lokaler Tresor noch nicht geprüft.');
  const [showLocalVaultPrompt, setShowLocalVaultPrompt] = useState(false);
  const [sshConfigPath, setSSHConfigPath] = useState('');
  const [importMsg, setImportMsg] = useState('Noch kein Import ausgeführt.');
  const [transferPath, setTransferPath] = useState('');
  const [transferPass, setTransferPass] = useState('');
  const [transferReplace, setTransferReplace] = useState(false);
  const [transferMsg, setTransferMsg] = useState('Noch kein lokaler Export/Import ausgeführt.');
  const [knownHosts, setKnownHosts] = useState<any>({path:'', content:'', count:0});
  const [knownHostsMsg, setKnownHostsMsg] = useState('Noch nicht geladen.');
  const [msg, setMsg] = useState<string>('Bereit');
  const [syncNotice, setSyncNotice] = useState<SyncNotice>(() => syncInfo('Sync aus — lokal zuerst.'));
  const syncMsg = syncNotice.message;
  const [syncRunning, setSyncRunning] = useState(false);
  const syncVaultLocked = syncSecretsLocked(syncCfg, syncPass) && localVault.configured && !localVault.unlocked;
  const syncCanRun = syncReady(syncCfg, syncPass) && !syncVaultLocked;
  const syncFooterState = !syncCfg.enabled ? 'off' : syncRunning ? 'syncing' : syncNotice.kind === 'error' ? 'error' : syncVaultLocked ? 'locked' : !syncCanRun ? 'waiting' : (syncNotice.kind === 'success' || !!syncCfg.lastSync) ? 'ok' : 'ready';
  const syncFooterTitle = syncFooterState === 'off' ? 'Sync aus' : syncFooterState === 'syncing' ? 'Sync läuft' : syncFooterState === 'locked' ? 'Sync wartet auf Datensafe' : syncFooterState === 'waiting' ? syncNotReadyText(syncCfg, syncPass) : syncFooterState === 'error' ? `Sync Fehler: ${syncMsg}` : syncMsg;
  const availableHostTags = Array.from(new Set(hosts.flatMap(h => h.tags || []).filter(Boolean))).sort((a,b)=>a.localeCompare(b));
  const filteredHosts = visibleTags.length === 0 ? hosts : hosts.filter(h => (h.tags || []).some(t => visibleTags.includes(t)));
  const hiddenHostCount = hosts.length - filteredHosts.length;
  const setAllTagsVisible = () => setVisibleTags([]);
  const toggleVisibleTag = (tag: string) => setVisibleTags(prev => {
    const base = prev.length === 0 ? availableHostTags : prev;
    const next = base.includes(tag) ? base.filter(t => t !== tag) : [...base, tag];
    return next.length === availableHostTags.length ? [] : next;
  });
  const setSyncMsg = (message: string) => setSyncNotice(syncNoticeFromText(message));
  const [connectingSSH, setConnectingSSH] = useState(false);
  const [connectingSFTP, setConnectingSFTP] = useState(false);
  const [connectingRDP, setConnectingRDP] = useState(false);
  const [ctx, setCtx] = useState<{x:number,y:number,host:HostConfig}|null>(null);
  const [termCtx, setTermCtx] = useState<TerminalContextMenu | null>(null);
  const [selectedLocal, setSelectedLocal] = useState<string>('');
  const [selectedRemote, setSelectedRemote] = useState<string>('');
  const [sftpCtx, setSftpCtx] = useState<{x:number,y:number,side:'local'|'remote',entry?:FileEntry}|null>(null);
  const [sftpDrag, setSftpDrag] = useState<{side:'local'|'remote',path:string,name:string,type:string}|null>(null);
  const [sftpDropSide, setSftpDropSide] = useState<'local'|'remote'|null>(null);
  const [sftpProps, setSftpProps] = useState<{side:'local'|'remote',entry:FileEntry}|null>(null);
  const [fileEditor, setFileEditor] = useState<FileEditorState | null>(null);
  const [propTab, setPropTab] = useState<'general'|'checksum'>('general');
  const [propEntry, setPropEntry] = useState<FileEntry | null>(null);
  const [propOctal, setPropOctal] = useState('');
  const [propSize, setPropSize] = useState<number | null>(null);
  const [propChecksum, setPropChecksum] = useState('');
  const [propMsg, setPropMsg] = useState('');
  const [propRecursive, setPropRecursive] = useState(false);
  const [propDirX, setPropDirX] = useState(false);
  const [propOwner, setPropOwner] = useState('');
  const [propGroup, setPropGroup] = useState('');
  const [propOwners, setPropOwners] = useState<any[]>([]);
  const [propGroups, setPropGroups] = useState<any[]>([]);
  const autoSyncBusy = useRef(false);
  const syncCfgRef = useRef(syncCfg);
  const syncPassRef = useRef(syncPass);
  const localVaultSettingsRef = useRef<HTMLElement | null>(null);
  const syncSettingsRef = useRef<HTMLElement | null>(null);
  const syncActionsRef = useRef<HTMLDivElement | null>(null);
  const updateSettingsRef = useRef<HTMLElement | null>(null);
  const pendingTermBuffers = useRef<Record<string, TerminalPayload[]>>({});
  const terms = useRef<Record<string, TerminalRecord>>({});
  const rdpCanvases = useRef<Record<string, HTMLCanvasElement>>({});
  const rdpRenderers = useRef<Record<string, RDPWebGLRenderer>>({});
  const rdpRenderStreams = useRef<Record<string, WebSocket>>({});
  const rdpRenderFrameQueues = useRef<Record<string, RDPBinaryFrame[]>>({});
  const rdpRenderFrameRAF = useRef<Record<string, number>>({});
  const rdpAudio = useRef<Record<string, RDPAudioRecord>>({});
  const rdpPressedKeys = useRef<Record<string, Set<string>>>({});
  const rdpSuppressedKeyUps = useRef<Record<string, Set<string>>>({});
  const rdpMouseMoves = useRef<Record<string, {x:number; y:number; frame?:number; timer?:number; lastSent?:number}>>({});
  const rdpWraps = useRef<Record<string, HTMLDivElement>>({});
  const rdpWrapObservers = useRef<Record<string, ResizeObserver>>({});
  const rdpResizeTimer = useRef<number | undefined>(undefined);
  const rdpConnectSizes = useRef<Record<string, string>>({});
  const rdpOpeningHosts = useRef<Set<string>>(new Set());
  const terminalPaneRef = useRef<HTMLDivElement | null>(null);

  const reloadHosts = () => API.ListHosts().then(h => { const clean = h.map(scrubHostConfig); setHosts(clean); if (!selected || !clean.some(x => x.id === selected)) setSelected(clean[0]?.id || ''); }).catch(e => setMsg('Hosts laden fehlgeschlagen: '+cleanError(e)));
  const decodeTerminalChunk = (payload: any): TerminalChunk => {
    const b64 = payload?.dataB64;
    if (b64) {
      const bin = window.atob(String(b64));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return String(payload?.data || '');
  };
  const playRDPAudio = (payload: any) => {
    const sessionID = String(payload?.sessionID || '');
    const b64 = String(payload?.base64 || '');
    const sampleRate = Number(payload?.sampleRate || 0);
    const channels = Math.max(1, Math.min(2, Number(payload?.channels || 1)));
    const bits = Number(payload?.bitsPerSample || 16);
    if (!sessionID || !b64 || !sampleRate || bits !== 16) return;
    const AudioCtor = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtor) return;
    let rec = rdpAudio.current[sessionID];
    if (!rec || rec.ctx.sampleRate !== sampleRate) {
      try { rec?.ctx.close(); } catch {}
      rec = {ctx: new AudioCtor({sampleRate}), nextTime: 0};
      rdpAudio.current[sessionID] = rec;
    }
    try { if (rec.ctx.state === 'suspended') void rec.ctx.resume(); } catch {}
    const bin = window.atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const samples = Math.floor(bytes.length / 2 / channels);
    if (samples <= 0) return;
    const buffer = rec.ctx.createBuffer(channels, samples, sampleRate);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < samples; i++) for (let ch = 0; ch < channels; ch++) buffer.getChannelData(ch)[i] = view.getInt16((i * channels + ch) * 2, true) / 32768;
    const src = rec.ctx.createBufferSource();
    src.buffer = buffer;
    src.connect(rec.ctx.destination);
    const now = rec.ctx.currentTime;
    const start = Math.max(now + 0.02, rec.nextTime || 0);
    rec.nextTime = start + buffer.duration;
    if (rec.nextTime - now > 0.8) rec.nextTime = now + buffer.duration;
    src.start(start);
  };
  const chunkControlText = (data: TerminalChunk) => {
    if (typeof data === 'string') return data;
    let out = '';
    for (let i = 0; i < data.length; i++) out += String.fromCharCode(data[i]);
    return out;
  };
  const updateAltScreenState = (rec: TerminalRecord, data: TerminalChunk) => {
    const text = (rec.altScanTail || '') + chunkControlText(data);
    if (/\x1b\[\?(1049|1047|47)h/.test(text)) rec.altScreen = true;
    if (/\x1b\[\?(1049|1047|47)l/.test(text)) rec.altScreen = false;
    if (/\x1b\[\?2004h/.test(text)) rec.bracketedPaste = true;
    if (/\x1b\[\?2004l/.test(text)) rec.bracketedPaste = false;
    rec.altScanTail = text.slice(-64);
  };
  const scheduleAltScreenRefresh = (rec: TerminalRecord) => {
    if (rec.altRefreshTimer) return;
    rec.altRefreshTimer = window.setTimeout(() => {
      rec.altRefreshTimer = undefined;
      window.requestAnimationFrame(() => { try { rec.term.refresh(0, rec.term.rows - 1); } catch {} });
    }, rec.altScreen ? 200 : 500);
  };
  const applyTerminalChunk = (rec: TerminalRecord, data: TerminalChunk) => {
    updateAltScreenState(rec, data);
    rec.term.write(data, () => scheduleAltScreenRefresh(rec));
  };
  const drainTerminalSeqBuffer = (rec: TerminalRecord) => {
    if (!rec.seqBuffer) rec.seqBuffer = {};
    if (!rec.expectedSeq) rec.expectedSeq = 1;
    while (rec.seqBuffer[rec.expectedSeq]) {
      const data = rec.seqBuffer[rec.expectedSeq];
      delete rec.seqBuffer[rec.expectedSeq];
      rec.expectedSeq++;
      applyTerminalChunk(rec, data);
    }
  };
  const handleTerminalSeqGap = (sessionId: string, rec: TerminalRecord) => {
    if (rec.seqGapTimer) return;
    rec.seqGapTimer = window.setTimeout(() => {
      rec.seqGapTimer = undefined;
      const buffered = rec.seqBuffer || {};
      const next = Math.min(...Object.keys(buffered).map(Number).filter(n => n > 0));
      if (!Number.isFinite(next) || !rec.expectedSeq || next <= rec.expectedSeq) return;
      setMsg(`Terminal Datenlücke erkannt (${rec.expectedSeq}→${next}); htop-Repaint wird angefordert.`);
      try { rec.term.reset(); } catch {}
      rec.expectedSeq = next;
      void API.ResizeSSH(sessionId, rec.cols || rec.term.cols, rec.rows || rec.term.rows);
      drainTerminalSeqBuffer(rec);
    }, 1200);
  };
  const writeSSHPayload = (sessionId: string, seq: number, data: TerminalChunk) => {
    const rec = terms.current[sessionId];
    if (rec) {
      if (!seq) { applyTerminalChunk(rec, data); return; }
      if (!rec.seqBuffer) rec.seqBuffer = {};
      if (!rec.expectedSeq) rec.expectedSeq = 1;
      if (seq < rec.expectedSeq) return;
      rec.seqBuffer[seq] = data;
      drainTerminalSeqBuffer(rec);
      if (seq > (rec.expectedSeq || 1)) handleTerminalSeqGap(sessionId, rec);
      return;
    }
    const pending = pendingTermBuffers.current[sessionId] || [];
    pending.push({seq, data});
    pendingTermBuffers.current[sessionId] = pending.slice(-512);
  };
  const estimateInitialPtySize = () => {
    const pane = terminalPaneRef.current || document.querySelector('.terminalPane.active') as HTMLDivElement | null;
    const rect = pane?.getBoundingClientRect();
    const width = Math.max(320, Math.floor((rect?.width || window.innerWidth - 460) - 4));
    const height = Math.max(180, Math.floor((rect?.height || window.innerHeight - 190) - 48));
    let cellW = 8;
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (ctx) { ctx.font = '13px JetBrains Mono, Consolas, monospace'; cellW = Math.max(7, Math.ceil(ctx.measureText('W').width || 8)); }
    } catch {}
    const cols = Math.max(40, Math.min(500, Math.floor(width / cellW)));
    const rows = Math.max(10, Math.min(200, Math.floor(height / 15)));
    return {cols, rows};
  };
  const reloadVault = () => API.ListVault().then(v => { const clean = v.map(scrubVaultCredential); setVault(clean); if (!selectedVault && clean[0]) setSelectedVault(clean[0].id); }).catch(e => setMsg('Vault laden fehlgeschlagen: '+cleanError(e)));
  const loadKnownHosts = () => API.KnownHostsInfo().then(k => { setKnownHosts(k); setKnownHostsMsg(`${(k as any).count || 0} bekannte Host-Keys geladen.`); }).catch(e => setKnownHostsMsg(cleanError(e)));
  const vaultLabel = (id?: string) => { const v = vault.find(x=>x.id===id); return v ? `${v.name} · ${v.username} · ${v.authMode === 'key' ? 'SSH-Key' : 'Passwort'}` : 'Direkte Host-Anmeldung'; }; 
  const refreshLocal = (p = localPath) => API.LocalList(p).then(r => { setLocal(r); setLocalPath(p); setSelectedLocal(''); }).catch(e => setMsg(cleanError(e)));
  const refreshRemote = (p = remotePath) => sftpId ? API.ListSFTP(sftpId, p).then(r => { setRemote(r); setRemotePath(p); setSelectedRemote(''); }).catch(e => setMsg(cleanError(e))) : Promise.resolve();
  const compatibleAssetFor = (appInfo: AppInfo | null, files: ReleaseAsset[] = []) => {
    const arch = (appInfo as any)?.arch || '';
    if (appInfo?.platform === 'windows') return files.find(a => a.name.includes('windows-amd64-installer.exe')) || files.find(a => a.name.includes('windows-amd64.exe'));
    if (appInfo?.platform === 'linux') return files.find(a => a.name.includes(`linux-${arch}.tar.gz`)) || files.find(a => a.name.includes('linux-amd64.tar.gz')) || files.find(a => a.name.includes('linux-') && a.name.endsWith('.tar.gz'));
    if (appInfo?.platform === 'darwin') return files.find(a => a.name.includes(`darwin-${arch}.zip`)) || files.find(a => a.name.includes('darwin-arm64.zip')) || files.find(a => a.name.includes('darwin-amd64.zip')) || files.find(a => a.name.includes('darwin-') && a.name.endsWith('.zip'));
    return files.find(a => a.name.includes(`${appInfo?.platform || ''}-${arch}`)) || files[0];
  };
  const compatibleAsset = (files: ReleaseAsset[] = []) => compatibleAssetFor(info, files);
  const releaseVersions = (r: ReleaseIndex | null): ReleaseVersion[] => {
    const versions = r?.versions?.length ? r.versions : (r?.version ? [{version:r.version, assets:r.files || []} as ReleaseVersion] : []);
    return [...versions].sort((a,b)=>semverGreater(a.version,b.version)?-1:semverGreater(b.version,a.version)?1:0);
  };
  const compatibleVersionsFor = (r: ReleaseIndex | null, appInfo: AppInfo | null): ReleaseVersion[] => releaseVersions(r).filter(v => !!compatibleAssetFor(appInfo, v.assets || []) && semverGreater(v.version, appInfo?.version || '0.0.0'));
  const compatibleVersions = (r: ReleaseIndex | null): ReleaseVersion[] => releaseVersions(r).filter(v => !!compatibleAsset(v.assets || []) && semverGreater(v.version, info?.version || '0.0.0'));
  const versionAssets = (r: ReleaseIndex | null, v: string): ReleaseAsset[] => compatibleVersions(r).find(x=>x.version===v)?.assets || [];
  const selectedCompatibleAsset = () => compatibleAsset(versionAssets(release, selectedVersion));
  const selectedReleaseVersion = () => releaseVersions(release).find(x=>x.version===selectedVersion);
  const selectedChangelog = () => (((selectedReleaseVersion() as any)?.changelog || (release as any)?.changelog || []) as string[]).map(x=>String(x || '').trim()).filter(Boolean);

  useEffect(() => {
    API.Info().then(i => { setInfo(i); void checkUpdatesOnStartup(i); });
    API.LocalVaultStatus().then(st => { setLocalVault(st); setLocalVaultMsg(st.message || 'Lokaler Tresorstatus geladen.'); if ((st.configured && !st.unlocked) || st.plaintextSecrets > 0) setShowLocalVaultPrompt(true); }).catch(e => setLocalVaultMsg(cleanError(e)));
    API.GetSyncConfig().then(c => { setSyncCfg(c); const pass = (c as any).autoPassphrase || ''; setSyncPass(pass); setSyncMsg(syncStatusText(c, pass)); if (syncReady(c, pass)) setTimeout(() => autoSync('startup'), 600); }).catch(e => setSyncMsg(cleanError(e)));
    reloadHosts();
    reloadVault();
    loadKnownHosts();
    API.LocalHome().then(p => { setLocalPath(p); return API.LocalList(p); }).then(setLocal).catch(e => setMsg(cleanError(e)));
    const offData = Events.On('ssh:data', (ev: any) => { const d = ev.data; writeSSHPayload(d.sessionId, Number(d.seq || 0), decodeTerminalChunk(d)); });
    const offStatus = Events.On('ssh:status', (ev: any) => { const st = ev.data as SessionState; setSessions(prev => prev.map(x => x.id === st.id ? st : x)); });
    const offRdpStatus = Events.On('rdp:status', (ev: any) => { const st = ev.data as SessionState; if (st.status === 'closed') { dropRDPClientSession(st.id); return; } setRdpSessions(prev => prev.map(x => x.id === st.id ? st : x)); });
    const offRdpAudio = Events.On('rdp:audio', (ev: any) => playRDPAudio(ev.data));
    return () => { offData(); offStatus(); offRdpStatus(); offRdpAudio(); Object.values(rdpAudio.current).forEach(r => { try { r.ctx.close(); } catch {} }); rdpAudio.current = {}; };
  }, []);

  useEffect(() => { const h = hosts.find(x => x.id === selected); if (h && !editing) setDraft({...h, tags: [...(h.tags || [])]}); }, [selected, hosts, editing]);
  useEffect(() => { syncCfgRef.current = syncCfg; }, [syncCfg]);
  useEffect(() => { syncPassRef.current = syncPass; }, [syncPass]);
  useEffect(() => {
    if (!sftpId) return;
    setSftpTabs(prev => prev.map(t => t.id === sftpId ? {...t, remotePath, remote, selectedRemote} : t));
  }, [sftpId, remotePath, remote, selectedRemote]);
  useEffect(() => { const close = () => { setCtx(null); setSftpCtx(null); setTermCtx(null); }; const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') close(); }; window.addEventListener('click', close); window.addEventListener('keydown', esc); return () => { window.removeEventListener('click', close); window.removeEventListener('keydown', esc); }; }, []);
  useEffect(() => { localStorage.setItem('sshv.sidebarCollapsed', sidebarCollapsed ? '1' : '0'); }, [sidebarCollapsed]);
  useEffect(() => { if (view === 'rdp' && activeRdp) { scheduleRDPResizeReconnect('active-rdp'); window.setTimeout(() => rdpCanvases.current[activeRdp]?.focus(), 80); } }, [view, activeRdp, sidebarCollapsed]);
  useEffect(() => {
    localStorage.setItem('sshv.theme', theme);
    const nextTheme = terminalTheme(theme);
    Object.values(terms.current).forEach(({term}) => { term.options.theme = nextTheme; term.refresh(0, term.rows - 1); });
  }, [theme]);
  useEffect(() => {
    const onResize = () => { Object.keys(terms.current).forEach(id => scheduleTerminalFit(id, id === activeSession, 'window-resize')); scheduleRDPResizeReconnect('window-resize'); };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [activeSession]);
  useEffect(() => {
    const id = activeSession;
    if (!id) return;
    if (view === 'terminal') scheduleTerminalFit(id, true, 'active-tab');
    const timer = window.setInterval(() => { scheduleTerminalFit(id, id === activeSession, 'size-sync'); }, 2000);
    return () => window.clearInterval(timer);
  }, [activeSession, view, sidebarCollapsed]);
  useEffect(() => {
    if (!sftpProps) return;
    setPropTab('general'); setPropEntry(sftpProps.entry); setPropSize(null); setPropChecksum(''); setPropMsg('Lade Eigenschaften…'); setPropRecursive(false); setPropDirX(false);
    const load = async () => {
      try {
        const st = sftpProps.side === 'remote' ? await API.PropertiesStatSFTP(sftpId, sftpProps.entry.path) : await API.PropertiesLocalStat(sftpProps.entry.path);
        setPropEntry(st); setPropOctal(modeToOctal(st.mode) || modeToOctal(sftpProps.entry.mode) || '0644');
        setPropOwner((st as any).owner || (typeof (st as any).uid === 'number' ? String((st as any).uid) : ''));
        setPropGroup((st as any).group || (typeof (st as any).gid === 'number' ? String((st as any).gid) : ''));
        if (sftpProps.side === 'remote' && sftpId) {
          try {
            const ids = await API.PropertiesIdentityOptionsSFTP(sftpId);
            const owners = [...((ids as any).owners || [])]; const groups = [...((ids as any).groups || [])];
            const ownerName = (st as any).owner || ''; const groupName = (st as any).group || '';
            if (ownerName && !owners.some((o:any)=>o.name===ownerName)) owners.unshift({name:ownerName, id:(st as any).uid || 0, label: ownerName + (typeof (st as any).uid === 'number' ? ` [${(st as any).uid}]` : '')});
            if (groupName && !groups.some((g:any)=>g.name===groupName)) groups.unshift({name:groupName, id:(st as any).gid || 0, label: groupName + (typeof (st as any).gid === 'number' ? ` [${(st as any).gid}]` : '')});
            setPropOwners(owners); setPropGroups(groups);
          } catch { setPropOwners([]); setPropGroups([]); }
        } else { setPropOwners([]); setPropGroups([]); }
        setPropMsg('Eigenschaften geladen');
      } catch(e) { setPropMsg(cleanError(e)); }
    };
    void load();
  }, [sftpProps?.entry.path, sftpProps?.side, sftpId]);
  useEffect(() => {
    try { localStorage.setItem(visibleTagsStorageKey, JSON.stringify(visibleTags)); } catch {}
  }, [visibleTags]);
  useEffect(() => {
    if (!syncReady(syncCfg, syncPass)) return;
    const id = window.setInterval(() => autoSync('interval'), 60000);
    return () => window.clearInterval(id);
  }, [syncCfg.enabled, syncCfg.endpoint, syncCfg.account, syncCfg.token, syncPass]);

  function scheduleTerminalFit(id: string, focus = false, _reason = 'layout') {
    const rec = terms.current[id];
    if (!rec) return;
    if (rec.resizeTimer) window.clearTimeout(rec.resizeTimer);
    if (rec.resizeFrame) window.cancelAnimationFrame(rec.resizeFrame);
    rec.resizeTimer = window.setTimeout(() => {
      rec.resizeFrame = window.requestAnimationFrame(() => {
        const current = terms.current[id];
        if (!current) return;
        const rect = current.el.getBoundingClientRect();
        if (rect.width < 40 || rect.height < 40) return;
        try {
          const beforeCols = current.cols || 0;
          const beforeRows = current.rows || 0;
          current.fit.fit();
          const cols = current.term.cols;
          const rows = current.term.rows;
          const sizeChanged = cols > 0 && rows > 0 && (cols !== beforeCols || rows !== beforeRows);
          current.cols = cols;
          current.rows = rows;
          if (sizeChanged) {
            current.resizeSeq = (current.resizeSeq || 0) + 1;
            const resizeSeq = current.resizeSeq;
            void API.ResizeSSH(id, cols, rows).then(() => {
              if (current.resizeSeq === resizeSeq) current.term.refresh(0, current.term.rows - 1);
            }).catch(() => undefined);
          } else {
            current.term.refresh(0, current.term.rows - 1);
          }
          if (focus && id === activeSession) current.term.focus();
        } catch {}
      });
    }, 70);
  }

  const normalizeTerminalPasteText = (text = '') => text.replace(/\r\n?/g, '\n');
  async function writeSSHPasteText(sessionId: string, text: string) {
    const normalized = normalizeTerminalPasteText(text);
    if (!normalized) return;
    const rec = terms.current[sessionId];
    const isMultiline = /\n/.test(normalized);
    if (isMultiline && rec?.bracketedPaste) {
      await API.WriteSSH(sessionId, `\x1b[200~${normalized.replace(/\n/g, '\r')}\x1b[201~`);
      return;
    }
    const payload = isMultiline ? normalized.replace(/\n/g, '\r') : normalized;
    const chars = Array.from(payload);
    for (let i = 0; i < chars.length; i += 256) {
      await API.WriteSSH(sessionId, chars.slice(i, i + 256).join(''));
      if (i + 256 < chars.length) await new Promise(resolve => window.setTimeout(resolve, 8));
    }
  }

  function attachTerm(id: string, el: HTMLDivElement | null) {
    if (!el) return;
    const existing = terms.current[id];
    if (existing?.el === el) { scheduleTerminalFit(id, id === activeSession, 'ref-stable'); return; }
    if (existing) {
      if (existing.resizeTimer) window.clearTimeout(existing.resizeTimer);
      if (existing.resizeFrame) window.cancelAnimationFrame(existing.resizeFrame);
      if (existing.altRefreshTimer) window.clearTimeout(existing.altRefreshTimer);
      if (existing.seqGapTimer) window.clearTimeout(existing.seqGapTimer);
      try { existing.resizeObserver?.disconnect(); } catch {}
      if (existing.contextMenuHandler) existing.el.removeEventListener('contextmenu', existing.contextMenuHandler, {capture:true});
      if (existing.pasteHandler) existing.el.removeEventListener('paste', existing.pasteHandler, {capture:true});
      try { existing.term.dispose(); } catch {}
      delete terms.current[id];
      el.innerHTML = '';
    }
    const fit = new FitAddon();
    const term = new Terminal({ cursorBlink: true, fontFamily: 'JetBrains Mono, Consolas, monospace', fontSize: 13, lineHeight: 1, letterSpacing: 0, customGlyphs: false, theme: terminalTheme(theme) });
    term.loadAddon(fit); term.open(el); term.onData(d => API.WriteSSH(id, d));
    const contextMenuHandler = (e: globalThis.MouseEvent) => openTerminalMenu(e, id);
    const pasteHandler = (e: globalThis.ClipboardEvent) => { const text = e.clipboardData?.getData('text/plain') || ''; if (!text) return; e.preventDefault(); e.stopPropagation(); void writeSSHPasteText(id, text).then(()=>setMsg('In Terminal eingefügt')).catch(err=>setMsg('Einfügen fehlgeschlagen: '+cleanError(err))); };
    el.addEventListener('contextmenu', contextMenuHandler, {capture:true});
    el.addEventListener('paste', pasteHandler, {capture:true});
    const rec: TerminalRecord = { term, fit, el, expectedSeq: 1, seqBuffer: {}, contextMenuHandler, pasteHandler };
    terms.current[id] = rec;
    const pending = pendingTermBuffers.current[id] || [];
    pending.sort((a, b) => a.seq - b.seq).forEach(p => writeSSHPayload(id, p.seq, p.data));
    delete pendingTermBuffers.current[id];
    if ('ResizeObserver' in window) {
      rec.resizeObserver = new ResizeObserver(() => scheduleTerminalFit(id, id === activeSession, 'container-resize'));
      rec.resizeObserver.observe(el);
    }
    terms.current[id] = rec;
    scheduleTerminalFit(id, id === activeSession, 'mount');
    window.setTimeout(() => scheduleTerminalFit(id, id === activeSession, 'mount-settle'), 180);
  }

  async function closeTerminal(id: string, e?: MouseEvent) {
    e?.preventDefault(); e?.stopPropagation();
    try { await API.CloseSSH(id); } catch {}
    const rec = terms.current[id];
    if (rec?.resizeTimer) window.clearTimeout(rec.resizeTimer);
    if (rec?.resizeFrame) window.cancelAnimationFrame(rec.resizeFrame);
    if (rec?.altRefreshTimer) window.clearTimeout(rec.altRefreshTimer);
    if (rec?.seqGapTimer) window.clearTimeout(rec.seqGapTimer);
    try { rec?.resizeObserver?.disconnect(); } catch {}
    if (rec?.contextMenuHandler) rec.el.removeEventListener('contextmenu', rec.contextMenuHandler, {capture:true});
    if (rec?.pasteHandler) rec.el.removeEventListener('paste', rec.pasteHandler, {capture:true});
    try { terms.current[id]?.term.dispose(); } catch {}
    delete terms.current[id];
    delete pendingTermBuffers.current[id];
    setTermCtx(prev => prev?.sessionId === id ? null : prev);
    setSessions(prev => { const next = prev.filter(s => s.id !== id); if (activeSession === id) setActiveSession(next[0]?.id || ''); return next; });
    setMsg('Terminal-Sitzung geschlossen');
  }

  function openTerminalMenu(e: MouseEvent<HTMLDivElement> | globalThis.MouseEvent, sessionId: string) {
    e.preventDefault(); e.stopPropagation();
    terms.current[sessionId]?.term.focus();
    setCtx(null); setSftpCtx(null);
    const menuW = 180, menuH = 128;
    setTermCtx({x:Math.max(8, Math.min(e.clientX, window.innerWidth - menuW)), y:Math.max(8, Math.min(e.clientY, window.innerHeight - menuH)), sessionId});
  }
  async function copyTerminalSelection(sessionId: string) {
    try {
      const selection = terms.current[sessionId]?.term.getSelection() || '';
      if (!selection) { setMsg('Keine Terminal-Auswahl zum Kopieren.'); return; }
      await navigator.clipboard.writeText(selection);
      setTermCtx(null);
      setMsg('Terminal-Auswahl kopiert');
    } catch (e) { setMsg('Kopieren fehlgeschlagen: ' + cleanError(e)); }
  }
  async function pasteTerminalClipboard(sessionId: string) {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) { setMsg('Zwischenablage ist leer.'); return; }
      await writeSSHPasteText(sessionId, text);
      setTermCtx(null);
      setMsg('In Terminal eingefügt');
    } catch (e) { setMsg('Einfügen fehlgeschlagen: ' + cleanError(e)); }
  }

  function beginNewHost() { setDraft(emptyHost); setSelected(''); setEditing(true); setView('terminal'); }
  function beginEditHost(id = selected) { const h = hosts.find(x => x.id === id); if (h) { setSelected(h.id); setDraft({...h, protocol: hostProtocol(h), tags:[...(h.tags||[])]} as any); setEditing(true); setCtx(null); } }
  function setDraftProtocol(protocol: 'ssh'|'rdp') {
    setDraft(prev => protocol === 'rdp'
      ? ({...prev, protocol:'rdp', rdpEnabled:true, rdpPort:(prev as any).rdpPort || 3389, rdpUsername:(prev as any).rdpUsername || prev.username || '', rdpWidth:(prev as any).rdpWidth || 1280, rdpHeight:(prev as any).rdpHeight || 800, rdpKeyboardLayout:rdpKeyboardLayoutOf(prev), port: prev.port === 22 ? 22 : prev.port} as any)
      : ({...prev, protocol:'ssh', rdpEnabled:false, rdpPort:0, rdpUsername:'', rdpPassword:'', rdpDomain:'', rdpWidth:0, rdpHeight:0, rdpScaleMode:'', rdpKeyboardLayout:'', port: prev.port && prev.port !== 3389 ? prev.port : 22} as any));
  }
  function editTags(id = selected) { beginEditHost(id); setMsg('Tags im Host-Editor bearbeiten.'); }
  function hostContext(e: MouseEvent, h: HostConfig) { e.preventDefault(); e.stopPropagation(); setSftpCtx(null); setSelected(h.id); closeHostEditor(); setCtx({x:e.clientX,y:e.clientY,host:h}); }
  async function connectSSHHost(id = selected) { setSelected(id); setCtx(null); return connectSSH(id); }
  async function connectSFTPHost(id = selected) { setSelected(id); setCtx(null); return connectSFTP(id); }
  async function deleteHost(id = selected) {
    const h0 = hosts.find(x => x.id === id);
    if (!id || !window.confirm(`Host wirklich löschen?\n${h0?.name || id}`)) return;
    setSelected(id); setCtx(null); const h = await API.DeleteHost(id); setHosts(h); setSelected(h[0]?.id || ''); closeHostEditor(); setMsg('Host gelöscht'); void autoSync('host deleted');
  }
  async function saveHost() {
    const protocol = hostProtocol(draft);
    const tags = String((draft as any).tagsText ?? draft.tags?.join(',') ?? '').split(',').map(x => x.trim()).filter(Boolean);
    const next = protocol === 'rdp'
      ? ({...draft, protocol:'rdp', rdpEnabled:true, rdpPort:Number((draft as any).rdpPort || 3389), rdpWidth:Number((draft as any).rdpWidth || 1280), rdpHeight:Number((draft as any).rdpHeight || 800), rdpScaleMode:rdpScaleModeOf(draft), rdpKeyboardLayout:rdpKeyboardLayoutOf(draft), port:Number(draft.port || 22), authMode:draft.authMode || 'agent', tags} as any)
      : ({...draft, protocol:'ssh', rdpEnabled:false, rdpPort:0, rdpUsername:'', rdpPassword:'', rdpDomain:'', rdpWidth:0, rdpHeight:0, rdpScaleMode:'smart', rdpKeyboardLayout:'', port:Number(draft.port || 22), tags} as any);
    const h = await API.SaveHost(next as HostConfig); setHosts(h); setSelected(next.id || h[h.length - 1]?.id || ''); closeHostEditor(); setMsg('Host gespeichert'); void autoSync('host saved');
  }
  async function delHost() { if (!selected) return; return deleteHost(selected); }
  const hostKeyDecision = async (hostID: string, err: unknown): Promise<'not-hostkey'|'trusted'|'cancelled'> => {
    const text = cleanError(err);
    const marker = 'SSH_HOST_KEY_UNKNOWN|';
    const idx = text.indexOf(marker);
    if (idx < 0) return 'not-hostkey';
    const [host, fingerprint, path] = text.slice(idx + marker.length).split('|');
    const ok = window.confirm(`Unbekannter SSH Host-Key für ${host || 'Host'}

Fingerprint:
${fingerprint || 'unbekannt'}

Speichern in known_hosts und verbinden?

Pfad: ${path || knownHosts.path || 'known_hosts'}`);
    if (!ok) { setMsg('Verbindung abgebrochen: Host-Key nicht gespeichert.'); return 'cancelled'; }
    if (!fingerprint) throw new Error('Host-Key Fingerprint fehlt; Trust abgebrochen.');
    const r = await API.TrustSSHHost(hostID, fingerprint);
    await loadKnownHosts();
    setMsg(String(r));
    return 'trusted';
  };
  const addSSHSession = (st: SessionState) => {
    setSessions(p => [...p, st]); setActiveSession(st.id); setView('terminal'); setMsg('SSH verbunden');
    setTimeout(() => { const t=terms.current[st.id]; if(t){ t.fit.fit(); t.term.refresh(0, t.term.rows - 1); t.term.focus(); } }, 180);
  };
  async function connectSSH(hostID = selected) {
    if (!hostID) { setMsg('Kein Host ausgewählt'); return; }
    if (connectingSSH) return;
    setConnectingSSH(true); setView('terminal'); setMsg('SSH verbindet…');
    try { const size = estimateInitialPtySize(); addSSHSession(await API.ConnectSSHWithSize(hostID, size.cols, size.rows)); }
    catch (e) {
      try {
        const d = await hostKeyDecision(hostID, e);
        if (d === 'trusted') { const size = estimateInitialPtySize(); addSSHSession(await API.ConnectSSHWithSize(hostID, size.cols, size.rows)); }
        else if (d === 'not-hostkey') setMsg('SSH Fehler: ' + cleanError(e));
      } catch(e2) { setMsg('SSH Fehler: ' + cleanError(e2)); }
    }
    finally { setConnectingSSH(false); }
  }

  function closeRDPRenderStream(id: string) {
    try { rdpRenderStreams.current[id]?.close(); } catch {}
    delete rdpRenderStreams.current[id];
    if (rdpRenderFrameRAF.current[id]) window.cancelAnimationFrame(rdpRenderFrameRAF.current[id]);
    delete rdpRenderFrameRAF.current[id];
    delete rdpRenderFrameQueues.current[id];
    try { rdpRenderers.current[id]?.dispose(); } catch {}
    delete rdpRenderers.current[id];
  }
  async function startRDPRenderStream(id: string, canvas: HTMLCanvasElement) {
    closeRDPRenderStream(id);
    let renderer: RDPWebGLRenderer;
    try {
      renderer = new RDPWebGLRenderer(canvas);
    } catch(e) {
      setMsg('RDP WebGL Fehler: ' + cleanError(e));
      return;
    }
    rdpRenderers.current[id] = renderer;
    const session = rdpSessions.find(s => s.id === id);
    const host = hosts.find(h => h.id === session?.hostId);
    renderer.setSharp(rdpScaleModeOf(host) === 'sharp' || rdpScaleModeOf(host) === 'original');
    try {
      const endpoint = await API.RDPRenderEndpoint(id);
      const ws = new WebSocket(endpoint.url);
      ws.binaryType = 'arraybuffer';
      ws.onmessage = ev => {
        try {
          if (rdpRenderStreams.current[id] !== ws) return;
          const frame = parseRDPBinaryFrame(ev.data as ArrayBuffer);
          const q = rdpRenderFrameQueues.current[id] || [];
          if (isFullRDPFrame(frame)) {
            rdpRenderFrameQueues.current[id] = [frame];
          } else {
            q.push(frame);
            const lastFull = lastFullRDPFrameIndex(q);
            rdpRenderFrameQueues.current[id] = lastFull >= 0 ? q.slice(lastFull) : q;
          }
          if (!rdpRenderFrameRAF.current[id]) {
            rdpRenderFrameRAF.current[id] = window.requestAnimationFrame(() => {
              delete rdpRenderFrameRAF.current[id];
              const frames = rdpRenderFrameQueues.current[id] || [];
              rdpRenderFrameQueues.current[id] = [];
              const lastFull = lastFullRDPFrameIndex(frames);
              const renderFrames = lastFull >= 0 ? frames.slice(lastFull) : frames;
              renderer.presentBatch(renderFrames);
            });
          }
        }
        catch(e) { setMsg('RDP Render Fehler: ' + cleanError(e)); }
      };
      ws.onerror = () => setMsg('RDP Render-Stream Fehler');
      ws.onclose = () => { if (rdpRenderStreams.current[id] === ws) delete rdpRenderStreams.current[id]; };
      rdpRenderStreams.current[id] = ws;
    } catch(e) {
      closeRDPRenderStream(id);
      setMsg('RDP Render-Endpunkt Fehler: ' + cleanError(e));
    }
  }
  function attachRDPCanvas(id: string, el: HTMLCanvasElement | null) {
    if (!el) return;
    rdpCanvases.current[id] = el;
    el.tabIndex = 0;
    if (!rdpRenderStreams.current[id] && !rdpRenderers.current[id]) void startRDPRenderStream(id, el);
  }
  function attachRDPWrap(id: string, el: HTMLDivElement | null) {
    if (!el) {
      delete rdpWraps.current[id];
      try { rdpWrapObservers.current[id]?.disconnect(); } catch {}
      delete rdpWrapObservers.current[id];
      return;
    }
    rdpWraps.current[id] = el;
    if (!rdpWrapObservers.current[id]) {
      const observer = new ResizeObserver(() => scheduleRDPResizeReconnect('pane-resize'));
      observer.observe(el);
      rdpWrapObservers.current[id] = observer;
    }
  }
  function rdpViewerSize(host?: HostConfig): {width:number; height:number} {
    const activeWrap = activeRdp ? rdpWraps.current[activeRdp] : undefined;
    const fallback = document.querySelector('.workspace') as HTMLElement | null;
    const box = activeWrap || fallback;
    const rect = box?.getBoundingClientRect();
    const rawW = Math.floor((rect?.width || Number((host as any)?.rdpWidth || 1280)) - (activeWrap ? 2 : 24));
    const rawH = Math.floor((rect?.height || Number((host as any)?.rdpHeight || 800)) - (activeWrap ? 2 : 88));
    const width = Math.max(640, Math.min(3840, rawW));
    const height = Math.max(480, Math.min(2160, rawH));
    return {width, height};
  }
  function scheduleRDPResizeReconnect(reason = 'resize') {
    if (view !== 'rdp' || !activeRdp) return;
    const session = rdpSessions.find(x => x.id === activeRdp);
    if (!session || session.status !== 'connected') return;
    const host = hosts.find(x => x.id === session.hostId);
    const scaleMode = rdpScaleModeOf(host);
    if (scaleMode === 'fit' || scaleMode === 'original') return;
    if (rdpResizeTimer.current) window.clearTimeout(rdpResizeTimer.current);
    rdpResizeTimer.current = window.setTimeout(async () => {
      const current = rdpSessions.find(x => x.id === activeRdp);
      if (!current || current.status !== 'connected') return;
      const host = hosts.find(x => x.id === current.hostId);
      const size = rdpViewerSize(host);
      const nextKey = `${size.width}x${size.height}`;
      const oldKey = rdpConnectSizes.current[current.id];
      const [oldW, oldH] = (oldKey || '').split('x').map(Number);
      if (oldKey && Math.abs((oldW || 0) - size.width) < 48 && Math.abs((oldH || 0) - size.height) < 48) return;
      try {
        setMsg(`RDP passt Auflösung an: ${size.width}×${size.height}`);
        await API.CloseRDP(current.id);
        delete rdpCanvases.current[current.id];
        closeRDPRenderStream(current.id);
        delete rdpConnectSizes.current[current.id];
        setRdpSessions(prev => prev.filter(x => x.id !== current.id));
        const st = await API.ConnectRDP(current.hostId, size.width, size.height);
        rdpConnectSizes.current[st.id] = nextKey;
        setRdpSessions(prev => [...prev.filter(x => x.id !== current.id), st]);
        setActiveRdp(st.id);
        setMsg(`RDP-Auflösung angepasst (${size.width}×${size.height})`);
      } catch(e) {
        setMsg('RDP Resize Fehler: '+cleanError(e));
      }
    }, reason === 'window-resize' ? 700 : 500);
  }
  const rdpPoint = (canvas: HTMLCanvasElement, e: {clientX:number; clientY:number}) => {
    const r = canvas.getBoundingClientRect();
    const x = Math.max(0, Math.min(canvas.width, Math.round((e.clientX - r.left) * (canvas.width / Math.max(1, r.width)))));
    const y = Math.max(0, Math.min(canvas.height, Math.round((e.clientY - r.top) * (canvas.height / Math.max(1, r.height)))));
    return {x,y};
  };
  async function connectRDP(hostID = selected) {
    if (!hostID) { setMsg('Kein Host ausgewählt'); return; }
    if (rdpOpeningHosts.current.has(hostID)) return;
    if (connectingRDP) return;
    rdpOpeningHosts.current.add(hostID);
    setConnectingRDP(true); setView('rdp'); setMsg('RDP verbindet…');
    try {
      const h = hosts.find(x => x.id === hostID);
      const existing = rdpSessions.find(x => x.hostId === hostID);
      if (existing) await closeRDP(existing.id);
      await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
      const scaleMode = rdpScaleModeOf(h);
      const size = (scaleMode === 'fit' || scaleMode === 'original') ? {width:Number((h as any)?.rdpWidth || 1280), height:Number((h as any)?.rdpHeight || 800)} : rdpViewerSize(h);
      const st = await API.ConnectRDP(hostID, size.width, size.height);
      rdpConnectSizes.current[st.id] = `${size.width}x${size.height}`;
      setRdpSessions(prev => prev.some(x=>x.id===st.id) ? prev : [...prev, st]);
      setActiveRdp(st.id); setMsg('RDP-Verbindung gestartet');
    } catch(e) { setMsg('RDP Fehler: '+cleanError(e)); }
    finally { rdpOpeningHosts.current.delete(hostID); setConnectingRDP(false); }
  }
  async function connectRDPHost(id = selected) { setSelected(id); setCtx(null); return connectRDP(id); }
  function dropRDPClientSession(id: string) {
    if (rdpMouseMoves.current[id]?.frame) cancelAnimationFrame(rdpMouseMoves.current[id].frame!);
    if (rdpMouseMoves.current[id]?.timer) window.clearTimeout(rdpMouseMoves.current[id].timer!);
    delete rdpCanvases.current[id];
    closeRDPRenderStream(id);
    delete rdpMouseMoves.current[id];
    delete rdpPressedKeys.current[id];
    delete rdpSuppressedKeyUps.current[id];
    delete rdpConnectSizes.current[id];
    try { rdpWrapObservers.current[id]?.disconnect(); } catch {}
    delete rdpWrapObservers.current[id];
    delete rdpWraps.current[id];
    setRdpSessions(prev => { const next = prev.filter(s => s.id !== id); setActiveRdp(current => current === id ? (next[0]?.id || '') : current); return next; });
  }
  async function closeRDP(id: string, e?: MouseEvent) {
    e?.preventDefault(); e?.stopPropagation();
    try { await API.CloseRDP(id); } catch {}
    dropRDPClientSession(id);
    setMsg('RDP-Sitzung geschlossen');
  }
  function rdpMissingOrSet(prefix: string, id: string, e: unknown) {
    const err = cleanError(e);
    if (err.includes('RDP-Session nicht gefunden')) { dropRDPClientSession(id); setMsg('RDP-Sitzung nicht mehr aktiv'); return; }
    setMsg(prefix + err);
  }
  function rdpMouse(id: string, action: string, ev: MouseEvent<HTMLCanvasElement>, delta = 0) {
    const p = rdpPoint(ev.currentTarget, ev);
    if (action === 'rightdown') void prepareRDPClipboardText(id).catch(()=>{});
    void API.RDPMouse(id, action, p.x, p.y, delta).catch(e=>rdpMissingOrSet('RDP Maus: ', id, e));
  }
  function rdpMouseMove(id: string, ev: MouseEvent<HTMLCanvasElement>) {
    const p = rdpPoint(ev.currentTarget, ev);
    const rec = rdpMouseMoves.current[id] || {x:p.x, y:p.y};
    rec.x = p.x;
    rec.y = p.y;
    rdpMouseMoves.current[id] = rec;
    if (rec.frame) return;
    const now = performance.now();
    const wait = Math.max(0, 16 - (now - (rec.lastSent || 0)));
    const send = () => {
      rec.frame = undefined;
      rec.timer = undefined;
      rec.lastSent = performance.now();
      API.RDPMouse(id, 'move', rec.x, rec.y, 0).catch(e=>rdpMissingOrSet('RDP Maus: ', id, e));
    };
    if (wait > 0) {
      if (!rec.timer) rec.timer = window.setTimeout(() => { rec.timer = undefined; rec.frame = requestAnimationFrame(send); }, wait);
    } else {
      rec.frame = requestAnimationFrame(send);
    }
  }
  const fileToBase64 = async (file: File): Promise<string> => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let out = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return window.btoa(out);
  };
  async function stageRDPClipboardFiles(id: string, filesLike: FileList | File[] | ExternalDropItem[]) {
    const raw: any[] = [];
    const list = filesLike as any;
    for (let i = 0; i < (list?.length || 0); i++) raw.push(list[i]);
    const files: ExternalDropItem[] = raw.map((item: any) => {
      if (item?.kind) return item as ExternalDropItem;
      const file = item as File;
      return {relPath: cleanRemoteRel((file as any).webkitRelativePath || file.name || 'clipboard-file'), file, kind:'file' as const};
    }).filter(f => f.kind === 'directory' || (!!f.file && f.file.size >= 0));
    if (!files.length) return false;
    const total = files.reduce((sum, f) => sum + (f.file?.size || 0), 0);
    if (files.length > 512) throw new Error('RDP-Dateiablage: maximal 512 Einträge.');
    if (total > 128 * 1024 * 1024) throw new Error('RDP-Dateiablage: maximal 128 MB.');
    const payload: {name:string; base64:string; isDirectory?:boolean}[] = [];
    for (const f of files) {
      if (f.kind === 'directory') payload.push({name: f.relPath || 'Ordner', base64: '', isDirectory: true});
      else if (f.file) payload.push({name: f.relPath || f.file.name || 'clipboard-file', base64: await fileToBase64(f.file)});
    }
    await API.RDPStageClipboardFiles(id, payload);
    setMsg(`${files.length} Element(e) werden per RDP eingefügt…`);
    return true;
  }
  async function collectRDPClipboardFiles(dt: DataTransfer): Promise<ExternalDropItem[]> {
    const items = await collectExternalDropFiles(dt);
    return items.filter(f => f.kind === 'directory' || !!f.file);
  }
  async function prepareRDPClipboardText(id: string, text?: string) {
    let payload = typeof text === 'string' ? text : '';
    if (!payload) {
      try { payload = await navigator.clipboard.readText(); } catch {}
    }
    if (!payload) {
      payload = await API.RDPClipboardText();
    }
    if (!payload) return false;
    await API.RDPStageClipboardText(id, payload);
    return true;
  }
  async function sendRDPRemotePasteShortcut(id: string, keyCode = 'KeyV') {
    await API.RDPKey(id, 'ControlLeft', true);
    await API.RDPKey(id, keyCode, true);
    await API.RDPKey(id, keyCode, false);
    await API.RDPKey(id, 'ControlLeft', false);
  }
  async function pasteRDPText(id: string, text?: string) {
    const staged = await prepareRDPClipboardText(id, text);
    if (!staged) return;
    await sendRDPRemotePasteShortcut(id);
    setMsg('RDP-Clipboard bereitgestellt und Remote-Einfügen gesendet');
  }
  function rdpPaste(id: string, ev: ReactClipboardEvent<HTMLCanvasElement>) {
    ev.preventDefault(); ev.stopPropagation();
    const files = ev.clipboardData.files;
    if (files && files.length) {
      void (async () => { if (await stageRDPClipboardFiles(id, files)) await sendRDPRemotePasteShortcut(id); })().catch(e=>rdpMissingOrSet('RDP Datei-Paste: ', id, e));
      return;
    }
    const text = ev.clipboardData.getData('text/plain');
    void pasteRDPText(id, text).catch(e=>rdpMissingOrSet('RDP Paste: ', id, e));
  }
  function rdpFileDrop(id: string, ev: DragEvent<HTMLCanvasElement>) {
    ev.preventDefault(); ev.stopPropagation();
    if (!ev.dataTransfer) return;
    void (async () => { const files = await collectRDPClipboardFiles(ev.dataTransfer); if (await stageRDPClipboardFiles(id, files)) await sendRDPRemotePasteShortcut(id); })().catch(e=>rdpMissingOrSet('RDP Datei-Drop: ', id, e));
  }
  function rdpKey(id: string, ev: ReactKeyboardEvent<HTMLCanvasElement>, down: boolean) {
    ev.preventDefault(); ev.stopPropagation();
    const pressed = rdpPressedKeys.current[id] || new Set<string>();
    rdpPressedKeys.current[id] = pressed;
    const suppressed = rdpSuppressedKeyUps.current[id] || new Set<string>();
    rdpSuppressedKeyUps.current[id] = suppressed;
    if (!down && suppressed.has(ev.code)) {
      suppressed.delete(ev.code);
      pressed.delete(ev.code);
      return;
    }
    if (down) pressed.add(ev.code); else pressed.delete(ev.code);
    if (down && (ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'v') {
      suppressed.add(ev.code);
      void (async () => {
        const staged = await prepareRDPClipboardText(id);
        if (!staged) return;
        await API.RDPKey(id, ev.code, true);
        await API.RDPKey(id, ev.code, false);
        setMsg('RDP-Clipboard bereitgestellt und Remote-Einfügen gesendet');
      })().catch(e=>rdpMissingOrSet('RDP Paste: ', id, e));
      return;
    }
    void API.RDPKey(id, ev.code, down).catch(e=>rdpMissingOrSet('RDP Tastatur: ', id, e));
  }
  function resetSFTPState() {
    setSftpId(''); setActiveSftp(''); setRemote([]); setRemotePath('/'); setSelectedRemote(''); setSftpCtx(null); setSftpProps(null);
    if (fileEditor?.side === 'remote') setFileEditor(null);
  }
  function switchSftpTab(tab: SftpTab) {
    setActiveSftp(tab.id); setSftpId(tab.id); setRemotePath(tab.remotePath || '/'); setRemote(tab.remote || []); setSelectedRemote(tab.selectedRemote || '');
    setSftpCtx(null); setSftpProps(null); if (fileEditor?.side === 'remote') setFileEditor(null);
    setView('sftp'); setMsg(`SFTP aktiv: ${tab.title}`);
  }
  async function closeSftpTab(id: string, e?: MouseEvent) {
    e?.preventDefault(); e?.stopPropagation();
    try { await API.CloseSFTP(id); } catch {}
    const next = sftpTabs.filter(t => t.id !== id);
    setSftpTabs(next);
    if (id === sftpId || id === activeSftp) {
      const fallback = next[0];
      if (fallback) switchSftpTab(fallback); else resetSFTPState();
    }
    setMsg(next.length ? 'SFTP-Tab geschlossen' : 'SFTP geschlossen');
  }
  async function openSFTPConnection(hostID: string) {
    const r = await API.ConnectSFTP(hostID);
    try {
      const ls = await API.ListSFTP(r.id, r.home || '/');
      const h = hosts.find(x => x.id === hostID);
      const tab: SftpTab = {id:r.id, hostID, title:h?.name || h?.address || 'SFTP', remotePath:r.home || '/', remote:ls, selectedRemote:''};
      setSftpTabs(prev => [...prev, tab]);
      setActiveSftp(r.id); setSftpId(r.id); setRemotePath(tab.remotePath); setView('sftp'); setRemote(ls); setSelectedRemote(''); setMsg('SFTP verbunden');
    } catch (e) {
      try { await API.CloseSFTP(r.id); } catch {}
      throw e;
    }
  }
  async function connectSFTP(hostID = selected) {
    if (!hostID) { setMsg('Kein Host ausgewählt'); return; }
    if (connectingSFTP) return;
    setConnectingSFTP(true); setMsg('SFTP verbindet…');
    try { await openSFTPConnection(hostID); }
    catch (e) {
      try {
        const d = await hostKeyDecision(hostID, e);
        if (d === 'trusted') await openSFTPConnection(hostID);
        else if (d === 'not-hostkey') setMsg('SFTP Fehler: ' + cleanError(e));
      } catch(e2) { setMsg('SFTP Fehler: ' + cleanError(e2)); }
    }
    finally { setConnectingSFTP(false); }
  }
  function openSftpMenu(e: MouseEvent, side: 'local'|'remote', entry?: FileEntry) {
    e.preventDefault(); e.stopPropagation();
    if (side === 'local' && entry) setSelectedLocal(entry.path);
    if (side === 'remote' && entry) setSelectedRemote(entry.path);
    const menuW = 250, menuH = entry ? 500 : 220;
    setSftpCtx({x:Math.max(8, Math.min(e.clientX, window.innerWidth - menuW)), y:Math.max(8, Math.min(e.clientY, window.innerHeight - menuH)), side, entry});
  }
  function startSftpDrag(e: DragEvent, side: 'local'|'remote', entry: FileEntry) {
    const payload = {side, path: entry.path, name: entry.name, type: entry.type};
    setSftpDrag(payload);
    setSftpDropSide(null);
    e.dataTransfer.effectAllowed = 'copy';
    e.dataTransfer.setData('application/x-ssh-vault2-sftp', JSON.stringify(payload));
    e.dataTransfer.setData('text/plain', `${side}:${entry.path}`);
    setMsg(`Drag & Drop: ${entry.name} ziehen → ${side === 'local' ? 'Remote Upload' : 'Lokal Download'}`);
  }
  function readSftpDrag(e: DragEvent) {
    const raw = e.dataTransfer.getData('application/x-ssh-vault2-sftp');
    if (raw) { try { return JSON.parse(raw) as {side:'local'|'remote',path:string,name:string,type:string}; } catch {} }
    return sftpDrag;
  }
  const hasExternalDropFiles = (e: DragEvent) => !sftpDrag && Array.from(e.dataTransfer.types || []).includes('Files');
  const remoteDirOf = (p: string) => parentRemote(p);
  const cleanRemoteRel = (p = '') => p.replace(/\\/g, '/').replace(/^\/+/, '').split('/').filter(Boolean).join('/');
  const joinRemoteRel = (dir: string, rel: string) => cleanRemoteRel(rel).split('/').reduce((acc, part) => joinRemote(acc, part), dir || '/');
  const fileChunkToBase64 = async (blob: Blob) => {
    const buf = await blob.arrayBuffer();
    let bin = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  };
  async function uploadDroppedFile(targetPath: string, file: File) {
    const chunk = 768 * 1024;
    const uploadID = crypto.randomUUID();
    for (let off = 0; off < file.size; off += chunk) {
      const data = await fileChunkToBase64(file.slice(off, Math.min(file.size, off + chunk)));
      await API.UploadSFTPChunk(sftpId, uploadID, targetPath, off, data);
    }
    await API.UploadSFTPChunk(sftpId, uploadID, targetPath, file.size, '');
  }
  async function collectExternalDropFiles(dt: DataTransfer): Promise<ExternalDropItem[]> {
    const out: ExternalDropItem[] = [];
    const readEntries = (reader: any) => new Promise<any[]>((resolve, reject) => reader.readEntries(resolve, reject));
    const walkEntry = async (entry: any, prefix = '') => {
      const rel = cleanRemoteRel(prefix ? `${prefix}/${entry.name}` : entry.name);
      if (entry.isDirectory) {
        out.push({relPath: rel, kind:'directory'});
        const reader = entry.createReader();
        while (true) {
          const batch = await readEntries(reader);
          if (!batch.length) break;
          for (const child of batch) await walkEntry(child, rel);
        }
      } else if (entry.isFile) {
        const file: File = await new Promise((resolve, reject) => entry.file(resolve, reject));
        out.push({relPath: rel || file.name, file, kind:'file'});
      }
    };
    const items = Array.from(dt.items || []);
    for (const item of items) {
      const entry = (item as any).webkitGetAsEntry?.();
      if (entry) await walkEntry(entry);
      else { const f = item.getAsFile?.(); if (f) out.push({relPath: cleanRemoteRel((f as any).webkitRelativePath || f.name), file:f, kind:'file'}); }
    }
    if (!out.length) for (const f of Array.from(dt.files || [])) out.push({relPath: cleanRemoteRel((f as any).webkitRelativePath || f.name), file:f, kind:'file'});
    return out;
  }
  async function uploadExternalDrop(e: DragEvent, targetEntry?: FileEntry) {
    if (!sftpId) throw new Error('SFTP nicht verbunden');
    const target = targetEntry?.type === 'directory' ? targetEntry.path : remotePath;
    const files = await collectExternalDropFiles(e.dataTransfer);
    if (!files.length) throw new Error('Keine externen Dateien erkannt');
    setMsg(`Explorer-Drop: ${files.length} Element(e) → ${target}`);
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const rel = cleanRemoteRel(f.relPath || f.file?.name || 'upload');
      const remoteTarget = joinRemoteRel(target, rel);
      if (f.kind === 'directory') {
        setMsg(`Explorer-Drop Ordner ${i + 1}/${files.length}: ${rel}`);
        await API.MkdirAllSFTP(sftpId, remoteTarget);
        continue;
      }
      if (!f.file) continue;
      setMsg(`Explorer-Drop Upload ${i + 1}/${files.length}: ${rel}`);
      await API.MkdirAllSFTP(sftpId, remoteDirOf(remoteTarget));
      await uploadDroppedFile(remoteTarget, f.file);
    }
    await refreshRemote();
    setMsg(files.length === 1 ? 'Explorer-Drop Upload abgeschlossen' : `Explorer-Drop Upload abgeschlossen: ${files.length} Elemente`);
  }
  function allowSftpDrop(e: DragEvent, targetSide: 'local'|'remote') {
    const external = targetSide === 'remote' && hasExternalDropFiles(e) && !!sftpId;
    const p = sftpDrag;
    if (!external && (!p || p.side === targetSide)) return false;
    if (targetSide === 'remote' && !sftpId) return false;
    e.preventDefault(); e.stopPropagation();
    e.dataTransfer.dropEffect = 'copy';
    setSftpDropSide(targetSide);
    return true;
  }
  async function dropSftp(e: DragEvent, targetSide: 'local'|'remote', targetEntry?: FileEntry) {
    e.preventDefault(); e.stopPropagation();
    const external = targetSide === 'remote' && hasExternalDropFiles(e);
    const payload = external ? null : readSftpDrag(e);
    setSftpDropSide(null);
    setSftpDrag(null);
    try {
      if (external) { await uploadExternalDrop(e, targetEntry); return; }
      if (!payload) { setMsg('Drag & Drop: keine Datei erkannt'); return; }
      if (payload.side === targetSide) { setMsg('Drag & Drop nur zwischen Lokal und Remote'); return; }
      if (targetSide === 'remote') {
        if (!sftpId) throw new Error('SFTP nicht verbunden');
        const target = targetEntry?.type === 'directory' ? targetEntry.path : remotePath;
        setMsg(`Upload per Drag & Drop: ${payload.name} → ${target}`);
        await API.UploadSFTP(sftpId, payload.path, target);
        await refreshRemote();
        setMsg(payload.type === 'directory' ? 'Ordner-Upload per Drag & Drop abgeschlossen' : 'Upload per Drag & Drop abgeschlossen');
      } else {
        const target = targetEntry?.type === 'directory' ? targetEntry.path : localPath;
        setMsg(`Download per Drag & Drop: ${payload.name} → ${target}`);
        await API.DownloadSFTP(sftpId, payload.path, target);
        await refreshLocal();
        setMsg(payload.type === 'directory' ? 'Ordner-Download per Drag & Drop abgeschlossen' : 'Download per Drag & Drop abgeschlossen');
      }
    } catch(err) { setMsg('Drag & Drop Fehler: '+cleanError(err)); }
  }

  async function openFileEditor(side: 'local'|'remote', entry: FileEntry) {
    if (entry.type === 'directory') { side === 'local' ? await refreshLocal(entry.path) : await refreshRemote(entry.path); return; }
    try {
      setMsg(`${side === 'remote' ? 'Remote' : 'Lokale'} Datei wird geöffnet: ${entry.name}`);
      const r = side === 'remote' ? await API.ReadTextSFTP(sftpId, entry.path) : await API.ReadTextLocal(entry.path);
      setFileEditor({side, path:r.path, name:r.name || entry.name, content:r.content, original:r.content, status: side === 'remote' ? 'Remote-Datei geladen. Speichern lädt automatisch per SFTP hoch.' : 'Lokale Datei geladen.', saving:false});
      setMsg(`${entry.name} im Editor geöffnet`);
    } catch(e) { setMsg('Editor öffnen fehlgeschlagen: '+cleanError(e)); }
  }
  async function saveFileEditor() {
    if (!fileEditor) return;
    try {
      setFileEditor({...fileEditor, saving:true, status:'Speichere…'});
      if (fileEditor.side === 'remote') { await API.WriteTextSFTP(sftpId, fileEditor.path, fileEditor.content); await refreshRemote(parentRemote(fileEditor.path)); }
      else { await API.WriteTextLocal(fileEditor.path, fileEditor.content); await refreshLocal(parentLocal(fileEditor.path)); }
      setFileEditor({...fileEditor, original:fileEditor.content, saving:false, status:fileEditor.side === 'remote' ? 'Gespeichert und automatisch per SFTP hochgeladen.' : 'Lokal gespeichert.'});
      setMsg(fileEditor.side === 'remote' ? `Gespeichert + hochgeladen: ${fileEditor.name}` : `Gespeichert: ${fileEditor.name}`);
    } catch(e) { setFileEditor({...fileEditor, saving:false, status:'Speichern fehlgeschlagen: '+cleanError(e)}); setMsg('Editor speichern fehlgeschlagen: '+cleanError(e)); }
  }

  async function sftpAction(kind: 'open'|'transfer'|'mkdir'|'rename'|'delete'|'refresh'|'copyPath'|'properties') {
    const c = sftpCtx; if (!c) return;
    setSftpCtx(null);
    try {
      const entry = c.entry;
      if (kind === 'refresh') { c.side === 'local' ? await refreshLocal() : await refreshRemote(); setMsg('SFTP Liste aktualisiert'); return; }
      if (kind === 'copyPath') { await navigator.clipboard?.writeText(entry?.path || (c.side === 'local' ? localPath : remotePath)); setMsg('Pfad kopiert'); return; }
      if (kind === 'open') {
        if (!entry) return;
        await openFileEditor(c.side, entry);
        return;
      }
      if (kind === 'transfer') {
        if (!entry) return;
        if (c.side === 'local') { if (!sftpId) throw new Error('SFTP nicht verbunden'); await API.UploadSFTP(sftpId, entry.path, remotePath); await refreshRemote(); setMsg(entry.type === 'directory' ? 'Ordner-Upload abgeschlossen' : 'Upload abgeschlossen'); }
        else { await API.DownloadSFTP(sftpId, entry.path, localPath); await refreshLocal(); setMsg(entry.type === 'directory' ? 'Ordner-Download abgeschlossen' : 'Download abgeschlossen'); }
        return;
      }
      if (kind === 'mkdir') {
        const name = window.prompt('Neuer Ordner:', 'Neuer Ordner'); if (!name) return;
        if (c.side === 'local') { await API.LocalMkdir(joinLocal(localPath, name)); await refreshLocal(); }
        else { if (!sftpId) throw new Error('SFTP nicht verbunden'); await API.MkdirSFTP(sftpId, joinRemote(remotePath, name)); await refreshRemote(); }
        setMsg('Ordner angelegt'); return;
      }
      if (!entry) return;
      if (kind === 'rename') {
        const rawName = window.prompt('Neuer Name:', entry.name); if (!rawName) return;
        const name = safeChildName(rawName);
        if (!name) { setMsg('Ungültiger Name: keine Pfade, . oder .. erlaubt'); return; }
        if (name === entry.name) return;
        if (c.side === 'local') { await API.RenameLocal(entry.path, name); await refreshLocal(); }
        else { await API.RenameSFTP(sftpId, entry.path, name); await refreshRemote(); }
        setMsg('Umbenannt'); return;
      }
      if (kind === 'properties') { setSftpProps({side:c.side, entry}); return; }
      if (kind === 'delete') {
        if (!window.confirm(`${entry.type === 'directory' ? 'Ordner' : 'Datei'} löschen?\n${entry.path}`)) return;
        if (c.side === 'local') { await API.RemoveLocal(entry.path); await refreshLocal(); }
        else { await API.RemoveSFTP(sftpId, entry.path); await refreshRemote(); }
        setMsg('Gelöscht'); return;
      }
    } catch(e) { setMsg(cleanError(e)); }
  }



  async function calculatePropSize() {
    const p = sftpProps, e = propEntry || sftpProps?.entry; if (!p || !e) return;
    try { setPropMsg('Größe wird berechnet…'); const n = p.side === 'remote' ? await API.PropertiesSizeSFTP(sftpId, e.path) : await API.PropertiesSizeLocal(e.path); setPropSize(n); setPropMsg('Größe berechnet'); }
    catch(err) { setPropMsg(cleanError(err)); }
  }
  async function calculateChecksum(algo: string) {
    const p = sftpProps, e = propEntry || sftpProps?.entry; if (!p || !e) return;
    if (e.type === 'directory') { setPropChecksum('Ordner haben keine einzelne Prüfsumme.'); return; }
    try { setPropMsg(`${algo} wird berechnet…`); const sum = p.side === 'remote' ? await API.PropertiesChecksumSFTP(sftpId, e.path, algo) : await API.PropertiesChecksumLocal(e.path, algo); setPropChecksum(sum); setPropMsg('Prüfsumme berechnet'); }
    catch(err) { setPropMsg(cleanError(err)); }
  }
  async function applyProperties() {
    const p = sftpProps, e = propEntry || sftpProps?.entry; if (!p || !e) return;
    try {
      const octal = propDirX && e.type === 'directory' ? octalWithDirX(propOctal) : octalNorm(propOctal);
      setPropMsg('Wende Eigenschaften an…');
      if (p.side === 'remote') { await API.PropertiesChmodSFTP(sftpId, e.path, octal, propRecursive); if (propOwner !== ((e as any).owner || '') || propGroup !== ((e as any).group || '')) await API.PropertiesChownSFTP(sftpId, e.path, propOwner, propGroup, propRecursive); await refreshRemote(); const st = await API.PropertiesStatSFTP(sftpId, e.path); setPropEntry(st); const reported = modeToOctal(st.mode) || octal; setPropOctal(reported); if (reported !== octal) { setPropMsg(`Server meldet weiterhin ${reported} statt ${octal}. Windows-SFTP kann chmod ignorieren.`); return; } }
      else { await API.PropertiesChmodLocal(e.path, octal, propRecursive); await refreshLocal(); const st = await API.PropertiesLocalStat(e.path); setPropEntry(st); setPropOctal(modeToOctal(st.mode) || octal); }
      setPropMsg('Eigenschaften gespeichert');
    } catch(err) { setPropMsg(cleanError(err)); }
  }
  function showPropertiesHelp() {
    window.alert('Eigenschaften:\n\n• Berechnen: ermittelt Datei-/Ordnergröße rekursiv.\n• Prüfsumme: MD5/SHA1/SHA256 nur für Dateien.\n• Rechte: R/W/X und Oktal ändern sich gegenseitig. OK speichert chmod.\n• Eigentümer/Gruppe: nutzt Server-Namen, wenn der SSH/SFTP-Server stat/getent/chown unterstützt. Windows-SFTP liefert oft nur eingeschränkte Unix-Metadaten.\n• Rekursiv: wendet Rechte/Besitzer auf Unterordner und Dateien an.');
  }

  function clearDraftSecrets() {
    setDraft(prev => ({...prev, password:'', privateKey:'', rdpPassword:''} as any));
    setVaultDraft(prev => ({...prev, password:'', privateKey:''}));
  }
  function clearFileEditorSecrets() {
    setFileEditor(null);
  }
  function closeFileEditor() {
    if (!fileEditor) return;
    if (fileEditor.content !== fileEditor.original && !window.confirm('Ungespeicherte Änderungen verwerfen?')) return;
    clearFileEditorSecrets();
  }
  function closeHostEditor() {
    clearDraftSecrets();
    setEditing(false);
  }
  function setWorkspaceView(next: typeof view) {
    if (next !== view) clearDraftSecrets();
    setView(next);
  }
  function beginNewVault() { setVaultDraft(emptyVault); setSelectedVault(''); setView('vault'); }
  function editVault(id: string) { const v = vault.find(x=>x.id===id); if (v) { setSelectedVault(id); setVaultDraft(scrubVaultCredential(v)); setView('vault'); } }
  async function saveVaultEntry() {
    try { const v = (await API.SaveVault(vaultDraft)).map(scrubVaultCredential); setVault(v); const id = vaultDraft.id || v[v.length - 1]?.id || ''; setSelectedVault(id); setVaultDraft(emptyVault); setMsg('Vault-Anmeldung gespeichert'); void autoSync('vault saved'); }
    catch(e) { setMsg('Vault Fehler: '+cleanError(e)); }
  }
  async function deleteVaultEntry(id = selectedVault) {
    if (!id) return;
    const v0 = vault.find(x => x.id === id);
    if (!window.confirm(`Vault-Anmeldung wirklich löschen?\n${v0?.name || id}`)) return;
    try { const v = (await API.DeleteVault(id)).map(scrubVaultCredential); setVault(v); setSelectedVault(v[0]?.id || ''); if (vaultDraft.id === id) setVaultDraft(emptyVault); setMsg('Vault-Anmeldung gelöscht'); void autoSync('vault deleted'); }
    catch(e) { setMsg('Vault Fehler: '+cleanError(e)); }
  }
  async function importVaultKeyFile() {
    try {
      if (!vaultDraft.keyPath) throw new Error('Key-Pfad fehlt');
      let id = vaultDraft.id;
      if (!id) {
        const saved = (await API.SaveVault(vaultDraft)).map(scrubVaultCredential);
        setVault(saved);
        id = saved[saved.length - 1]?.id || '';
        setSelectedVault(id);
      }
      if (!id) throw new Error('Vault-Eintrag konnte nicht gespeichert werden');
      const res = await API.ImportVaultKeyFile(id, vaultDraft.keyPath);
      const v = (await API.ListVault()).map(scrubVaultCredential);
      setVault(v);
      const savedEntry = v.find(x => x.id === id);
      setVaultDraft(savedEntry ? scrubVaultCredential(savedEntry) : emptyVault);
      setMsg(res.message || 'Key-Datei backendseitig in Vault übernommen — Inhalt wird verschlüsselt gespeichert.');
      void autoSync('vault key imported');
    } catch(e) { setMsg('Key-Import Fehler: '+cleanError(e)); }
  }

  async function checkUpdatesOnStartup(appInfo: AppInfo) {
    setUpdateStatus('checking');
    try {
      const r = await API.ServerReleases();
      setRelease(r);
      const versions = compatibleVersionsFor(r, appInfo);
      const v = versions[0]?.version || '';
      setSelectedVersion(v);
      setUpdateAvailableVersion(v);
      setUpdateStatus(v ? 'available' : 'current');
    } catch { setUpdateStatus('error'); }
  }
  async function checkUpdates() {
    setMsg('Updates prüfen…'); setUpdateStatus('checking');
    try {
      const r = await API.ServerReleases();
      setRelease(r);
      const versions = compatibleVersions(r);
      const v = versions[0]?.version || '';
      setSelectedVersion(v);
      setUpdateAvailableVersion(v);
      setUpdateStatus(v ? 'available' : 'current');
      setMsg('Updates geladen');
    }
    catch(e) { setUpdateStatus('error'); setMsg('Update Fehler: '+cleanError(e)); }
  }
  async function installSelectedUpdate() {
    if (!release) { setMsg('Bitte zuerst Updates prüfen.'); return; }
    const asset = selectedCompatibleAsset();
    if (!selectedVersion || !asset) { setMsg('Keine Version/kein Installer ausgewählt.'); return; }
    if (!semverGreater(selectedVersion, info?.version || '0.0.0')) { setMsg('Nur neuere Versionen können installiert werden. Downgrades sind blockiert.'); return; }
    try { setInstallingUpdate(true); setMsg(`Version ${info?.version} → ${selectedVersion} wird installiert…`); await API.InstallUpdate(asset); }
    catch(e) { setInstallingUpdate(false); setMsg('Version installieren fehlgeschlagen: '+cleanError(e)); }
  }
  async function refreshLocalVaultStatus() {
    try { const st = await API.LocalVaultStatus(); setLocalVault(st); setLocalVaultMsg(st.message || 'Lokaler Tresorstatus geladen.'); if ((st.configured && !st.unlocked) || st.plaintextSecrets > 0) setShowLocalVaultPrompt(true); return st; }
    catch(e) { setLocalVaultMsg(cleanError(e)); }
  }
  async function unlockLocalVault() {
    try {
      const st = await API.LocalVaultUnlock(localVaultPass);
      setLocalVault(st);
      setLocalVaultMsg(st.message || 'Lokaler Tresor entsperrt.');
      await reloadHosts();
      await reloadVault();
      const c = await API.GetSyncConfig();
      syncCfgRef.current = c;
      syncPassRef.current = '';
      setSyncCfg(c);
      setSyncPass('');
      if (st.plaintextSecrets === 0) setShowLocalVaultPrompt(false);
      if (syncReady(c, '')) void autoSync('vault-unlock');
      return st;
    }
    catch(e) { setLocalVaultMsg(cleanError(e)); }
    finally { setLocalVaultPass(''); }
  }
  async function encryptLocalVaultExisting() {
    try {
      const st = await API.LocalVaultEncryptExisting(localVaultPass);
      setLocalVault(st);
      setLocalVaultMsg('Lokale Plaintext-Secrets verschlüsselt.');
      await reloadHosts();
      await reloadVault();
      const c = await API.GetSyncConfig();
      syncCfgRef.current = c;
      syncPassRef.current = '';
      setSyncCfg(c);
      setSyncPass('');
      setShowLocalVaultPrompt(false);
      if (syncReady(c, '')) void autoSync('vault-unlock');
      return st;
    }
    catch(e) { setLocalVaultMsg(cleanError(e)); }
    finally { setLocalVaultPass(''); }
  }
  async function lockLocalVault() {
    try { const st = await API.LocalVaultLock(); setLocalVault(st); setLocalVaultPass(''); syncPassRef.current = ''; setSyncPass(''); clearDraftSecrets(); clearFileEditorSecrets(); setLocalVaultMsg(st.message || 'Lokaler Tresor gesperrt.'); await reloadHosts(); await reloadVault(); const c = await API.GetSyncConfig(); setSyncCfg(c); if ((st.configured && !st.unlocked) || st.plaintextSecrets > 0) setShowLocalVaultPrompt(true); return st; }
    catch(e) { setLocalVaultMsg(cleanError(e)); }
  }
  function openLocalVaultSettings() { setView('settings'); setShowLocalVaultPrompt(false); setTimeout(() => localVaultSettingsRef.current?.scrollIntoView({ behavior:'smooth', block:'start' }), 60); }
  function openLocalVaultUnlock() { setSidebarCollapsed(false); closeHostEditor(); setView('settings'); setShowLocalVaultPrompt(true); setTimeout(() => localVaultSettingsRef.current?.scrollIntoView({ behavior:'smooth', block:'start' }), 60); }
  const renderSyncNotice = () => <div className={`notice notice-${syncNotice.kind}`}>
    <div className="noticeBody"><div className="noticeIcon" aria-hidden="true">{syncNotice.kind === 'success' ? '✓' : syncNotice.kind === 'warning' ? '!' : syncNotice.kind === 'error' ? '×' : 'i'}</div><div><div className="noticeTitle">{syncNotice.title}</div><p>{syncNotice.message}</p></div></div>
    {syncNotice.action === 'unlockVault' && <div className="noticeActions"><button className="primary" onClick={openLocalVaultUnlock}>Datensafe entsperren</button></div>}
    {syncNotice.details && <details className="noticeDetails"><summary>Technische Details</summary><code>{syncNotice.details}</code></details>}
  </div>;
  function openUpdateSettings() { setWorkspaceView('settings'); closeHostEditor(); setSidebarCollapsed(false); setTimeout(() => updateSettingsRef.current?.scrollIntoView({ behavior:'smooth', block:'start' }), 60); }
  function openSyncSettings() { setWorkspaceView('settings'); closeHostEditor(); setSidebarCollapsed(false); setShowLocalVaultPrompt(false); setTimeout(() => (syncActionsRef.current || syncSettingsRef.current)?.scrollIntoView({ behavior:'smooth', block:'center' }), 60); }
  function handleSyncFooterClick() { if (syncFooterState === 'locked') openLocalVaultUnlock(); else openSyncSettings(); }
  const accountWebURL = () => `${normalizeEndpoint(accountLogin.endpoint)}/account`;
  function openAccountWeb() {
    if (!validSyncEndpoint(accountLogin.endpoint)) { setSyncMsg('Sync-Server muss HTTPS nutzen (HTTP nur localhost/127.0.0.1).'); return; }
    API.OpenExternalURL(accountWebURL()).catch(e => setSyncMsg('Kontoverwaltung konnte nicht geöffnet werden: '+cleanError(e)));
  }
  function closeTotpDialog() {
    setAccountTotp('');
    setShowTotpDialog(false);
    setAccountLogin(prev => ({...prev, totp:''}));
  }
  async function loginSyncAccount(totpCode = '') {
    setAccountLoginBusy(true);
    setAccountMsg(totpCode ? 'TOTP-Code wird geprüft…' : 'Login läuft…');
    setSyncMsg(totpCode ? 'TOTP-Code wird geprüft…' : 'Login läuft…');
    try {
      const endpoint = normalizeEndpoint(accountLogin.endpoint);
      if (!validSyncEndpoint(endpoint)) throw new Error('Sync-Server muss HTTPS nutzen (HTTP nur localhost/127.0.0.1).');
      const req = {...accountLogin, endpoint, totp: totpCode.trim(), label: accountLogin.label || `ssh-vault2-${info?.platform || 'desktop'}`};
      const res = await API.SyncLogin(req);
      closeTotpDialog();
      setAccountLogin(prev => ({...prev, endpoint, password:'', totp:''}));
      const c = await API.GetSyncConfig();
      setSyncCfg(c);
      const okMsg = `${res.message || 'Sync-Login gespeichert'}: verschlüsselter Sync ist eingerichtet.`;
      setAccountMsg(okMsg);
      setSyncMsg(okMsg);
      if (syncReady(c, syncPass)) void autoSync('account-login');
    } catch(e) {
      const text = cleanError(e);
      if (text.includes('TOTP')) {
        setShowTotpDialog(true);
        setAccountMsg(text.includes('ungültig') ? 'TOTP-Code ungültig. Bitte erneut eingeben.' : 'TOTP-Code nötig. Popup geöffnet.');
      } else if (text.includes('Lokaler Tresor gesperrt')) {
        setShowLocalVaultPrompt(true);
        setAccountMsg('Lokalen Datensafe entsperren, dann Sync-Login erneut ausführen.');
      } else {
        setAccountMsg('Sync-Login fehlgeschlagen: '+text);
      }
      setSyncMsg('Sync-Login fehlgeschlagen: '+text);
    } finally {
      setAccountLogin(prev => ({...prev, password:'', totp:''}));
      setAccountLoginBusy(false);
    }
  }
  function submitTotpLogin() {
    void loginSyncAccount(accountTotp);
  }
  async function importSSHConfig() {
    try { const r = await API.ImportSSHConfig(sshConfigPath); setImportMsg(`${r.message}: ${r.count} neue Hosts`); await reloadHosts(); }
    catch(e) { setImportMsg(cleanError(e)); }
  }
  async function exportLocalData() {
    try {
      if (!transferPass || transferPass.length < 10) throw new Error('Export-Passphrase mind. 10 Zeichen nötig.');
      const r = await API.ExportLocalData(transferPath, transferPass);
      setTransferPath((r as any).path || transferPath);
      setTransferMsg(`${r.message}: ${r.count} Hosts · ${(r as any).vaultCount || 0} Tresor-Einträge → ${(r as any).path || 'Datei'}`);
    } catch(e) { setTransferMsg(cleanError(e)); }
    finally { setTransferPass(''); }
  }
  async function importLocalData() {
    try {
      if (!transferPath.trim()) throw new Error('Import-Pfad fehlt.');
      if (!transferPass || transferPass.length < 10) throw new Error('Export-Passphrase mind. 10 Zeichen nötig.');
      const r = await API.ImportLocalData(transferPath, transferPass, transferReplace);
      setTransferMsg(`${r.message}: ${r.count} Hosts · ${(r as any).vaultCount || 0} Tresor-Einträge ${transferReplace ? 'ersetzt' : 'zusammengeführt'}.`);
      await reloadHosts(); await reloadVault(); await refreshLocalVaultStatus();
    } catch(e) { setTransferMsg(cleanError(e)); }
    finally { setTransferPass(''); }
  }
  async function saveSync(runAuto = true) { try { if (!validSyncEndpoint(syncCfg.endpoint || defaultSyncServer)) throw new Error('Sync-Server muss HTTPS nutzen (HTTP nur localhost/127.0.0.1).'); const c = await API.SaveSyncConfig({...syncCfg, autoPassphrase: syncPass} as any); syncCfgRef.current = c; setSyncCfg(c); setSyncMsg(c.enabled ? 'Auto-Sync gespeichert. Server speichert nur verschlüsselte Daten.' : 'Sync deaktiviert. Alles bleibt lokal.'); if (runAuto && syncReady(c, syncPass)) void autoSync('enabled'); return c; } catch(e) { setSyncMsg(cleanError(e)); } }
  async function pushSync() { setSyncRunning(true); try { const c = await saveSync(false); if (!syncReady(c || syncCfg, syncPass)) throw new Error(syncNotReadyText(c || syncCfg, syncPass)); const r = await API.SyncPush(syncPass); setSyncMsg(`${r.message}: ${r.count} Hosts · ${(r as any).vaultCount || 0} Tresor-Einträge`); } catch(e) { setSyncMsg(cleanError(e)); } finally { setSyncRunning(false); } }
  async function pullSync() { setSyncRunning(true); try { const c = await saveSync(false); if (!syncReady(c || syncCfg, syncPass)) throw new Error(syncNotReadyText(c || syncCfg, syncPass)); const r = await API.SyncPull(syncPass); setSyncMsg(`${r.message}: ${r.count} Hosts · ${(r as any).vaultCount || 0} Tresor-Einträge`); await reloadHosts(); await reloadVault(); } catch(e) { setSyncMsg(cleanError(e)); } finally { setSyncRunning(false); } }
  async function autoSync(reason: string) {
    const cfg = syncCfgRef.current;
    const pass = syncPassRef.current;
    if (autoSyncBusy.current || !syncReady(cfg, pass)) return;
    autoSyncBusy.current = true;
    setSyncRunning(true);
    try {
      const setupReason = reason === 'startup' || reason === 'enabled' || reason.startsWith('account-') || reason.startsWith('vault-');
      if (setupReason) {
        try {
          const pulled = await API.SyncPull(pass);
          await reloadHosts();
          await reloadVault();
          const next = await API.GetSyncConfig();
          setSyncCfg(next);
          setSyncMsg(`Auto-Sync Pull OK (${reason}): ${pulled.count} Hosts · ${(pulled as any).vaultCount || 0} Tresor-Einträge vom Server geladen. Kein Upload vom neuen Gerät.`);
          return;
        }
        catch(e) {
          const msg = cleanError(e);
          if (!msg.includes('Noch kein Sync auf Server')) {
            setSyncMsg(`Auto-Sync Upload gestoppt (${reason}): Server-Pull zuerst fehlgeschlagen: ${msg}`);
            return;
          }
        }
      } else if (!cfg.lastSync) {
        setSyncMsg(`Auto-Sync Upload gestoppt (${reason}): Erst „Vom Server laden“ ausführen, damit ein neues Gerät nichts überschreibt.`);
        return;
      }
      const r = await API.SyncPush(pass);
      const next = await API.GetSyncConfig();
      setSyncCfg(next);
      setSyncMsg(`Auto-Sync Upload OK (${reason}): ${r.count} Hosts · ${(r as any).vaultCount || 0} Tresor-Einträge`);
    }
    catch(e) { setSyncNotice(friendlySyncError(e, reason)); }
    finally { autoSyncBusy.current = false; setSyncRunning(false); }
  }

  const selHost = hosts.find(h => h.id === selected);
  const selectedLocalEntry = local.find(f => f.path === selectedLocal);
  const selectedRemoteEntry = remote.find(f => f.path === selectedRemote);
  const hasActiveSftp = !!sftpId && sftpTabs.some(t => t.id === sftpId);
  const localVaultAttention = (localVault.configured && !localVault.unlocked) || localVault.plaintextSecrets > 0;
  const localVaultPromptTitle = localVault.plaintextSecrets > 0 ? 'Lokale Secrets verschlüsseln' : 'Lokalen Datensafe entsperren';
  return <div className={`app theme-${theme}`}>
    {showLocalVaultPrompt && localVaultAttention && <div className="unlockOverlay" onClick={()=>setShowLocalVaultPrompt(false)}><div className="unlockDialog" onClick={e=>e.stopPropagation()}>
      <div className="unlockTitle"><span>{localVaultPromptTitle}</span><button onClick={()=>setShowLocalVaultPrompt(false)}>×</button></div>
      <p>{localVault.plaintextSecrets > 0 ? 'Es gibt noch lokale Passwörter/Keys im Klartext. Bitte Tresor-Passphrase setzen und migrieren.' : 'Gespeicherte Passwörter/Keys sind verschlüsselt. Zum Verbinden bitte den lokalen Datensafe entsperren.'}</p>
      <label>Tresor-Passphrase<input autoFocus type="password" value={localVaultPass} onChange={e=>setLocalVaultPass(e.target.value)} onKeyDown={e=>{ if(e.key === 'Enter') { localVault.plaintextSecrets > 0 ? void encryptLocalVaultExisting() : void unlockLocalVault(); } }}/></label>
      <div className="unlockStats"><span>{localVault.unlocked ? 'entsperrt' : 'gesperrt'}</span><span>verschlüsselt: {localVault.encryptedValues}</span><span>Plaintext: {localVault.plaintextSecrets}</span></div>
      <p className={localVault.plaintextSecrets ? 'warn' : 'syncStatus'}>{localVaultMsg}</p>
      <div className="unlockActions"><button className="primary" onClick={()=>localVault.plaintextSecrets > 0 ? encryptLocalVaultExisting() : unlockLocalVault()}>{localVault.plaintextSecrets > 0 ? 'Entsperren & migrieren' : 'Entsperren'}</button><button onClick={openLocalVaultSettings}>Einstellungen öffnen</button><button onClick={()=>setShowLocalVaultPrompt(false)}>Später</button></div>
    </div></div>}
    {showTotpDialog && <div className="unlockOverlay totpOverlay" onClick={closeTotpDialog}><div className="unlockDialog totpDialog" onClick={e=>e.stopPropagation()}>
      <div className="unlockTitle"><span>TOTP-Code eingeben</span><button onClick={closeTotpDialog}>×</button></div>
      <p>Für dieses Konto ist Zwei-Faktor-Authentifizierung aktiv. Gib den aktuellen 6-stelligen Code ein.</p>
      <label>TOTP-Code<input autoFocus inputMode="numeric" autoComplete="one-time-code" value={accountTotp} onChange={e=>setAccountTotp(e.target.value)} onKeyDown={e=>{ if(e.key === 'Enter') submitTotpLogin(); }}/></label>
      <p className="syncStatus">{syncMsg}</p>
      <div className="unlockActions"><button className="primary" onClick={submitTotpLogin}>Login fortsetzen</button><button onClick={closeTotpDialog}>Abbrechen</button></div>
    </div></div>}
    <aside className={sidebarCollapsed ? 'sidebar collapsed' : 'sidebar'}>
      <div className="brandRow"><div className="brand"><img className="brandIcon" src="/ssh-vault2.png" alt="ssh-vault2"/><div><b>ssh-vault2</b><span>SSH/SFTP Workspace</span></div></div><button className="sidebarToggle" title={sidebarCollapsed ? 'Hostmenü ausklappen' : 'Hostmenü einklappen'} onClick={()=>setSidebarCollapsed(!sidebarCollapsed)}>{sidebarCollapsed ? '›' : '‹'}</button></div>
      {!sidebarCollapsed && <div className="hostAddRow"><button className="sideButton newHostButton" onClick={beginNewHost}>+ Host</button><div className="hostFilter"><button className="hostFilterButton sideButton" onClick={()=>setTagFilterOpen(!tagFilterOpen)} title="Hosts nach Tags filtern" aria-label={`Tags anzeigen${visibleTags.length ? ` (${visibleTags.length} aktiv)` : ' (alle)'}`}> <svg className="filterIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16l-6.2 7.1v4.2l-3.6 1.8v-6L4 6z"/></svg>{(visibleTags.length > 0 || hiddenHostCount > 0) && <span className="filterBadge">{visibleTags.length || hiddenHostCount}</span>}</button>{tagFilterOpen && <div className="tagFilterMenu">
        <div className="tagFilterTitle"><b>Tags anzeigen</b><button onClick={()=>setTagFilterOpen(false)}>×</button></div>
        <div className="tagFilterActions"><button onClick={setAllTagsVisible}>Alle anzeigen</button><button onClick={()=>setVisibleTags([])}>Zurücksetzen</button></div>
        {availableHostTags.length===0 && <p>Keine Tags vorhanden.</p>}
        {availableHostTags.map(tag => <label key={tag} className="tagFilterOption"><input type="checkbox" checked={visibleTags.length===0 || visibleTags.includes(tag)} onChange={()=>toggleVisibleTag(tag)}/><span>{tag}</span></label>)}
      </div>}</div></div>}
      {!sidebarCollapsed && <div className="hosts">{filteredHosts.map(h => <button key={h.id} className={h.id===selected?'sideButton host active':'sideButton host'} onClick={() => { setSelected(h.id); closeHostEditor(); }} onDoubleClick={() => hostProtocol(h) === 'rdp' ? connectRDPHost(h.id) : connectSSHHost(h.id)} onContextMenu={e=>hostContext(e,h)}><b>{h.name}</b><span>{hostProtocol(h).toUpperCase()} · {hostUserLabel(h)}@{h.address}:{hostPortLabel(h)}</span><em>{(h.tags||[]).join(' · ')}</em></button>)}{filteredHosts.length===0 && <div className="empty hostFilterEmpty">Keine Hosts für diese Tags.</div>}</div>}
      {sidebarCollapsed && <div className="collapsedRail"><button title="Hostmenü öffnen" onClick={()=>setSidebarCollapsed(false)}>☰</button><button title="Neuer Host" onClick={()=>{setSidebarCollapsed(false); beginNewHost();}}>＋</button><button className="settingsGear compact" title="Einstellungen" onClick={()=>{setSidebarCollapsed(false); setWorkspaceView('settings'); closeHostEditor();}}><span>⚙</span></button></div>}
      {!sidebarCollapsed && <div className="sidebarFooter"><button className="settingsGear" title="Einstellungen" onClick={()=>{setWorkspaceView('settings'); closeHostEditor();}}><span>⚙</span><b>Einstellungen</b></button><div className="footerSyncCluster"><button className="versionMeta" title={`${info?.platform || 'desktop'} · v${info?.version || ''}${updateStatus==='available' && updateAvailableVersion ? ` · Update ${updateAvailableVersion}` : ''} · Updates öffnen`} onClick={openUpdateSettings}><span>v{info?.version}</span><em className={`updateBadge ${updateStatus}`}>{updateStatus==='checking' ? '↻' : updateStatus==='available' ? 'neu' : updateStatus==='error' ? '!' : '✓'}</em></button><button className={`syncFooterButton ${syncFooterState}`} title={syncFooterTitle} aria-label={syncFooterTitle} onClick={handleSyncFooterClick}>{syncFooterState === 'locked' ? <span className="syncLockIcon" aria-hidden="true"></span> : <span className="syncCompositeIcon"><svg className="syncGlyph" viewBox="0 0 40 40" preserveAspectRatio="xMidYMid meet" aria-hidden="true"><circle className="syncGlyphRing" cx="20" cy="20" r="13"/><path className="syncGlyphHead" d="M33 7v8h-8"/><path className="syncGlyphHead" d="M7 33v-8h8"/><circle className="syncStatusDot" cx="20" cy="20" r="4.8"/></svg></span>}</button></div></div>}
      {ctx && <div className="contextMenu" style={{left:ctx.x, top:ctx.y}} onClick={e=>e.stopPropagation()}>
        <button onClick={()=>beginEditHost(ctx.host.id)}>Host bearbeiten</button>
        <button onClick={()=>editTags(ctx.host.id)}>Tag vergeben</button>
        <button onClick={()=>connectSSHHost(ctx.host.id)}>SSH verbinden</button>
        <button onClick={()=>connectSFTPHost(ctx.host.id)}>SFTP verbinden</button>
        <button onClick={()=>connectRDPHost(ctx.host.id)}>RDP verbinden</button>
        <button className="danger" onClick={()=>deleteHost(ctx.host.id)}>Löschen</button>
      </div>}
    </aside>
    <section className="main">
      <header className="toolbar">
        <div><b>{selHost?.name || (editing ? 'Neuer Host' : 'Kein Host ausgewählt')}</b><span>{msg}</span></div>
        <div className="viewTabs" role="tablist"><button type="button" role="tab" data-view="terminal" className={view==='terminal'?'active':''} onClick={()=>setWorkspaceView('terminal')}>Terminal</button><button type="button" role="tab" data-view="sftp" className={view==='sftp'?'active':''} onClick={()=>setWorkspaceView('sftp')}>SFTP</button><button type="button" role="tab" data-view="rdp" className={view==='rdp'?'active':''} onClick={()=>setWorkspaceView('rdp')}>RDP</button><button type="button" role="tab" data-view="vault" className={view==='vault'?'active':''} onClick={()=>setWorkspaceView('vault')}>Vault</button></div>
      </header>
      <div className={editing ? 'content withEditor' : 'content'}>
        {editing && <div className="editor card">
          <h3>{draft.id ? 'Host bearbeiten' : 'Host anlegen'}</h3>
          <label className="editorLabel">Verbindungstyp
            <select value={hostProtocol(draft)} onChange={e=>setDraftProtocol(e.target.value as 'ssh'|'rdp')}>
              <option value="ssh">SSH / SFTP</option>
              <option value="rdp">RDP</option>
            </select>
          </label>
          <input placeholder="Name / Alias" value={draft.name} onChange={e=>setDraft({...draft,name:e.target.value})}/>
          <input placeholder="Host / IP-Adresse" value={draft.address} onChange={e=>setDraft({...draft,address:e.target.value})}/>
          {hostProtocol(draft) === 'ssh' ? <>
            <div className="row"><input placeholder="SSH-Port" value={draft.port || 22} onChange={e=>setDraft({...draft,port:Number(e.target.value)})}/><input placeholder="SSH-User" value={draft.username} onChange={e=>setDraft({...draft,username:e.target.value})}/></div>
            <label className="editorLabel">Vault-Anmeldung<select value={(draft as any).vaultId || ''} onChange={e=>setDraft({...draft,vaultId:e.target.value} as any)}><option value="">Direkte Host-Anmeldung</option>{vault.map(v=><option key={v.id} value={v.id}>{v.name} · {v.username} · {v.authMode === 'key' ? 'SSH-Key' : 'Passwort'}</option>)}</select></label>
            {(draft as any).vaultId && <p className="hint">Nutzt Vault: {vaultLabel((draft as any).vaultId)}. Direkte User/Passwort/Key-Felder bleiben als Fallback gespeichert.</p>}
            <select value={draft.authMode} onChange={e=>setDraft({...draft,authMode:e.target.value})}><option value="key">Key</option><option value="password">Passwort</option><option value="agent">Agent</option></select>
            <input placeholder="Key-Pfad" value={draft.keyPath || ''} onChange={e=>setDraft({...draft,keyPath:e.target.value})}/>
            <input placeholder={draft.authMode === 'key' ? 'Key-Passphrase (optional, nicht Login-Passwort)' : 'Passwort'} type="password" value={draft.password || ''} onChange={e=>setDraft({...draft,password:e.target.value})}/>
            <p className="hint">SSH/SFTP nutzt Terminal und Dateimanager. RDP-Felder bleiben ausgeblendet.</p>
          </> : <>
            <div className="row"><input placeholder="RDP-Port" value={(draft as any).rdpPort || 3389} onChange={e=>setDraft({...draft,rdpPort:Number(e.target.value)} as any)}/><input placeholder="RDP-Benutzer" value={(draft as any).rdpUsername || ''} onChange={e=>setDraft({...draft,rdpUsername:e.target.value} as any)}/></div>
            <div className="row"><input placeholder="RDP-Domain optional" value={(draft as any).rdpDomain || ''} onChange={e=>setDraft({...draft,rdpDomain:e.target.value} as any)}/><input placeholder="RDP-Passwort" type="password" value={(draft as any).rdpPassword || ''} onChange={e=>setDraft({...draft,rdpPassword:e.target.value} as any)}/></div>
            <div className="row"><input placeholder="Breite" value={(draft as any).rdpWidth || 1280} onChange={e=>setDraft({...draft,rdpWidth:Number(e.target.value)} as any)}/><input placeholder="Höhe" value={(draft as any).rdpHeight || 800} onChange={e=>setDraft({...draft,rdpHeight:Number(e.target.value)} as any)}/><label className="editorLabel compactSelect">RDP Skalierung<select value={rdpScaleModeOf(draft)} onChange={e=>setDraft({...draft, rdpScaleMode:e.target.value as RDPScaleMode} as any)}><option value="smart">Smart Auto</option><option value="sharp">Scharf / Reconnect</option><option value="fit">Fit / Autoscale</option><option value="original">Originalgröße</option></select></label></div>
            <label className="editorLabel compactSelect">RDP Tastatur<select value={rdpKeyboardLayoutOf(draft)} onChange={e=>setDraft({...draft, rdpKeyboardLayout:e.target.value as RDPKeyboardLayout} as any)}><option value="en-US">Englisch / US</option><option value="de-DE">Deutsch / DE</option></select></label>
            <p className="hint">RDP läuft im App-Fenster. Skalierung und Tastaturlayout werden pro Host gespeichert. Passwort wird lokal verschlüsselt und nicht im Frontend angezeigt.</p>
          </>}
          <input placeholder="Tags, comma separated" value={(draft.tags||[]).join(', ')} onChange={e=>setDraft({...draft,tags:e.target.value.split(',').map(x=>x.trim()).filter(Boolean)})}/>
          <div className="row"><button className="primary" onClick={saveHost}>Speichern</button><button onClick={closeHostEditor}>Abbrechen</button>{draft.id && <button className="danger" onClick={delHost}>Löschen</button>}</div>
        </div>}
        <div className="workspace card">
          <div ref={terminalPaneRef} className={view==='terminal'?'terminalPane active':'terminalPane'}><div className="tabs sessionTabs">{sessions.map(s => <button key={s.id} title={`${s.title} · ${s.status}`} className={s.id===activeSession?'tab active':'tab'} onClick={()=>{setActiveSession(s.id); window.setTimeout(()=>scheduleTerminalFit(s.id, true, 'session-tab-click'),80)}}><span>{s.title} · {s.status}</span><em className="tabClose" title="Sitzung schließen" onClick={(e)=>closeTerminal(s.id,e)}>×</em></button>)}</div>{sessions.length===0 && <div className="empty">Host wählen und SSH verbinden.</div>}{sessions.map(s => <div key={s.id} className={s.id===activeSession?'term active':'term'} onContextMenu={e=>openTerminalMenu(e,s.id)} ref={el=>attachTerm(s.id, el)} />)}</div>
          {termCtx && <div className="contextMenu terminalContextMenu" style={{left:termCtx.x, top:termCtx.y}} onClick={e=>e.stopPropagation()} onContextMenu={e=>e.preventDefault()}>
            <button onClick={()=>copyTerminalSelection(termCtx.sessionId)}>Kopieren</button>
            <button onClick={()=>pasteTerminalClipboard(termCtx.sessionId)}>Einfügen</button>
            <button onClick={()=>setTermCtx(null)}>Schließen</button>
          </div>}
          {view==='rdp' && <div className={`rdpWorkspace rdpScale-${rdpScaleModeOf(selHost)}`}><div className="tabs sessionTabs rdpTabs">{rdpSessions.map(s => <button key={s.id} title={`${s.title} · ${s.status}`} className={s.id===activeRdp?'tab active':'tab'} onClick={()=>{setActiveRdp(s.id); window.setTimeout(()=>rdpCanvases.current[s.id]?.focus(), 40)}}><span>{s.title} · {s.status}</span><em className="tabClose" title="RDP schließen" onClick={(e)=>closeRDP(s.id,e)}>×</em></button>)}</div>{rdpSessions.length===0 && <div className="empty rdpEmpty"><span>Host wählen und RDP öffnen.</span></div>}{rdpSessions.map(s => <div key={s.id} className={s.id===activeRdp?'rdpPane active':'rdpPane'}><div className="rdpCanvasWrap" ref={el=>attachRDPWrap(s.id, el)}><canvas ref={el=>attachRDPCanvas(s.id, el)} onMouseMove={e=>rdpMouseMove(s.id,e)} onMouseDown={e=>{e.currentTarget.focus(); rdpMouse(s.id, e.button===2?'rightdown':'leftdown', e)}} onMouseUp={e=>rdpMouse(s.id, e.button===2?'rightup':'leftup', e)} onContextMenu={e=>e.preventDefault()} onDragOver={e=>{e.preventDefault(); e.stopPropagation();}} onDrop={e=>rdpFileDrop(s.id,e)} onWheel={e=>{e.preventDefault(); rdpMouse(s.id,'wheel',e, e.deltaY < 0 ? 120 : -120)}} onKeyDown={e=>rdpKey(s.id,e,true)} onKeyUp={e=>rdpKey(s.id,e,false)} onPaste={e=>rdpPaste(s.id,e)} /></div><p className="rdpHint">WebGL-RDP anklicken, dann Tastatur/Maus für RDP nutzen.</p></div>)}</div>}
          {view==='sftp' && <div className={hasActiveSftp ? 'sftp' : 'sftp emptySftpView'}>
            <div className="tabs sessionTabs sftpTabs">{sftpTabs.map(t => <button key={t.id} title={`${t.title} · ${t.remotePath}`} className={t.id===activeSftp?'tab active':'tab'} onClick={()=>switchSftpTab(t)}><span>{t.title} · {t.remotePath}</span><em className="tabClose" title="SFTP-Tab schließen" onClick={(e)=>closeSftpTab(t.id,e)}>×</em></button>)}</div>{!hasActiveSftp && <div className="empty sftpEmpty">Host wählen und SFTP öffnen.</div>}
            {hasActiveSftp && <>
            <div className="pane"><h3>Lokal <span className="sftpBadge">Liste</span></h3><div className="pathBar"><button className="upButton" title="Ordner hoch" onClick={()=>refreshLocal(parentLocal(localPath))}>↑</button><input value={localPath} onChange={e=>setLocalPath(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')refreshLocal()}}/></div><div className="fileHeader"><span>Name</span><span>Typ</span><span>Rechte</span><span>Größe</span></div><div className={sftpDropSide==='local'?'fileList dropActive':'fileList'} onContextMenu={e=>openSftpMenu(e,'local')} onDragOver={e=>allowSftpDrop(e,'local')} onDragLeave={()=>setSftpDropSide(null)} onDrop={e=>dropSftp(e,'local')}>{local.map(f=><button key={f.path} draggable className={f.path===selectedLocal?'fileRow selectedFile':'fileRow'} onDragStart={e=>startSftpDrag(e,'local',f)} onDragEnd={()=>{setSftpDrag(null); setSftpDropSide(null);}} onDragOver={e=>allowSftpDrop(e,'local')} onDrop={e=>dropSftp(e,'local',f)} onClick={()=>setSelectedLocal(f.path)} onContextMenu={e=>openSftpMenu(e,'local',f)} onDoubleClick={()=>openFileEditor('local', f)}><span className="fileName"><span className="fileIcon" aria-hidden="true">{fileIcon(f)}</span><span className="fileText">{f.name}</span></span><span className="fileType">{f.type}</span><span className="fileMode">{f.mode || '—'}</span><span className="fileSize">{fmt(f.size)}</span></button>)}</div></div>
            <div className="transfer"><button disabled={!sftpId || !selectedLocal} onClick={()=>{selectedLocalEntry&&API.UploadSFTP(sftpId, selectedLocal, remotePath).then(async()=>{ await refreshRemote(); setMsg(selectedLocalEntry.type === 'directory' ? 'Ordner-Upload abgeschlossen' : 'Upload abgeschlossen'); }).catch(e=>setMsg(cleanError(e)))}}>Upload →</button><button disabled={!sftpId || !selectedRemote} onClick={()=>{selectedRemoteEntry&&API.DownloadSFTP(sftpId, selectedRemote, localPath).then(async()=>{ await refreshLocal(); setMsg(selectedRemoteEntry.type === 'directory' ? 'Ordner-Download abgeschlossen' : 'Download abgeschlossen'); }).catch(e=>setMsg(cleanError(e)))}}>← Download</button><small>{selectedLocalEntry ? `Lokal: ${selectedLocalEntry.name}` : 'Lokal wählen'}<br/>{selectedRemoteEntry ? `Remote: ${selectedRemoteEntry.name}` : 'Remote wählen'}<br/><span>Explorer → Remote</span></small></div>
            <div className="pane"><h3>Remote <span className="sftpBadge">Liste</span><span className="sftpBadge dropBadge">Explorer-Drop</span></h3><div className="pathBar"><button className="upButton" title="Ordner hoch" onClick={()=>refreshRemote(parentRemote(remotePath))}>↑</button><input value={remotePath} onChange={e=>setRemotePath(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')refreshRemote()}}/></div><div className="fileHeader"><span>Name</span><span>Typ</span><span>Rechte</span><span>Größe</span></div><div className={sftpDropSide==='remote'?'fileList dropActive':'fileList'} onContextMenu={e=>openSftpMenu(e,'remote')} onDragOver={e=>allowSftpDrop(e,'remote')} onDragLeave={()=>setSftpDropSide(null)} onDrop={e=>dropSftp(e,'remote')}>{remote.map(f=><button key={f.path} draggable className={f.path===selectedRemote?'fileRow selectedFile':'fileRow'} onDragStart={e=>startSftpDrag(e,'remote',f)} onDragEnd={()=>{setSftpDrag(null); setSftpDropSide(null);}} onDragOver={e=>allowSftpDrop(e,'remote')} onDrop={e=>dropSftp(e,'remote',f)} onClick={()=>setSelectedRemote(f.path)} onContextMenu={e=>openSftpMenu(e,'remote',f)} onDoubleClick={()=>openFileEditor('remote', f)}><span className="fileName"><span className="fileIcon" aria-hidden="true">{fileIcon(f)}</span><span className="fileText">{f.name}</span></span><span className="fileType">{f.type}</span><span className="fileMode">{f.mode || '—'}</span><span className="fileSize">{fmt(f.size)}</span></button>)}</div></div>
            </>}
            {hasActiveSftp && sftpCtx && <div className="contextMenu sftpContextMenu" style={{left:sftpCtx.x, top:sftpCtx.y}} onClick={e=>e.stopPropagation()} onContextMenu={e=>e.preventDefault()}>
              <div className="menuTitle">{sftpCtx.side === 'local' ? 'Lokal' : 'Remote'}{sftpCtx.entry ? ` · ${sftpCtx.entry.name}` : ''}</div>
              {sftpCtx.entry && <button onClick={()=>sftpAction('open')}>Öffnen</button>}
              {sftpCtx.entry && <button disabled={sftpCtx.side==='remote' && !sftpId} onClick={()=>sftpAction('transfer')}>{sftpCtx.side === 'local' ? 'Upload →' : '← Herunterladen'}</button>}
              <button onClick={()=>sftpAction('mkdir')}>Neuer Ordner…</button>
              {sftpCtx.entry && <button onClick={()=>sftpAction('rename')}>Umbenennen… <span>F2</span></button>}
              {sftpCtx.entry && <button className="danger" onClick={()=>sftpAction('delete')}>Löschen <span>F8</span></button>}
              {sftpCtx.entry && <button onClick={()=>sftpAction('properties')}>Eigenschaften <span>F9</span></button>}
              <button onClick={()=>sftpAction('refresh')}>Aktualisieren</button>
              <button onClick={()=>sftpAction('copyPath')}>Pfad kopieren</button>
            </div>}
            {hasActiveSftp && sftpProps && (() => { const pe = propEntry || sftpProps.entry; const shownSize = propSize !== null ? propSize : pe.size; return <div className="propsOverlay" onClick={()=>setSftpProps(null)}><div className="propsDialog winscpProps" onClick={e=>e.stopPropagation()}>
              <div className="propsTitle"><span>{pe.name} Eigenschaften</span><button onClick={()=>setSftpProps(null)}>×</button></div>
              <div className="propTabs"><button className={propTab==='general'?'active':''} onClick={()=>setPropTab('general')}>Allgemein</button><button className={propTab==='checksum'?'active':''} onClick={()=>setPropTab('checksum')}>Prüfsumme</button></div>
              {propTab==='general' && <>
                <section className="propGeneral">
                  <div className="propIcon">{pe.type === 'directory' ? '📁' : '📄'}</div>
                  <div className="propMain">
                    <div className="propName">{pe.name}</div>
                    <div className="propLine"><label>Ort:</label><span>{dirName(pe.path)}</span></div>
                    <div className="propLine"><label>Größe:</label><span>{pe.type === 'directory' && propSize === null ? 'Unbekannt' : fmt(shownSize)}</span><button className="calcButton" onClick={calculatePropSize}>Berechnen</button></div>
                    <div className="propLine"><label>Geändert:</label><span>{fmtDate(pe.modified)}</span></div>
                  </div>
                </section>
                <section className="ownerGrid">
                  <label>Eigentümer:<select value={propOwner} disabled={sftpProps.side !== 'remote'} onChange={e=>setPropOwner(e.target.value)}><option value={propOwner}>{propOwner || ownerLabel(pe)}</option>{propOwners.map((o:any)=><option key={`o-${o.name}-${o.id}`} value={o.name}>{o.label || `${o.name} [${o.id}]`}</option>)}</select></label>
                  <label>Gruppe:<select value={propGroup} disabled={sftpProps.side !== 'remote'} onChange={e=>setPropGroup(e.target.value)}><option value={propGroup}>{propGroup || groupLabel(pe)}</option>{propGroups.map((g:any)=><option key={`g-${g.name}-${g.id}`} value={g.name}>{g.label || `${g.name} [${g.id}]`}</option>)}</select></label>
                </section>
                <section className="permBox"><div className="permHeader"><span>Rechte:</span><b>R</b><b>W</b><b>X</b></div>
                  {(['Eigentümer','Gruppe','Andere'] as const).map((row,ri)=><div className="permRow" key={row}><span>{row}</span>{[0,1,2].map((_,ci)=><input key={ci} type="checkbox" checked={octalHasBit(propOctal, ri, ci)} onChange={ev=>setPropOctal(setOctalBit(propOctal, ri, ci, ev.target.checked))}/>)}</div>)}
                  <div className="specialPerms"><label><input type="checkbox" checked={octalSpecial(propOctal,0)} onChange={e=>setPropOctal(setOctalSpecial(propOctal,0,e.target.checked))}/> UID setzen</label><label><input type="checkbox" checked={octalSpecial(propOctal,1)} onChange={e=>setPropOctal(setOctalSpecial(propOctal,1,e.target.checked))}/> GID setzen</label><label><input type="checkbox" checked={octalSpecial(propOctal,2)} onChange={e=>setPropOctal(setOctalSpecial(propOctal,2,e.target.checked))}/> Sticky-Bit</label></div>
                  <label className="octalLine">Oktal<input value={propOctal} onChange={e=>setPropOctal(octalClean(e.target.value))} onBlur={()=>setPropOctal(octalNorm(propOctal))}/></label>
                </section>
                <label className="propCheck"><input type="checkbox" checked={propDirX} onChange={e=>setPropDirX(e.target.checked)}/> X bei Verzeichnissen setzen</label>
                <label className="propCheck"><input type="checkbox" checked={propRecursive} onChange={e=>setPropRecursive(e.target.checked)}/> Besitzer, Gruppe und Berechtigungen rekursiv setzen</label>
              </>}
              {propTab==='checksum' && <section className="checksumPane"><p>{pe.type === 'directory' ? 'Ordner haben keine einzelne Prüfsumme.' : 'Prüfsumme für Datei berechnen:'}</p><div className="checksumButtons"><button disabled={pe.type==='directory'} onClick={()=>calculateChecksum('sha256')}>SHA-256</button><button disabled={pe.type==='directory'} onClick={()=>calculateChecksum('sha1')}>SHA-1</button><button disabled={pe.type==='directory'} onClick={()=>calculateChecksum('md5')}>MD5</button></div><textarea readOnly value={propChecksum} placeholder="Noch keine Prüfsumme berechnet." /></section>}
              <p className="propMsg">{propMsg}</p>
              <div className="propButtons"><button className="primary" onClick={applyProperties}>OK</button><button onClick={()=>setSftpProps(null)}>Abbrechen</button><button onClick={showPropertiesHelp}>Hilfe</button></div>
            </div></div>; })()}
          </div>}

          {fileEditor && <div className="editorOverlay" onClick={closeFileEditor}><div className="fileEditorDialog" onClick={e=>e.stopPropagation()}>
            <div className="fileEditorTitle"><div><b>{fileEditor.side === 'remote' ? 'Remote-Editor' : 'Lokaler Editor'} · {fileEditor.name}</b><span>{fileEditor.path}</span></div><button onClick={closeFileEditor}>×</button></div>
            <textarea className="fileEditorText" value={fileEditor.content} spellCheck={false} onChange={e=>{ const next = e.target.value; setFileEditor({...fileEditor, content:next, status:next===fileEditor.original ? fileEditor.status : 'Geändert — noch nicht gespeichert.'}); }} onKeyDown={e=>{ if((e.ctrlKey || e.metaKey) && e.key.toLowerCase()==='s'){ e.preventDefault(); void saveFileEditor(); } }}/>
            <div className="fileEditorFooter"><span className={fileEditor.content===fileEditor.original ? 'syncStatus' : 'warn'}>{fileEditor.status}</span><div><button onClick={()=>setFileEditor({...fileEditor, content:fileEditor.original, status:'Änderungen zurückgesetzt.'})} disabled={fileEditor.saving || fileEditor.content===fileEditor.original}>Zurücksetzen</button><button className="primary" onClick={saveFileEditor} disabled={fileEditor.saving}>{fileEditor.saving ? 'Speichere…' : fileEditor.side === 'remote' ? 'Speichern + Upload' : 'Speichern'}</button></div></div>
          </div></div>}
          {view==='vault' && <div className="settings vaultView compactVault"><div className="vaultHeader"><div><h2>Vault</h2><p>Anmeldungen lokal speichern und bei aktiviertem Sync verschlüsselt mitnehmen.</p></div></div>
            {localVaultAttention && <section className="settingsCard vaultSafeNotice"><div><b>{localVault.plaintextSecrets > 0 ? 'Lokale Klartext-Secrets gefunden' : 'Lokaler Datensafe gesperrt'}</b><p>{localVault.plaintextSecrets > 0 ? 'Bitte lokale Passwörter/Keys verschlüsseln, bevor du weiterarbeitest.' : 'Zum Anzeigen/Nutzen gespeicherter Passwörter und eingebetteter Keys Datensafe entsperren.'}</p></div><button className="primary" onClick={openLocalVaultSettings}>Datensafe öffnen</button></section>}
            <section className="settingsCard vaultFormCard"><div className="cardTitle"><h3>{vaultDraft.id ? 'Anmeldung bearbeiten' : 'Anmeldung hinzufügen'}</h3><span>{vaultDraft.authMode === 'key' && (vaultDraft as any).privateKeySaved ? 'Key-Inhalt im Vault gespeichert' : vaultDraft.authMode === 'key' ? 'Key-Pfad lokal · Import speichert backendseitig' : 'Passwort wird verschlüsselt gespeichert'}</span></div>
              <div className="vaultGrid compact">
                <label>Name<input value={vaultDraft.name} onChange={e=>setVaultDraft({...vaultDraft,name:e.target.value})} placeholder="z.B. prod-key"/></label>
                <label>Benutzer<input value={vaultDraft.username} onChange={e=>setVaultDraft({...vaultDraft,username:e.target.value})} placeholder="z.B. demo-user"/></label>
                <label>Typ<select value={vaultDraft.authMode} onChange={e=>setVaultDraft({...vaultDraft,authMode:e.target.value})}><option value="password">Benutzer + Kennwort</option><option value="key">Benutzer + SSH-Key</option></select></label>
              </div>
              {vaultDraft.authMode === 'password' && <div className="vaultWide"><label>Passwort<input type="password" value={vaultDraft.password || ''} onChange={e=>setVaultDraft({...vaultDraft,password:e.target.value})}/></label></div>}
              {vaultDraft.authMode === 'key' && <div className="vaultKeyBox"><div className="keyPathRow"><label>SSH-Key-Pfad<input value={vaultDraft.keyPath || ''} onChange={e=>setVaultDraft({...vaultDraft,keyPath:e.target.value})} placeholder="z.B. C:\Users\demo-user\.ssh\id_ed25519"/></label><button onClick={importVaultKeyFile}>Datei in Vault übernehmen</button></div><p className="syncStatus">{(vaultDraft as any).privateKeySaved ? 'Private Key ist im Vault gespeichert. Inhalt wird nicht im Frontend angezeigt.' : 'Noch kein Private Key im Vault gespeichert. Datei importieren speichert ihn backendseitig.'}</p><label>Key-Passphrase (optional)<input type="password" value={vaultDraft.password || ''} onChange={e=>setVaultDraft({...vaultDraft,password:e.target.value})}/></label><p className="hint compactHint">Nur ein Pfad funktioniert lokal auf diesem Gerät. Key-Passphrase ist nur für verschlüsselte Private Keys, nicht das Login-Passwort. Mit „Datei in Vault übernehmen“ wird der Key-Inhalt verschlüsselt gesynct.</p></div>}
              <div className="vaultActions"><button onClick={beginNewVault}>Felder leeren</button>{vaultDraft.id && <button className="danger" onClick={()=>deleteVaultEntry(vaultDraft.id)}>Löschen</button>}<button className="primary" onClick={saveVaultEntry}>Speichern</button></div>
            </section>
            <section className="settingsCard vaultSavedCard"><div className="cardTitle"><h3>Gespeicherte Anmeldungen</h3><span>{vault.length} Einträge</span></div>{vault.length===0 && <p className="emptyInline">Noch keine Vault-Anmeldungen. Neue Anmeldung oben hinzufügen.</p>}<div className="vaultList compact">{vault.map(v=><div key={v.id} className={v.id===selectedVault?'vaultItem visibleVaultItem active':'vaultItem visibleVaultItem'}><div className="vaultVisibleText" onClick={()=>editVault(v.id)} role="button" tabIndex={0}><b><span className="vaultMonoIcon">{v.authMode === 'key' ? 'KEY' : 'PWD'}</span> {v.name || 'Unbenannt'}</b><span>{v.username || 'ohne Benutzer'} · {v.authMode === 'key' ? ((v as any).privateKeySaved ? 'SSH-Key im Vault' : 'SSH-Key-Pfad') : ((v as any).passwordSaved ? 'Passwort gespeichert' : 'Passwort')} · {v.id.slice(0,8)}</span></div><div className="vaultCardActions"><button onClick={()=>editVault(v.id)}>Bearbeiten</button><button className="danger vaultMiniDelete" onClick={()=>deleteVaultEntry(v.id)}>Löschen</button></div></div>)}</div></section>
          </div>}
          {view==='settings' && <div className="settings"><h2>Einstellungen</h2>
            <section className="settingsCard appearanceCard"><h3>Darstellung</h3><p>Theme für Oberfläche und Terminal wählen.</p><label>Theme<div className="themePicker"><button className="themeTrigger" onClick={()=>setThemeMenuOpen(!themeMenuOpen)}>{themeOptions.find(t=>t.value===theme)?.label || 'Theme wählen'}<span>▾</span></button>{themeMenuOpen && <div className="themeMenu">{themeOptions.map(t=><button key={t.value} className={t.value===theme?'active':''} onClick={()=>{setTheme(t.value); setThemeMenuOpen(false);}}>{t.label}</button>)}</div>}</div></label></section>
            <section className="settingsCard updateSettingsCard" ref={updateSettingsRef}><h3>Updates</h3><p>Installiert: {info?.version}. Server: {release?.version || 'noch nicht geprüft'}.</p><div className="row updateActions"><button className="primary" onClick={checkUpdates}>Updates prüfen</button><button className="primary" disabled={!release || !selectedVersion || !semverGreater(selectedVersion, info?.version || '0.0.0') || installingUpdate} onClick={installSelectedUpdate}>{installingUpdate?'Installiere…':'Ausgewählte Version installieren'}</button></div>{compatibleVersions(release).length===0 && release && <p className="ok">Du bist auf dem neusten Stand.</p>}{installingUpdate && <p className="warn">Version wird installiert… App schließt sich und startet danach neu.</p>}{release && selectedVersion && selectedVersion !== info?.version && <p className="warn">Ausgewählt: {selectedVersion}</p>}{compatibleVersions(release).length ? <><div className="versionPicker"><label>Version auswählen</label><button className="versionTrigger" onClick={()=>setVersionMenuOpen(!versionMenuOpen)}>{selectedVersion || 'Version wählen'}<span>▾</span></button>{versionMenuOpen && <div className="versionMenu">{compatibleVersions(release).map(v=><button key={v.version} className={v.version===selectedVersion?'active':''} onClick={()=>{ setSelectedVersion(v.version); setVersionMenuOpen(false); }}>{v.version}</button>)}</div>}</div><p className="packageInfo">Kompatibles Paket: {selectedCompatibleAsset()?.name || 'kein kompatibles Paket'} · {selectedCompatibleAsset() ? fmt(selectedCompatibleAsset()!.size) : ''}</p>{selectedChangelog().length ? <div className="changelogBox"><b>Changelog {selectedVersion}</b><ul>{selectedChangelog().map((line, idx)=><li key={idx}>{line}</li>)}</ul></div> : <p className="syncStatus">Für diese Version ist kein Changelog hinterlegt.</p>}</> : null}</section>
            <section className="settingsCard" ref={localVaultSettingsRef}><h3>Lokaler Datensafe</h3><p>Passwörter, Sync-Token, Auto-Passphrase und eingebettete SSH-Keys werden lokal mit AES-GCM verschlüsselt. Ohne Entsperren bleiben Secret-Felder leer und Verbindungen mit gespeicherten Secrets gesperrt.</p><label>Tresor-Passphrase<input type="password" value={localVaultPass} onChange={e=>setLocalVaultPass(e.target.value)} placeholder="mind. 10 Zeichen"/></label><div className="row"><button className="primary" onClick={unlockLocalVault}>Entsperren</button><button onClick={encryptLocalVaultExisting}>Plaintext migrieren</button><button onClick={lockLocalVault}>Sperren</button><button onClick={refreshLocalVaultStatus}>Status prüfen</button></div><p className={localVault.plaintextSecrets ? 'warn' : localVault.unlocked ? 'ok' : 'syncStatus'}>{localVaultMsg}</p><p className="syncStatus">Status: {localVault.unlocked ? 'entsperrt' : 'gesperrt'} · verschlüsselt: {localVault.encryptedValues} · Plaintext-Secrets: {localVault.plaintextSecrets}</p></section>
            <section className="settingsCard"><h3>SSH Known Hosts</h3><p>Host-Keys sind Trust-Anker, keine Secrets. Sie liegen deshalb nicht im Vault, sondern in der App-Konfiguration. Neue Hosts werden erst nach Bestätigung gespeichert.</p><label>Pfad<input readOnly value={knownHosts.path || ''}/></label><div className="row"><button onClick={loadKnownHosts}>Neu laden</button></div><textarea readOnly className="knownHostsBox" value={knownHosts.content || ''} placeholder="Noch keine bekannten Host-Keys."/><p className="syncStatus">{knownHostsMsg}</p></section>
            <section className="settingsCard"><h3>Sync-Konto</h3><p>In der App meldest du dich nur an, damit der verschlüsselte Sync automatisch mit Token/Account gefüllt wird. Passwort, E-Mail und TOTP verwaltest du auf der Webseite.</p><label>Sync-Server<input value={accountLogin.endpoint || ''} onChange={e=>setAccountLogin({...accountLogin, endpoint:e.target.value})}/></label><label>Benutzername oder E-Mail<input value={accountLogin.username || ''} onChange={e=>setAccountLogin({...accountLogin, username:e.target.value})}/></label><label>Passwort<input type="password" value={accountLogin.password || ''} onChange={e=>setAccountLogin({...accountLogin, password:e.target.value})}/></label><div className="row"><button className="primary" disabled={accountLoginBusy} onClick={()=>loginSyncAccount()}>{accountLoginBusy?'Login läuft…':'Einloggen & Sync einrichten'}</button><button onClick={openAccountWeb}>Kontoverwaltung im Browser öffnen</button></div><p className={accountMsg.includes('fehlgeschlagen') || accountMsg.includes('entsperren') || accountMsg.includes('ungültig') ? 'warn' : accountMsg.includes('gespeichert') || accountMsg.includes('eingerichtet') ? 'ok' : 'syncStatus'}>{accountMsg}</p><p className="syncStatus">Registrierung, Passwort ändern, E-Mail ändern, TOTP aktivieren/deaktivieren und Token löschen: nur auf der Webseite. Falls TOTP aktiv ist, fragt die App den Code nach dem Passwort per Popup ab.</p></section>
            <section className="settingsCard" ref={syncSettingsRef}><h3>Verschlüsselter Sync</h3><p>Local-first. Ohne Aktivierung bleiben Hosts, Keys und Einstellungen nur lokal. Server speichert nur AES-GCM Ciphertext.</p><label><input type="checkbox" checked={syncCfg.enabled} onChange={e=>setSyncCfg({...syncCfg, enabled:e.target.checked})}/> Sync aktivieren</label><label>Sync-Server<input value={syncCfg.endpoint || defaultSyncServer} onChange={e=>setSyncCfg({...syncCfg, endpoint:e.target.value})}/></label><label>Account/Namespace<input value={syncCfg.account || ''} onChange={e=>setSyncCfg({...syncCfg, account:e.target.value})}/></label><label>Sync-Token<input type="password" value={syncCfg.token || ''} onChange={e=>setSyncCfg({...syncCfg, token:e.target.value})} placeholder={syncTokenPlaceholder(syncCfg)}/></label><label>Verschlüsselungs-Passphrase<input type="password" value={syncPass} onChange={e=>setSyncPass(e.target.value)} placeholder={syncPassPlaceholder(syncCfg, syncPass)}/></label><label><input type="checkbox" checked={!!syncCfg.includeKeys} onChange={e=>setSyncCfg({...syncCfg, includeKeys:e.target.checked})}/> SSH-Keys verschlüsselt mitsynchronisieren</label><div className="row" ref={syncActionsRef}><button onClick={()=>saveSync(true)}>Auto-Sync speichern</button><button className="primary" onClick={pushSync}>Jetzt hochladen</button><button onClick={pullSync}>Vom Server laden</button></div>{renderSyncNotice()}</section>
            <section className="settingsCard"><h3>Lokaler Export / Import</h3><p>Für Rechner ohne Sync-Service: Hosts + Tresor als verschlüsselte <code>.sshv2export</code>-Datei exportieren und auf anderem Gerät importieren. Vorher lokalen Datensafe entsperren.</p><label>Dateipfad<input value={transferPath} onChange={e=>setTransferPath(e.target.value)} placeholder="leer beim Export = ~/Downloads/ssh-vault2-export-....sshv2export"/></label><label>Export-Passphrase<input type="password" value={transferPass} onChange={e=>setTransferPass(e.target.value)} placeholder="mind. 10 Zeichen — auf Zielgerät nötig"/></label><label><input type="checkbox" checked={transferReplace} onChange={e=>setTransferReplace(e.target.checked)}/> Beim Import lokale Hosts/Tresor ersetzen statt zusammenführen</label><div className="row"><button className="primary" onClick={exportLocalData}>Verschlüsselt exportieren</button><button onClick={importLocalData}>Aus Datei importieren</button></div><p className="syncStatus">{transferMsg}</p></section>
            <section className="settingsCard"><h3>.ssh/config importieren</h3><p>Einmaliger, idempotenter Import vorhandener SSH-Hosts. Unterstützt Host, HostName, User, Port und IdentityFile. Wildcards werden übersprungen.</p><label>Pfad zur SSH Config<input value={sshConfigPath} onChange={e=>setSSHConfigPath(e.target.value)} placeholder="leer = ~/.ssh/config"/></label><div className="row"><button className="primary" onClick={importSSHConfig}>Jetzt importieren</button></div><p className="syncStatus">{importMsg}</p></section>
          </div>}
        </div>
      </div>
    </section>
  </div>;
}
export default App;
