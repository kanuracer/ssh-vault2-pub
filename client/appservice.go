package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const releaseServer = "https://ssh-vault.example.org"
const releaseSumsPublicKeyB64 = "vJeyJk2gpQ8XWilK/MseOuIWiw6llWP3NXbNPmw2HiQ="
const sshUnknownHostKeyPrefix = "SSH_HOST_KEY_UNKNOWN|"
const appVersion = "1.5.6"
const appHTTPTimeout = 20 * time.Second
const maxReleaseIndexBytes int64 = 2 * 1024 * 1024
const maxReleaseSumsBytes int64 = 1024 * 1024
const maxErrorBodyBytes int64 = 16 * 1024
const maxSyncBodyBytes int64 = 50 * 1024 * 1024
const maxReleaseArtifactBytes int64 = 500 * 1024 * 1024

func appHTTPClient() *http.Client { return &http.Client{Timeout: appHTTPTimeout} }

func readAllStrict(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("ungültiges Größenlimit")
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("Antwort zu groß (Limit %.1f MB)", float64(limit)/1024/1024)
	}
	return b, nil
}

func readErrorBody(r io.Reader) string {
	b, _ := readAllStrict(r, maxErrorBodyBytes)
	return strings.TrimSpace(string(cleanJSONBytes(b)))
}

func versionFromString(s string) string {
	re := regexp.MustCompile(`(?:^|[^0-9])(\d+\.\d+\.\d+)(?:[^0-9]|$)`)
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func compareSemver(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		parts := strings.Split(versionFromString(v), ".")
		if len(parts) == 0 || parts[0] == "" {
			parts = strings.Split(strings.TrimSpace(v), ".")
		}
		for i := 0; i < 3 && i < len(parts); i++ {
			fmt.Sscanf(parts[i], "%d", &out[i])
		}
		return out
	}
	A, B := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if A[i] > B[i] {
			return 1
		}
		if A[i] < B[i] {
			return -1
		}
	}
	return 0
}

func validateUpdateAssetForInstall(asset ReleaseAsset) error {
	v := versionFromString(asset.Name)
	if v == "" {
		return fmt.Errorf("Update-Artefakt enthält keine SemVer-Version")
	}
	if compareSemver(v, appVersion) <= 0 {
		return fmt.Errorf("Downgrade/Neuinstallation blockiert: installiert %s, angeboten %s", appVersion, v)
	}
	if asset.Size <= 0 {
		return fmt.Errorf("Update-Artefakt hat keine gültige Größe")
	}
	if asset.Size > maxReleaseArtifactBytes {
		return fmt.Errorf("Update-Artefakt zu groß")
	}
	if !strings.HasPrefix(asset.URL, "/downloads/") {
		return fmt.Errorf("ungültige Update-URL")
	}
	return nil
}

func normalizeSyncEndpoint(endpoint string) string {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" || endpoint == "https://ssh-vault.example.org" || endpoint == "https://192.0.2.117:18080" {
		return releaseServer
	}
	return endpoint
}
func validateSyncEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("Sync-Endpoint ungültig")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("Sync-Endpoint muss HTTPS nutzen (HTTP nur für localhost/127.0.0.1 im Dev-Modus)")
}

func sshDialAddress(h HostConfig) (string, error) {
	addr := strings.TrimSpace(h.Address)
	if addr == "" {
		return "", fmt.Errorf("Adresse fehlt")
	}
	if h.Port < 1 || h.Port > 65535 {
		return "", fmt.Errorf("ungültiger SSH-Port: %d", h.Port)
	}
	return net.JoinHostPort(addr, strconv.Itoa(h.Port)), nil
}

type HostConfig struct {
	ID                string   `json:"id"`
	Protocol          string   `json:"protocol,omitempty"`
	Name              string   `json:"name"`
	Address           string   `json:"address"`
	Port              int      `json:"port"`
	Username          string   `json:"username"`
	AuthMode          string   `json:"authMode"`
	KeyPath           string   `json:"keyPath,omitempty"`
	Password          string   `json:"password,omitempty"`
	PrivateKey        string   `json:"privateKey,omitempty"`
	PasswordSaved     bool     `json:"passwordSaved,omitempty"`
	PrivateKeySaved   bool     `json:"privateKeySaved,omitempty"`
	RDPEnabled        bool     `json:"rdpEnabled,omitempty"`
	RDPPort           int      `json:"rdpPort,omitempty"`
	RDPUsername       string   `json:"rdpUsername,omitempty"`
	RDPPassword       string   `json:"rdpPassword,omitempty"`
	RDPPasswordSaved  bool     `json:"rdpPasswordSaved,omitempty"`
	RDPDomain         string   `json:"rdpDomain,omitempty"`
	RDPWidth          int      `json:"rdpWidth,omitempty"`
	RDPHeight         int      `json:"rdpHeight,omitempty"`
	RDPScaleMode      string   `json:"rdpScaleMode,omitempty"`
	RDPKeyboardLayout string   `json:"rdpKeyboardLayout,omitempty"`
	VaultID           string   `json:"vaultId,omitempty"`
	Tags              []string `json:"tags"`
	Group             string   `json:"group,omitempty"`
}
type SessionState struct {
	ID        string `json:"id"`
	HostID    string `json:"hostId"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	StartedAt int64  `json:"startedAt"`
	Error     string `json:"error,omitempty"`
}
type SSHDataPayload struct {
	SessionID string `json:"sessionId"`
	Data      string `json:"data,omitempty"`
	DataB64   string `json:"dataB64,omitempty"`
	Seq       int    `json:"seq"`
}
type FileEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified,omitempty"`
	Mode     string `json:"mode,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	GID      uint32 `json:"gid,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Group    string `json:"group,omitempty"`
}
type TextFileContent struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified,omitempty"`
}

const textEditorMaxBytes int64 = 1024 * 1024

type AppInfo struct {
	Version   string `json:"version"`
	ConfigDir string `json:"configDir"`
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Server    string `json:"server"`
}
type KnownHostsView struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Count   int    `json:"count"`
}
type ReleaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type ReleaseVersion struct {
	Version   string         `json:"version"`
	Assets    []ReleaseAsset `json:"assets"`
	Changelog []string       `json:"changelog,omitempty"`
}
type ReleaseIndex struct {
	Version   string           `json:"version"`
	Versions  []ReleaseVersion `json:"versions"`
	Files     []ReleaseAsset   `json:"files"`
	Changelog []string         `json:"changelog,omitempty"`
}

func verifyReleaseSumsSignature(sumsBody, sigBody []byte) error {
	pubRaw, err := base64.StdEncoding.DecodeString(releaseSumsPublicKeyB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("Release-Signatur Public Key ungültig")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBody)))
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("Release-Signatur ungültig")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), sumsBody, sigRaw) {
		return fmt.Errorf("Release-Signaturprüfung fehlgeschlagen")
	}
	return nil
}
func parseReleaseSums(body []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && len(fields[0]) == 64 {
			name := filepath.Base(fields[1])
			out[name] = strings.ToLower(fields[0])
		}
	}
	return out
}
func fetchURLLimited(u string, limit int64) ([]byte, error) {
	res, err := appHTTPClient().Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail := readErrorBody(res.Body)
		if detail != "" {
			return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, detail)
		}
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return readAllStrict(res.Body, limit)
}
func fetchSignedReleaseSums() (map[string]string, error) {
	body, err := fetchURLLimited(releaseServer+"/SHA256SUMS.txt", maxReleaseSumsBytes)
	if err != nil {
		return nil, fmt.Errorf("Release-Checksums nicht ladbar: %w", err)
	}
	sig, err := fetchURLLimited(releaseServer+"/SHA256SUMS.txt.sig", 4096)
	if err != nil {
		return nil, fmt.Errorf("Release-Signatur nicht ladbar: %w", err)
	}
	if err = verifyReleaseSumsSignature(body, sig); err != nil {
		return nil, err
	}
	sums := parseReleaseSums(body)
	if len(sums) == 0 {
		return nil, fmt.Errorf("Release-Checksums leer")
	}
	return sums, nil
}

type SFTPConnectResult struct {
	ID   string `json:"id"`
	Home string `json:"home"`
}

type SyncConfig struct {
	Enabled             bool   `json:"enabled"`
	Endpoint            string `json:"endpoint"`
	Account             string `json:"account"`
	Token               string `json:"token,omitempty"`
	TokenSaved          bool   `json:"tokenSaved,omitempty"`
	IncludeKeys         bool   `json:"includeKeys"`
	LastSync            int64  `json:"lastSync,omitempty"`
	AutoPassphrase      string `json:"autoPassphrase,omitempty"`
	AutoPassphraseSaved bool   `json:"autoPassphraseSaved,omitempty"`
}
type SyncAccountRequest struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`
	Label    string `json:"label,omitempty"`
	TOTP     string `json:"totp,omitempty"`
}
type SyncAccountResult struct {
	Token        string `json:"token"`
	Account      string `json:"account"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
	TOTPRequired bool   `json:"totpRequired,omitempty"`
}
type SyncKey struct {
	HostID  string `json:"hostId"`
	Name    string `json:"name"`
	Content string `json:"content"`
}
type SyncPayload struct {
	Version  int               `json:"version"`
	Hosts    []HostConfig      `json:"hosts"`
	Vault    []VaultCredential `json:"vault,omitempty"`
	Keys     []SyncKey         `json:"keys,omitempty"`
	Settings map[string]string `json:"settings,omitempty"`
	SyncedAt int64             `json:"syncedAt"`
}
type EncryptedSyncBlob struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	UpdatedAt  int64  `json:"updatedAt"`
}
type SyncResult struct {
	OK         bool   `json:"ok"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	VaultCount int    `json:"vaultCount"`
}
type LocalTransferResult struct {
	OK         bool   `json:"ok"`
	Message    string `json:"message"`
	Path       string `json:"path"`
	Count      int    `json:"count"`
	VaultCount int    `json:"vaultCount"`
}
type VaultCredential struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	AuthMode        string `json:"authMode"`
	Password        string `json:"password,omitempty"`
	KeyPath         string `json:"keyPath,omitempty"`
	PrivateKey      string `json:"privateKey,omitempty"`
	PasswordSaved   bool   `json:"passwordSaved,omitempty"`
	PrivateKeySaved bool   `json:"privateKeySaved,omitempty"`
}
type ImportResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Count   int    `json:"count"`
}
type LocalVaultStatus struct {
	Configured       bool   `json:"configured"`
	Unlocked         bool   `json:"unlocked"`
	EncryptedValues  int    `json:"encryptedValues"`
	PlaintextSecrets int    `json:"plaintextSecrets"`
	Message          string `json:"message"`
}

type sshRec struct {
	state     SessionState
	client    *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	out       chan []byte
	done      chan struct{}
	closeOnce sync.Once
}
type uploadState struct {
	path string
	tmp  string
	next int64
}
type sftpRec struct {
	id      string
	hostID  string
	client  *ssh.Client
	sftp    *sftp.Client
	cwd     string
	mu      sync.Mutex
	closed  bool
	uploads map[string]*uploadState
}

type AppService struct {
	app      *application.App
	mu       sync.Mutex
	dataMu   sync.Mutex
	ssh      map[string]*sshRec
	sftps    map[string]*sftpRec
	rdps     map[string]*rdpRec
	render   *RDPRenderHub
	localKey []byte
}

func NewAppService() *AppService {
	render, err := NewRDPRenderHub()
	if err != nil {
		appLog("RDP render hub unavailable: %v", err)
	}
	return &AppService{ssh: map[string]*sshRec{}, sftps: map[string]*sftpRec{}, rdps: map[string]*rdpRec{}, render: render}
}
func (s *AppService) setApp(app *application.App) { s.app = app }
func appLog(format string, args ...any) {
	d, e := configDir()
	if e != nil {
		return
	}
	f, e := os.OpenFile(filepath.Join(d, "debug.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, time.Now().Format(time.RFC3339)+" "+format+"\n", args...)
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "ssh-vault2")
	return dir, os.MkdirAll(dir, 0700)
}
func hostsPath() (string, error) {
	d, e := configDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "hosts.json"), nil
}
func vaultPath() (string, error) {
	d, e := configDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "vault.json"), nil
}
func knownHostsPath() (string, error) {
	d, e := configDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "known_hosts"), nil
}

func localVaultSaltPath() (string, error) {
	d, e := configDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "local-vault.salt"), nil
}

const encPrefix = "enc:v1:"

func secureWriteFile(p string, b []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := rejectSymlinkPath(dir); err != nil {
		return err
	}
	var tmp string
	var f *os.File
	var err error
	for i := 0; i < 16; i++ {
		var rb [12]byte
		if _, err = rand.Read(rb[:]); err != nil {
			return err
		}
		tmp = filepath.Join(dir, "."+filepath.Base(p)+"."+base64.RawURLEncoding.EncodeToString(rb[:])+".tmp")
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		break
	}
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup && tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, p); err != nil {
		return err
	}
	cleanup = false
	_ = os.Chmod(p, 0600)
	if d, e := os.Open(dir); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
func secureWriteJSON(p string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	return secureWriteFile(p, b)
}
func isEncryptedValue(v string) bool { return strings.HasPrefix(strings.TrimSpace(v), encPrefix) }
func (s *AppService) localKeyCopy() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.localKey) == 0 {
		return nil
	}
	k := make([]byte, len(s.localKey))
	copy(k, s.localKey)
	return k
}
func (s *AppService) setLocalKey(k []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localKey = k
}
func localVaultSalt(create bool) ([]byte, error) {
	p, e := localVaultSaltPath()
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if e == nil && len(bytes.TrimSpace(b)) > 0 {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	}
	if !create {
		return nil, e
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	if e := secureWriteFile(p, []byte(base64.StdEncoding.EncodeToString(salt)+"\n")); e != nil {
		return nil, e
	}
	return salt, nil
}
func deriveLocalVaultKey(passphrase string, create bool) ([]byte, error) {
	passphrase = strings.TrimSpace(passphrase)
	if len(passphrase) < 10 {
		return nil, fmt.Errorf("Lokale Tresor-Passphrase braucht mindestens 10 Zeichen")
	}
	salt, e := localVaultSalt(create)
	if e != nil {
		return nil, e
	}
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}
func (s *AppService) encryptSecret(v string) (string, error) {
	if strings.TrimSpace(v) == "" || isEncryptedValue(v) {
		return v, nil
	}
	key := s.localKeyCopy()
	if len(key) == 0 {
		return "", fmt.Errorf("Lokaler Tresor gesperrt: erst entsperren, dann Passwörter/Keys speichern")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	ct := gcm.Seal(nil, nonce, []byte(v), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ct), nil
}
func (s *AppService) decryptSecret(v string, blankWhenLocked bool) (string, error) {
	if !isEncryptedValue(v) {
		return v, nil
	}
	key := s.localKeyCopy()
	if len(key) == 0 {
		if blankWhenLocked {
			return "", nil
		}
		return "", fmt.Errorf("Lokaler Tresor gesperrt")
	}
	parts := strings.Split(strings.TrimPrefix(v, encPrefix), ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("verschlüsselter Wert ungültig")
	}
	nonce, e := base64.StdEncoding.DecodeString(parts[0])
	if e != nil {
		return "", e
	}
	ct, e := base64.StdEncoding.DecodeString(parts[1])
	if e != nil {
		return "", e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	plain, e := gcm.Open(nil, nonce, ct, nil)
	if e != nil {
		return "", fmt.Errorf("Lokaler Tresor: Passphrase falsch oder Daten beschädigt")
	}
	return string(plain), nil
}
func (s *AppService) decryptHostSecrets(h HostConfig, blankWhenLocked bool) (HostConfig, error) {
	var e error
	h.Password, e = s.decryptSecret(h.Password, blankWhenLocked)
	if e != nil {
		return h, e
	}
	h.PrivateKey, e = s.decryptSecret(h.PrivateKey, blankWhenLocked)
	if e != nil {
		return h, e
	}
	h.RDPPassword, e = s.decryptSecret(h.RDPPassword, blankWhenLocked)
	if e != nil {
		return h, e
	}
	return h, nil
}
func (s *AppService) encryptHostSecrets(h HostConfig) (HostConfig, error) {
	var e error
	h.Password, e = s.encryptSecret(h.Password)
	if e != nil {
		return h, e
	}
	h.PrivateKey, e = s.encryptSecret(h.PrivateKey)
	if e != nil {
		return h, e
	}
	h.RDPPassword, e = s.encryptSecret(h.RDPPassword)
	if e != nil {
		return h, e
	}
	return h, nil
}
func (s *AppService) decryptVaultSecrets(v VaultCredential, blankWhenLocked bool) (VaultCredential, error) {
	var e error
	v.Password, e = s.decryptSecret(v.Password, blankWhenLocked)
	if e != nil {
		return v, e
	}
	v.PrivateKey, e = s.decryptSecret(v.PrivateKey, blankWhenLocked)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (s *AppService) encryptVaultSecrets(v VaultCredential) (VaultCredential, error) {
	var e error
	v.Password, e = s.encryptSecret(v.Password)
	if e != nil {
		return v, e
	}
	v.PrivateKey, e = s.encryptSecret(v.PrivateKey)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (s *AppService) decryptSyncSecrets(c SyncConfig, blankWhenLocked bool) (SyncConfig, error) {
	var e error
	rawToken := c.Token
	rawAutoPassphrase := c.AutoPassphrase
	c.TokenSaved = strings.TrimSpace(rawToken) != ""
	c.AutoPassphraseSaved = strings.TrimSpace(rawAutoPassphrase) != ""
	c.Token, e = s.decryptSecret(rawToken, blankWhenLocked)
	if e != nil {
		return c, e
	}
	c.AutoPassphrase, e = s.decryptSecret(rawAutoPassphrase, blankWhenLocked)
	if e != nil {
		return c, e
	}
	if strings.TrimSpace(c.Token) != "" {
		c.TokenSaved = true
	}
	if strings.TrimSpace(c.AutoPassphrase) != "" {
		c.AutoPassphraseSaved = true
	}
	return c, nil
}
func (s *AppService) encryptSyncSecrets(c SyncConfig) (SyncConfig, error) {
	var e error
	c.Token, e = s.encryptSecret(c.Token)
	if e != nil {
		return c, e
	}
	c.AutoPassphrase, e = s.encryptSecret(c.AutoPassphrase)
	if e != nil {
		return c, e
	}
	return c, nil
}

func cleanJSONBytes(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}
func validUUID(v string) bool { _, err := uuid.Parse(strings.TrimSpace(v)); return err == nil }
func safeRecordID(v string) string {
	v = strings.TrimSpace(v)
	if validUUID(v) {
		return v
	}
	return uuid.NewString()
}
func stableHostID(h HostConfig) string {
	proto := strings.ToLower(strings.TrimSpace(h.Protocol))
	if proto == "" {
		if h.RDPEnabled {
			proto = "rdp"
		} else {
			proto = "ssh"
		}
	}
	if proto != "rdp" {
		proto = "ssh"
	}
	seed := strings.Join([]string{
		proto,
		strings.ToLower(strings.TrimSpace(h.Name)),
		strings.ToLower(strings.TrimSpace(h.Address)),
		fmt.Sprintf("%d", h.Port),
		fmt.Sprintf("%d", h.RDPPort),
		strings.ToLower(strings.TrimSpace(h.Username)),
		strings.ToLower(strings.TrimSpace(h.RDPUsername)),
	}, "\x1f")
	if strings.Trim(seed, "\x1f0") == "" {
		return uuid.NewString()
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("ssh-vault2-host:"+seed)).String()
}

func normHost(h HostConfig) HostConfig {
	h.Protocol = strings.ToLower(strings.TrimSpace(h.Protocol))
	if h.Protocol == "" {
		if h.RDPEnabled {
			h.Protocol = "rdp"
		} else {
			h.Protocol = "ssh"
		}
	}
	if h.Protocol != "rdp" {
		h.Protocol = "ssh"
	}
	h.Name = strings.TrimSpace(h.Name)
	h.Address = strings.TrimSpace(h.Address)
	h.Username = strings.TrimSpace(h.Username)
	h.RDPUsername = strings.TrimSpace(h.RDPUsername)
	h.RDPDomain = strings.TrimSpace(h.RDPDomain)
	if !validUUID(h.ID) {
		h.ID = stableHostID(h)
	}
	if h.Protocol == "rdp" {
		h.RDPEnabled = true
		if h.RDPUsername == "" {
			h.RDPUsername = h.Username
		}
		if h.RDPPort == 0 {
			h.RDPPort = 3389
		}
		h.RDPScaleMode = strings.ToLower(strings.TrimSpace(h.RDPScaleMode))
		if h.RDPScaleMode != "sharp" && h.RDPScaleMode != "fit" && h.RDPScaleMode != "original" {
			h.RDPScaleMode = "smart"
		}
		h.RDPKeyboardLayout = normalizeRDPKeyboardLayout(h.RDPKeyboardLayout)
		if h.RDPWidth == 0 {
			h.RDPWidth = 1280
		}
		if h.RDPHeight == 0 {
			h.RDPHeight = 720
		}
		if h.RDPWidth < 640 {
			h.RDPWidth = 640
		}
		if h.RDPHeight < 480 {
			h.RDPHeight = 480
		}
		if h.RDPWidth > 3840 {
			h.RDPWidth = 3840
		}
		if h.RDPHeight > 2160 {
			h.RDPHeight = 2160
		}
	} else {
		h.RDPEnabled = false
		h.RDPPort = 0
		h.RDPUsername = ""
		h.RDPPassword = ""
		h.RDPDomain = ""
		h.RDPWidth = 0
		h.RDPHeight = 0
		h.RDPScaleMode = ""
		h.RDPKeyboardLayout = ""
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.AuthMode == "" {
		h.AuthMode = "agent"
	}
	if h.Protocol == "ssh" && h.Username == "" {
		if u, err := user.Current(); err == nil {
			h.Username = u.Username
		}
	}
	if h.Name == "" {
		h.Name = h.Address
	}
	tags := []string{}
	for _, t := range h.Tags {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}
	h.Tags = tags
	return h
}
func (s *AppService) Info() (AppInfo, error) {
	d, e := configDir()
	return AppInfo{Version: appVersion, ConfigDir: d, Platform: runtime.GOOS, Arch: runtime.GOARCH, Server: releaseServer}, e
}
func (s *AppService) OpenExternalURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("ungültige Web-URL")
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u.String()).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Start()
	default:
		return exec.Command("xdg-open", u.String()).Start()
	}
}

func (s *AppService) readHostsRaw() ([]HostConfig, error) {
	p, e := hostsPath()
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if errors.Is(e, os.ErrNotExist) {
		return []HostConfig{}, nil
	}
	if e != nil {
		return nil, e
	}
	var hs []HostConfig
	clean := cleanJSONBytes(b)
	if e = json.Unmarshal(clean, &hs); e != nil {
		var single HostConfig
		if e2 := json.Unmarshal(clean, &single); e2 != nil {
			return nil, e
		}
		hs = []HostConfig{single}
		_ = writeHostsRaw(s, hs)
	}
	for i := range hs {
		hs[i] = normHost(hs[i])
	}
	return hs, nil
}
func (s *AppService) readVaultRaw() ([]VaultCredential, error) {
	p, e := vaultPath()
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if errors.Is(e, os.ErrNotExist) {
		return []VaultCredential{}, nil
	}
	if e != nil {
		return nil, e
	}
	var vs []VaultCredential
	clean := cleanJSONBytes(b)
	if e = json.Unmarshal(clean, &vs); e != nil {
		var single VaultCredential
		if e2 := json.Unmarshal(clean, &single); e2 != nil {
			return nil, e
		}
		vs = []VaultCredential{single}
		_ = writeVaultRaw(s, vs)
	}
	for i := range vs {
		vs[i] = normVaultCredential(vs[i])
	}
	return vs, nil
}
func countSecretState(hs []HostConfig, vs []VaultCredential, c SyncConfig) (enc, plain int) {
	vals := []string{c.Token, c.AutoPassphrase}
	for _, h := range hs {
		vals = append(vals, h.Password, h.PrivateKey, h.RDPPassword)
	}
	for _, v := range vs {
		vals = append(vals, v.Password, v.PrivateKey)
	}
	for _, v := range vals {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if isEncryptedValue(v) {
			enc++
		} else {
			plain++
		}
	}
	return
}
func (s *AppService) LocalVaultStatus() (LocalVaultStatus, error) {
	_ = s.hardenLocalFiles()
	hs, _ := s.readHostsRaw()
	vs, _ := s.readVaultRaw()
	c, _ := s.getSyncConfigRaw()
	enc, plain := countSecretState(hs, vs, c)
	st := LocalVaultStatus{Configured: enc > 0, Unlocked: len(s.localKeyCopy()) > 0, EncryptedValues: enc, PlaintextSecrets: plain}
	if plain > 0 {
		st.Message = fmt.Sprintf("%d lokale Secret-Werte sind noch unverschlüsselt", plain)
	}
	if st.Configured && !st.Unlocked {
		st.Message = "Lokaler Tresor gesperrt"
	}
	if st.Unlocked {
		st.Message = "Lokaler Tresor entsperrt"
	}
	return st, nil
}
func (s *AppService) LocalVaultUnlock(passphrase string) (LocalVaultStatus, error) {
	key, e := deriveLocalVaultKey(passphrase, true)
	if e != nil {
		return LocalVaultStatus{}, e
	}
	s.setLocalKey(key)
	// verify against first encrypted value, if present
	hs, _ := s.readHostsRaw()
	vs, _ := s.readVaultRaw()
	c, _ := s.getSyncConfigRaw()
	for _, v := range append([]string{c.Token, c.AutoPassphrase}, collectSecretValues(hs, vs)...) {
		if isEncryptedValue(v) {
			if _, e := s.decryptSecret(v, false); e != nil {
				s.setLocalKey(nil)
				return LocalVaultStatus{}, e
			}
			break
		}
	}
	return s.LocalVaultStatus()
}
func collectSecretValues(hs []HostConfig, vs []VaultCredential) []string {
	out := []string{}
	for _, h := range hs {
		out = append(out, h.Password, h.PrivateKey, h.RDPPassword)
	}
	for _, v := range vs {
		out = append(out, v.Password, v.PrivateKey)
	}
	return out
}
func (s *AppService) LocalVaultLock() (LocalVaultStatus, error) {
	s.setLocalKey(nil)
	return s.LocalVaultStatus()
}
func (s *AppService) LocalVaultEncryptExisting(passphrase string) (LocalVaultStatus, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if _, e := s.LocalVaultUnlock(passphrase); e != nil {
		return LocalVaultStatus{}, e
	}
	hs, e := s.readHostsRaw()
	if e != nil {
		return LocalVaultStatus{}, e
	}
	if e = writeHostsRaw(s, hs); e != nil {
		return LocalVaultStatus{}, e
	}
	vs, e := s.readVaultRaw()
	if e != nil {
		return LocalVaultStatus{}, e
	}
	if e = writeVaultRaw(s, vs); e != nil {
		return LocalVaultStatus{}, e
	}
	c, e := s.getSyncConfigRaw()
	if e == nil {
		_, _ = s.saveSyncConfigRaw(c)
	}
	return s.LocalVaultStatus()
}
func (s *AppService) hardenLocalFiles() error {
	d, e := configDir()
	if e != nil {
		return e
	}
	_ = os.Chmod(d, 0700)
	for _, name := range []string{"hosts.json", "vault.json", "sync.json", "local-vault.salt"} {
		p := filepath.Join(d, name)
		if _, e := os.Stat(p); e == nil {
			_ = os.Chmod(p, 0600)
		}
	}
	return nil
}
func sanitizeHostForRenderer(h HostConfig) HostConfig {
	h.PasswordSaved = strings.TrimSpace(h.Password) != ""
	h.PrivateKeySaved = strings.TrimSpace(h.PrivateKey) != ""
	h.RDPPasswordSaved = strings.TrimSpace(h.RDPPassword) != ""
	h.Password = ""
	h.PrivateKey = ""
	h.RDPPassword = ""
	return h
}
func sanitizeVaultForRenderer(v VaultCredential) VaultCredential {
	v.PasswordSaved = strings.TrimSpace(v.Password) != ""
	v.PrivateKeySaved = strings.TrimSpace(v.PrivateKey) != ""
	v.Password = ""
	v.PrivateKey = ""
	return v
}
func (s *AppService) listHostsDecrypted(blankWhenLocked bool) ([]HostConfig, error) {
	hs, e := s.readHostsRaw()
	if e != nil {
		return nil, e
	}
	for i := range hs {
		hs[i], _ = s.decryptHostSecrets(hs[i], blankWhenLocked)
	}
	sort.Slice(hs, func(i, j int) bool { return strings.ToLower(hs[i].Name) < strings.ToLower(hs[j].Name) })
	return hs, nil
}
func (s *AppService) listVaultDecrypted(blankWhenLocked bool) ([]VaultCredential, error) {
	vs, e := s.readVaultRaw()
	if e != nil {
		return nil, e
	}
	for i := range vs {
		vs[i], _ = s.decryptVaultSecrets(vs[i], blankWhenLocked)
	}
	sort.Slice(vs, func(i, j int) bool { return strings.ToLower(vs[i].Name) < strings.ToLower(vs[j].Name) })
	return vs, nil
}
func (s *AppService) ListHosts() ([]HostConfig, error) {
	hs, e := s.listHostsDecrypted(true)
	if e != nil {
		return nil, e
	}
	for i := range hs {
		hs[i] = sanitizeHostForRenderer(hs[i])
	}
	return hs, nil
}
func (s *AppService) SaveHost(h HostConfig) ([]HostConfig, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	h = normHost(h)
	if h.Address == "" {
		return nil, fmt.Errorf("Adresse fehlt")
	}
	hs, e := s.readHostsRaw()
	if e != nil {
		return nil, e
	}
	found := false
	for i := range hs {
		if hs[i].ID == h.ID {
			if h.Protocol == "ssh" {
				if h.Password == "" && strings.TrimSpace(hs[i].Password) != "" {
					h.Password = hs[i].Password
				}
				if h.PrivateKey == "" && strings.TrimSpace(hs[i].PrivateKey) != "" {
					h.PrivateKey = hs[i].PrivateKey
				}
			}
			if h.Protocol == "rdp" && h.RDPPassword == "" && strings.TrimSpace(hs[i].RDPPassword) != "" {
				h.RDPPassword = hs[i].RDPPassword
			}
			hs[i] = h
			found = true
			break
		}
	}
	if !found {
		hs = append(hs, h)
	}
	if e := writeHostsRaw(s, hs); e != nil {
		return nil, e
	}
	return s.ListHosts()
}
func (s *AppService) DeleteHost(id string) ([]HostConfig, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	hs, e := s.readHostsRaw()
	if e != nil {
		return nil, e
	}
	out := []HostConfig{}
	for _, h := range hs {
		if h.ID != id {
			out = append(out, h)
		}
	}
	if e := writeHostsRaw(s, out); e != nil {
		return nil, e
	}
	return s.ListHosts()
}

func normVaultCredential(v VaultCredential) VaultCredential {
	if !validUUID(v.ID) {
		v.ID = uuid.NewString()
	}
	v.Name = strings.TrimSpace(v.Name)
	v.Username = strings.TrimSpace(v.Username)
	v.AuthMode = strings.TrimSpace(v.AuthMode)
	if v.AuthMode == "" {
		if strings.TrimSpace(v.KeyPath) != "" || strings.TrimSpace(v.PrivateKey) != "" {
			v.AuthMode = "key"
		} else {
			v.AuthMode = "password"
		}
	}
	if v.Name == "" {
		v.Name = v.Username
		if v.Name == "" {
			v.Name = "Vault Login"
		}
	}
	return v
}
func (s *AppService) ListVault() ([]VaultCredential, error) {
	vs, e := s.listVaultDecrypted(true)
	if e != nil {
		return nil, e
	}
	for i := range vs {
		vs[i] = sanitizeVaultForRenderer(vs[i])
	}
	return vs, nil
}
func (s *AppService) SaveVault(v VaultCredential) ([]VaultCredential, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	v = normVaultCredential(v)
	vs, e := s.readVaultRaw()
	if e != nil {
		return nil, e
	}
	found := false
	for i := range vs {
		if vs[i].ID == v.ID {
			if v.Password == "" && strings.TrimSpace(vs[i].Password) != "" {
				v.Password = vs[i].Password
			}
			if v.PrivateKey == "" && strings.TrimSpace(vs[i].PrivateKey) != "" {
				v.PrivateKey = vs[i].PrivateKey
			}
			if v.KeyPath == "" && strings.TrimSpace(vs[i].KeyPath) != "" {
				v.KeyPath = vs[i].KeyPath
			}
			vs[i] = v
			found = true
			break
		}
	}
	if v.Username == "" {
		return nil, fmt.Errorf("Vault: Benutzer fehlt")
	}
	if v.AuthMode == "password" && v.Password == "" {
		return nil, fmt.Errorf("Vault: Passwort fehlt")
	}
	if v.AuthMode == "key" && strings.TrimSpace(v.KeyPath) == "" && strings.TrimSpace(v.PrivateKey) == "" {
		return nil, fmt.Errorf("Vault: SSH-Key oder Key-Pfad fehlt")
	}
	if !found {
		vs = append(vs, v)
	}
	if e := writeVaultRaw(s, vs); e != nil {
		return nil, e
	}
	return s.ListVault()
}
func (s *AppService) DeleteVault(id string) ([]VaultCredential, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	vs, e := s.readVaultRaw()
	if e != nil {
		return nil, e
	}
	out := []VaultCredential{}
	for _, v := range vs {
		if v.ID != id {
			out = append(out, v)
		}
	}
	if e := writeVaultRaw(s, out); e != nil {
		return nil, e
	}
	return s.ListVault()
}
func readPrivateKeyFileForImport(keyPath string) (string, string, error) {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return "", "", fmt.Errorf("Key-Pfad fehlt")
	}
	b, cleanPath, err := readAllowedSmallLocalFile(keyPath, 1024*1024)
	if err != nil {
		return "", "", err
	}
	text := strings.TrimSpace(string(b))
	if !strings.Contains(text, "PRIVATE KEY") {
		return "", "", fmt.Errorf("Datei sieht nicht wie ein privater SSH-Key aus")
	}
	return text + "\n", cleanPath, nil
}
func (s *AppService) ImportVaultKeyFile(vaultID string, keyPath string) (ImportResult, error) {
	vaultID = strings.TrimSpace(vaultID)
	if vaultID == "" {
		return ImportResult{}, fmt.Errorf("Vault-Eintrag zuerst speichern, dann Key importieren")
	}
	text, cleanKeyPath, err := readPrivateKeyFileForImport(keyPath)
	if err != nil {
		return ImportResult{}, err
	}
	vs, err := s.readVaultRaw()
	if err != nil {
		return ImportResult{}, err
	}
	found := false
	for i := range vs {
		if vs[i].ID == vaultID {
			vs[i].PrivateKey = text
			vs[i].KeyPath = cleanKeyPath
			vs[i].AuthMode = "key"
			found = true
			break
		}
	}
	if !found {
		return ImportResult{}, fmt.Errorf("Vault-Eintrag nicht gefunden")
	}
	if err = writeVaultRaw(s, vs); err != nil {
		return ImportResult{}, err
	}
	return ImportResult{OK: true, Message: "Private Key backendseitig importiert", Count: 1}, nil
}
func (s *AppService) resolveHostCredential(h HostConfig) (HostConfig, error) {
	h = normHost(h)
	if strings.TrimSpace(h.VaultID) == "" {
		return h, nil
	}
	vs, e := s.listVaultDecrypted(false)
	if e != nil {
		return h, e
	}
	for _, v := range vs {
		if v.ID == h.VaultID {
			v = normVaultCredential(v)
			h.Username = v.Username
			h.AuthMode = v.AuthMode
			h.Password = v.Password
			h.KeyPath = v.KeyPath
			h.PrivateKey = v.PrivateKey
			return h, nil
		}
	}
	return h, fmt.Errorf("Vault-Anmeldung nicht gefunden")
}

func expand(p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
func parseSSHPrivateKey(b []byte, passphrase string) (ssh.Signer, error) {
	passphrase = strings.TrimSpace(passphrase)
	if passphrase != "" {
		if signer, err := ssh.ParsePrivateKeyWithPassphrase(b, []byte(passphrase)); err == nil {
			return signer, nil
		} else if signer, noPassErr := ssh.ParsePrivateKey(b); noPassErr == nil {
			// User filled the passphrase field for an unencrypted key. Accept the key and ignore that field.
			return signer, nil
		} else if strings.Contains(err.Error(), "no key found") || strings.Contains(err.Error(), "unsupported") {
			return nil, fmt.Errorf("SSH-Key kann nicht gelesen werden: Format nicht unterstützt oder kein privater Key. Unterstützt OpenSSH/PEM; PuTTY .ppk bitte vorher in OpenSSH konvertieren")
		} else {
			return nil, fmt.Errorf("SSH-Key kann nicht gelesen werden: Key-Passphrase falsch oder Key-Format ungültig (%v)", err)
		}
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err == nil {
		return signer, nil
	}
	if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "encrypted") {
		return nil, fmt.Errorf("SSH-Key ist verschlüsselt: bitte Key-Passphrase eintragen (nicht das Login-Passwort)")
	}
	if strings.Contains(err.Error(), "no key found") || strings.Contains(err.Error(), "unsupported") {
		return nil, fmt.Errorf("SSH-Key kann nicht gelesen werden: Format nicht unterstützt oder kein privater Key. Unterstützt OpenSSH/PEM; PuTTY .ppk bitte vorher in OpenSSH konvertieren")
	}
	return nil, fmt.Errorf("SSH-Key kann nicht gelesen werden: %v", err)
}
func appendKnownHost(p, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	hosts := []string{}
	seen := map[string]bool{}
	for _, h := range []string{hostname, func() string {
		if remote != nil {
			return remote.String()
		}
		return ""
	}()} {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return fmt.Errorf("SSH Host-Key konnte nicht gespeichert werden: Hostname fehlt")
	}
	line := knownhosts.Line(hosts, key)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = fmt.Fprintln(f, line); err != nil {
		return err
	}
	return os.Chmod(p, 0600)
}
func hostKeyUnknownError(hostname string, key ssh.PublicKey, p string) error {
	return fmt.Errorf("%s%s|%s|%s", sshUnknownHostKeyPrefix, hostname, ssh.FingerprintSHA256(key), p)
}
func (s *AppService) hostKeyCallbackWithExpectedFingerprint(trustUnknown bool, expectedFingerprint string) (ssh.HostKeyCallback, error) {
	expectedFingerprint = strings.TrimSpace(expectedFingerprint)
	p, err := knownHostsPath()
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(p); errors.Is(err, os.ErrNotExist) {
		if err = secureWriteFile(p, []byte("")); err != nil {
			return nil, err
		}
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				if !trustUnknown {
					return hostKeyUnknownError(hostname, key, p)
				}
				actual := ssh.FingerprintSHA256(key)
				if expectedFingerprint != "" && actual != expectedFingerprint {
					return fmt.Errorf("SSH Host-Key Fingerprint stimmt nicht überein: erwartet %s, erhalten %s", expectedFingerprint, actual)
				}
				if e := appendKnownHost(p, hostname, remote, key); e != nil {
					return e
				}
				return nil
			}
			fp := ssh.FingerprintSHA256(key)
			return fmt.Errorf("SSH Host-Key geändert für %s (%s). Verbindung blockiert. Prüfe den Fingerprint und entferne bei legitimer Änderung den alten Eintrag in Einstellungen → SSH Known Hosts (%s)", hostname, fp, p)
		}
		return err
	}, nil
}
func (s *AppService) sshConfig(h HostConfig, trustUnknown bool) (*ssh.ClientConfig, error) {
	return s.sshConfigWithExpectedFingerprint(h, trustUnknown, "")
}
func (s *AppService) sshConfigWithExpectedFingerprint(h HostConfig, trustUnknown bool, expectedFingerprint string) (*ssh.ClientConfig, error) {
	var err error
	h, err = s.resolveHostCredential(h)
	if err != nil {
		return nil, err
	}
	methods := []ssh.AuthMethod{}
	switch h.AuthMode {
	case "password":
		if h.Password == "" {
			return nil, fmt.Errorf("Passwort fehlt")
		}
		methods = append(methods, ssh.Password(h.Password))
	case "key":
		var b []byte
		if h.PrivateKey != "" {
			b = []byte(h.PrivateKey)
		} else {
			if h.KeyPath == "" {
				return nil, fmt.Errorf("Key-Pfad fehlt")
			}
			data, _, e := readAllowedSmallLocalFile(h.KeyPath, 1024*1024)
			if e != nil {
				return nil, e
			}
			text := strings.TrimSpace(string(data))
			if isEncryptedValue(text) {
				text, e = s.decryptSecret(text, false)
				if e != nil {
					return nil, e
				}
				data = []byte(text)
			}
			b = data
		}
		signer, e := parseSSHPrivateKey(b, h.Password)
		if e != nil {
			return nil, e
		}
		methods = append(methods, ssh.PublicKeys(signer))
	default:
		return nil, fmt.Errorf("Agent-Auth noch nicht implementiert; bitte Key oder Passwort wählen")
	}
	cb, err := s.hostKeyCallbackWithExpectedFingerprint(trustUnknown, expectedFingerprint)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: h.Username, Auth: methods, HostKeyCallback: cb, Timeout: 15 * time.Second}, nil
}
func (s *AppService) KnownHostsInfo() (KnownHostsView, error) {
	p, err := knownHostsPath()
	if err != nil {
		return KnownHostsView{}, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return KnownHostsView{Path: p, Content: "", Count: 0}, nil
	}
	if err != nil {
		return KnownHostsView{}, err
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return KnownHostsView{Path: p, Content: string(b), Count: count}, nil
}

func (s *AppService) TrustSSHHost(hostID string, expectedFingerprint string) (string, error) {
	h, e := s.hostByID(hostID)
	if e != nil {
		return "", e
	}
	cfg, e := s.sshConfigWithExpectedFingerprint(h, true, expectedFingerprint)
	if e != nil {
		return "", e
	}
	addr, e := sshDialAddress(h)
	if e != nil {
		return "", e
	}
	c, e := ssh.Dial("tcp", addr, cfg)
	if e == nil {
		_ = c.Close()
		return "SSH Host-Key gespeichert und Verbindung geprüft.", nil
	}
	if strings.Contains(e.Error(), sshUnknownHostKeyPrefix) || strings.Contains(e.Error(), "Host-Key geändert") {
		return "", e
	}
	return "SSH Host-Key gespeichert. Verbindung/Auth danach fehlgeschlagen: " + e.Error(), nil
}
func (s *AppService) hostByID(id string) (HostConfig, error) {
	hs, e := s.readHostsRaw()
	if e != nil {
		return HostConfig{}, e
	}
	for _, h := range hs {
		if h.ID == id {
			return s.decryptHostSecrets(h, false)
		}
	}
	return HostConfig{}, fmt.Errorf("Host nicht gefunden")
}
func (s *AppService) emitStatus(st SessionState) {
	if s.app != nil {
		s.app.Event.Emit("ssh:status", st)
	}
}
func (s *AppService) emitDataPayload(id string, seq int, data []byte) {
	if s.app != nil {
		s.app.Event.Emit("ssh:data", SSHDataPayload{SessionID: id, DataB64: base64.StdEncoding.EncodeToString(data), Seq: seq})
	}
}
func (s *AppService) startSSHOutputPump(id string, out <-chan []byte, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(16 * time.Millisecond)
		defer ticker.Stop()
		buf := make([]byte, 0, 65536)
		seq := 0
		flush := func() {
			if len(buf) == 0 {
				return
			}
			seq++
			payload := append([]byte(nil), buf...)
			buf = buf[:0]
			s.emitDataPayload(id, seq, payload)
		}
		for {
			select {
			case b := <-out:
				if len(b) == 0 {
					continue
				}
				buf = append(buf, b...)
				if len(buf) >= 65536 {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-done:
				flush()
				return
			}
		}
	}()
}
func (s *AppService) queueSSHData(id string, data []byte) {
	if len(data) == 0 {
		return
	}
	copyData := append([]byte(nil), data...)
	s.mu.Lock()
	r := s.ssh[id]
	if r == nil || r.out == nil || r.done == nil {
		s.mu.Unlock()
		return
	}
	out, done := r.out, r.done
	s.mu.Unlock()
	select {
	case out <- copyData:
	case <-done:
	}
}
func (s *AppService) emitText(id, data string) { s.queueSSHData(id, []byte(data)) }
func sanitizePtySize(cols, rows int) (int, int) {
	if cols < 40 {
		cols = 120
	}
	if rows < 10 {
		rows = 34
	}
	if cols > 500 {
		cols = 500
	}
	if rows > 200 {
		rows = 200
	}
	return cols, rows
}

func (s *AppService) ConnectSSH(hostID string) (SessionState, error) {
	return s.ConnectSSHWithSize(hostID, 120, 34)
}

func (s *AppService) ConnectSSHWithSize(hostID string, cols int, rows int) (SessionState, error) {
	cols, rows = sanitizePtySize(cols, rows)
	appLog("ConnectSSH hostID=%s pty=%dx%d", hostID, cols, rows)
	h, e := s.hostByID(hostID)
	if e != nil {
		appLog("ConnectSSH host error: %v", e)
		return SessionState{}, e
	}
	appLog("ConnectSSH target=%s@%s:%d auth=%s key=%s", h.Username, h.Address, h.Port, h.AuthMode, h.KeyPath)
	cfg, e := s.sshConfig(h, false)
	if e != nil {
		appLog("ConnectSSH config error: %v", e)
		return SessionState{}, e
	}
	addr, e := sshDialAddress(h)
	if e != nil {
		return SessionState{}, e
	}
	c, e := ssh.Dial("tcp", addr, cfg)
	if e != nil {
		appLog("ConnectSSH dial error: %v", e)
		return SessionState{}, e
	}
	sess, e := c.NewSession()
	if e != nil {
		c.Close()
		return SessionState{}, e
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if e = sess.RequestPty("xterm-256color", rows, cols, modes); e != nil {
		_ = sess.Close()
		_ = c.Close()
		return SessionState{}, e
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()
	id := h.ID + "-" + uuid.NewString()
	st := SessionState{ID: id, HostID: h.ID, Title: h.Name, Status: "connected", StartedAt: time.Now().UnixMilli()}
	out := make(chan []byte, 256)
	done := make(chan struct{})
	s.mu.Lock()
	s.ssh[id] = &sshRec{state: st, client: c, session: sess, stdin: stdin, out: out, done: done}
	s.mu.Unlock()
	s.startSSHOutputPump(id, out, done)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := stdout.Read(buf)
			if n > 0 {
				s.queueSSHData(id, buf[:n])
			}
			if e != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := stderr.Read(buf)
			if n > 0 {
				s.queueSSHData(id, buf[:n])
			}
			if e != nil {
				return
			}
		}
	}()
	if e = sess.Shell(); e != nil {
		appLog("ConnectSSH shell error: %v", e)
		_ = s.cleanupSSH(id, false)
		return st, e
	}
	appLog("ConnectSSH connected session=%s", id)
	s.emitStatus(st)
	s.emitText(id, "\r\nconnected: "+h.Username+"@"+h.Address+"\r\n")
	go func() { _ = sess.Wait(); _ = s.cleanupSSH(id, true) }()
	return st, nil
}
func (s *AppService) WriteSSH(id, data string) error {
	s.mu.Lock()
	r := s.ssh[id]
	s.mu.Unlock()
	if r == nil {
		return fmt.Errorf("Session nicht gefunden")
	}
	_, e := io.WriteString(r.stdin, data)
	return e
}
func (s *AppService) cleanupSSH(id string, emit bool) error {
	s.mu.Lock()
	r := s.ssh[id]
	delete(s.ssh, id)
	s.mu.Unlock()
	if r != nil {
		r.closeOnce.Do(func() {
			if r.done != nil {
				close(r.done)
			}
		})
		if r.stdin != nil {
			_ = r.stdin.Close()
		}
		if r.session != nil {
			_ = r.session.Close()
		}
		if r.client != nil {
			_ = r.client.Close()
		}
		if emit {
			st := r.state
			st.Status = "closed"
			s.emitStatus(st)
		}
	}
	return nil
}
func (s *AppService) CloseSSH(id string) error { return s.cleanupSSH(id, true) }
func (s *AppService) ResizeSSH(id string, cols int, rows int) error {
	s.mu.Lock()
	r := s.ssh[id]
	s.mu.Unlock()
	if r == nil {
		return nil
	}
	return r.session.WindowChange(rows, cols)
}

func (s *AppService) ConnectSFTP(hostID string) (SFTPConnectResult, error) {
	appLog("ConnectSFTP hostID=%s", hostID)
	h, e := s.hostByID(hostID)
	if e != nil {
		return SFTPConnectResult{}, e
	}
	cfg, e := s.sshConfig(h, false)
	if e != nil {
		return SFTPConnectResult{}, e
	}
	addr, e := sshDialAddress(h)
	if e != nil {
		return SFTPConnectResult{}, e
	}
	c, e := ssh.Dial("tcp", addr, cfg)
	if e != nil {
		return SFTPConnectResult{}, e
	}
	sc, e := sftp.NewClient(c)
	if e != nil {
		c.Close()
		return SFTPConnectResult{}, e
	}
	cwd, e := sc.Getwd()
	if e != nil {
		cwd = "/"
	}
	id := uuid.NewString()
	s.mu.Lock()
	s.sftps[id] = &sftpRec{id: id, hostID: hostID, client: c, sftp: sc, cwd: cwd, uploads: map[string]*uploadState{}}
	s.mu.Unlock()
	return SFTPConnectResult{ID: id, Home: cwd}, nil
}
func (s *AppService) CloseSFTP(id string) error {
	s.mu.Lock()
	r := s.sftps[id]
	delete(s.sftps, id)
	s.mu.Unlock()
	if r != nil {
		r.mu.Lock()
		r.closed = true
		for _, up := range r.uploads {
			if up.tmp != "" && r.sftp != nil {
				_ = r.sftp.Remove(up.tmp)
			}
		}
		r.uploads = map[string]*uploadState{}
		if r.sftp != nil {
			_ = r.sftp.Close()
		}
		if r.client != nil {
			_ = r.client.Close()
		}
		r.mu.Unlock()
	}
	return nil
}
func (s *AppService) lockedSFTP(id string) (*sftpRec, func(), error) {
	s.mu.Lock()
	r := s.sftps[id]
	s.mu.Unlock()
	if r == nil {
		return nil, nil, fmt.Errorf("SFTP nicht verbunden")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, nil, fmt.Errorf("SFTP nicht verbunden")
	}
	return r, r.mu.Unlock, nil
}
func (s *AppService) CloseAllSessions() error {
	s.mu.Lock()
	sshIDs := make([]string, 0, len(s.ssh))
	for id := range s.ssh {
		sshIDs = append(sshIDs, id)
	}
	sftpIDs := make([]string, 0, len(s.sftps))
	for id := range s.sftps {
		sftpIDs = append(sftpIDs, id)
	}
	s.mu.Unlock()
	for _, id := range sftpIDs {
		_ = s.CloseSFTP(id)
	}
	for _, id := range sshIDs {
		_ = s.cleanupSSH(id, true)
	}
	return nil
}
func sftpEntry(base string, fi os.FileInfo) FileEntry {
	typ := "file"
	if fi.Mode()&os.ModeSymlink != 0 {
		typ = "symlink"
	} else if fi.IsDir() {
		typ = "directory"
	}
	out := FileEntry{Name: fi.Name(), Path: pathJoinRemote(base, fi.Name()), Type: typ, Size: fi.Size(), Modified: fi.ModTime().UnixMilli(), Mode: fi.Mode().String()}
	if st, ok := fi.Sys().(*sftp.FileStat); ok {
		out.UID = st.UID
		out.GID = st.GID
	}
	return out
}
func pathJoinRemote(base, name string) string {
	if base == "/" {
		return "/" + name
	}
	return strings.TrimRight(base, "/") + "/" + name
}
func (s *AppService) ListSFTP(id, path string) ([]FileEntry, error) {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if path == "" {
		path = r.cwd
	}
	fis, e := r.sftp.ReadDir(path)
	if e != nil {
		return nil, e
	}
	out := []FileEntry{}
	for _, fi := range fis {
		out = append(out, sftpEntry(path, fi))
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Type == "directory" && !(out[j].Type == "directory")) || (out[i].Type == out[j].Type && strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name))
	})
	return out, nil
}
func remoteSafeTempPath(remotePath string) string {
	dir := path.Dir(remotePath)
	base := path.Base(remotePath)
	return path.Join(dir, "."+base+".sshv2part."+uuid.NewString())
}

func ensureRemoteParentDir(r *sftpRec, remotePath string) error {
	if err := rejectRemoteParentSymlinks(r, remotePath); err != nil {
		return err
	}
	dir := path.Dir(remotePath)
	if err := r.sftp.MkdirAll(dir); err != nil {
		return err
	}
	return rejectRemoteParentSymlinks(r, remotePath)
}

func finalizeRemoteReplace(sc *sftp.Client, tmp, dest string) error {
	if fi, err := sc.Lstat(tmp); err != nil {
		return err
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("SFTP-Tempdatei ungültig: %s", tmp)
	}
	if fi, err := sc.Lstat(dest); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SFTP-Symlink blockiert: %s", dest)
	}
	if err := sc.Rename(tmp, dest); err == nil {
		return nil
	}
	if err := sc.Remove(dest); err != nil {
		return err
	}
	return sc.Rename(tmp, dest)
}
func uploadFileSFTP(r *sftpRec, localPath, remotePath string) error {
	if err := ensureRemoteParentDir(r, remotePath); err != nil {
		return err
	}
	if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
		return err
	}
	src, e := os.Open(localPath)
	if e != nil {
		return e
	}
	defer src.Close()
	tmp := remoteSafeTempPath(remotePath)
	dst, e := r.sftp.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if e != nil {
		return e
	}
	_, e = io.Copy(dst, src)
	if closeErr := dst.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		_ = r.sftp.Remove(tmp)
		return e
	}
	return finalizeRemoteReplace(r.sftp, tmp, remotePath)
}
func uploadAnySFTP(r *sftpRec, localPath, remotePath string) error {
	fi, e := os.Lstat(localPath)
	if e != nil {
		return e
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Symlinks sind für lokale Uploads blockiert")
	}
	if !fi.IsDir() {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("nur reguläre Dateien/Ordner können hochgeladen werden")
		}
		return uploadFileSFTP(r, localPath, remotePath)
	}
	if err := rejectRemoteParentSymlinks(r, remotePath); err != nil {
		return err
	}
	if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
		return err
	}
	if e = r.sftp.MkdirAll(remotePath); e != nil {
		return e
	}
	ents, e := os.ReadDir(localPath)
	if e != nil {
		return e
	}
	for _, de := range ents {
		if e = uploadAnySFTP(r, filepath.Join(localPath, de.Name()), pathJoinRemote(remotePath, de.Name())); e != nil {
			return e
		}
	}
	return nil
}
func (s *AppService) UploadSFTP(id, localPath, remoteDir string) error {
	var accessErr error
	localPath, accessErr = requireGenericLocalPathAccess(localPath, true)
	if accessErr != nil {
		return accessErr
	}
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	return uploadAnySFTP(r, localPath, pathJoinRemote(remoteDir, filepath.Base(localPath)))
}

func (s *AppService) MkdirAllSFTP(id, remotePath string) error {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	remotePath = path.Clean(strings.TrimSpace(remotePath))
	if remotePath == "" || remotePath == "." {
		remotePath = "/"
	}
	if remotePath != "/" {
		if err := rejectRemoteParentSymlinks(r, remotePath); err != nil {
			return err
		}
		if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
			return err
		}
	}
	if err := r.sftp.MkdirAll(remotePath); err != nil {
		return err
	}
	if remotePath != "/" {
		return rejectRemoteExistingSymlink(r, remotePath)
	}
	return nil
}
func rejectRemoteSymlink(r *sftpRec, remotePath string) error {
	fi, err := r.sftp.Lstat(remotePath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SFTP-Symlink blockiert: %s", remotePath)
	}
	return nil
}
func rejectRemoteParentSymlinks(r *sftpRec, remotePath string) error {
	remotePath = path.Clean(strings.TrimSpace(remotePath))
	if remotePath == "." || remotePath == "" {
		return fmt.Errorf("ungültiger Remote-Dateipfad: %s", remotePath)
	}
	dir := path.Dir(remotePath)
	if dir == "." || dir == "/" || dir == "" {
		return nil
	}
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	cur := ""
	if strings.HasPrefix(dir, "/") {
		cur = "/"
	}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if cur == "/" {
			cur = "/" + part
		} else if cur == "" {
			cur = part
		} else {
			cur = path.Join(cur, part)
		}
		fi, err := r.sftp.Lstat(cur)
		if err != nil {
			return nil
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("SFTP-Symlink im Zielpfad blockiert: %s", cur)
		}
	}
	return nil
}
func rejectRemoteExistingSymlink(r *sftpRec, remotePath string) error {
	fi, err := r.sftp.Lstat(remotePath)
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SFTP-Symlink blockiert: %s", remotePath)
	}
	return nil
}
func (s *AppService) UploadSFTPChunk(id, uploadID, remotePath string, offset int64, base64Data string) error {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" || strings.HasSuffix(remotePath, "/") {
		return fmt.Errorf("ungültiger Remote-Dateipfad: %s", remotePath)
	}
	uploadID = strings.TrimSpace(uploadID)
	if uploadID == "" || strings.ContainsAny(uploadID, `/\\`) {
		return fmt.Errorf("ungültige Upload-ID")
	}
	if offset < 0 {
		return fmt.Errorf("ungültiger Upload-Offset")
	}
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return fmt.Errorf("Upload-Daten ungültig: %w", err)
	}
	if err := ensureRemoteParentDir(r, remotePath); err != nil {
		return err
	}
	if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
		return err
	}
	up := r.uploads[uploadID]
	if offset == 0 {
		if up != nil && up.tmp != "" {
			_ = r.sftp.Remove(up.tmp)
		}
		up = &uploadState{path: remotePath, tmp: remoteSafeTempPath(remotePath), next: 0}
		r.uploads[uploadID] = up
	} else if up == nil || up.path != remotePath {
		return fmt.Errorf("Upload-Session fehlt oder passt nicht")
	}
	if up.next != offset {
		return fmt.Errorf("Upload-Offset passt nicht: got %d want %d", offset, up.next)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	if offset == 0 {
		if err := rejectRemoteExistingSymlink(r, up.tmp); err != nil {
			return err
		}
	}
	dst, err := r.sftp.OpenFile(up.tmp, flags)
	if err != nil {
		return err
	}
	if _, err = dst.Seek(offset, io.SeekStart); err != nil {
		_ = dst.Close()
		return err
	}
	if _, err = dst.Write(data); err != nil {
		_ = dst.Close()
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	up.next += int64(len(data))
	if len(data) == 0 {
		if err := finalizeRemoteReplace(r.sftp, up.tmp, remotePath); err != nil {
			return err
		}
		delete(r.uploads, uploadID)
	}
	return nil
}

func mkdirAllLocal(p string, perm os.FileMode) error {
	p = filepath.Clean(strings.TrimSpace(p))
	if err := rejectSymlinkPath(p); err != nil {
		return err
	}
	if err := os.MkdirAll(p, perm); err == nil {
		return rejectSymlinkPath(p)
	} else if runtime.GOOS == "windows" {
		// Windows occasionally returns ERROR_PATH_NOT_FOUND for perfectly valid
		// user-profile paths created from WebView input. cmd/mkdir handles those
		// paths more consistently (spaces, localized profile dirs, junctions).
		if out, e2 := exec.Command("cmd", "/C", "mkdir", p).CombinedOutput(); e2 == nil {
			return rejectSymlinkPath(p)
		} else {
			return fmt.Errorf("lokalen Ordner anlegen fehlgeschlagen: %s: %v (cmd: %s)", p, err, strings.TrimSpace(string(out)))
		}
	} else {
		return err
	}
}
func ensureDownloadDir(localDir string) (string, error) {
	localDir = strings.TrimSpace(localDir)
	if localDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			localDir = h
		}
	}
	localDir = filepath.Clean(localDir)
	if err := rejectSymlinkPath(localDir); err != nil {
		return "", err
	}
	fi, err := os.Lstat(localDir)
	if err != nil {
		return "", fmt.Errorf("lokaler Zielordner nicht erreichbar: %s: %w", localDir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("lokales Ziel ist kein Ordner: %s", localDir)
	}
	return localDir, nil
}
func remoteBaseName(remotePath string) string {
	name := strings.TrimSpace(path.Base(strings.TrimRight(remotePath, "/")))
	if safe, err := safeLocalChildName(name); err == nil {
		return safe
	}
	return "download"
}
func safeLocalChildName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("unsicherer Dateiname: %q", name)
	}
	return name, nil
}
func safeJoinUnder(root string, elems ...string) (string, error) {
	root = filepath.Clean(root)
	parts := append([]string{root}, elems...)
	target := filepath.Clean(filepath.Join(parts...))
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("Zielpfad verlässt den Zielordner: %s", target)
	}
	return target, nil
}

func textFileFromBytes(filePath string, fi os.FileInfo, data []byte) (TextFileContent, error) {
	if len(data) > 0 && bytes.Contains(data, []byte{0}) {
		return TextFileContent{}, fmt.Errorf("Datei wirkt binär und wird nicht im Texteditor geöffnet")
	}
	if !utf8.Valid(data) {
		return TextFileContent{}, fmt.Errorf("Datei ist kein gültiger UTF-8-Text")
	}
	return TextFileContent{Path: filePath, Name: path.Base(filePath), Content: string(data), Size: fi.Size(), Modified: fi.ModTime().UnixMilli()}, nil
}

func (s *AppService) ReadTextSFTP(id, remotePath string) (TextFileContent, error) {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return TextFileContent{}, err
	}
	defer unlock()
	if err := rejectRemoteSymlink(r, remotePath); err != nil {
		return TextFileContent{}, err
	}
	fi, err := r.sftp.Stat(remotePath)
	if err != nil {
		return TextFileContent{}, err
	}
	if fi.IsDir() {
		return TextFileContent{}, fmt.Errorf("Ordner kann nicht im Texteditor geöffnet werden")
	}
	if fi.Size() > textEditorMaxBytes {
		return TextFileContent{}, fmt.Errorf("Datei zu groß für Editor: %.1f MB (Limit 1 MB)", float64(fi.Size())/1024/1024)
	}
	f, err := r.sftp.Open(remotePath)
	if err != nil {
		return TextFileContent{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, textEditorMaxBytes+1))
	if err != nil {
		return TextFileContent{}, err
	}
	if int64(len(data)) > textEditorMaxBytes {
		return TextFileContent{}, fmt.Errorf("Datei zu groß für Editor (Limit 1 MB)")
	}
	out, err := textFileFromBytes(remotePath, fi, data)
	if err != nil {
		return TextFileContent{}, err
	}
	return out, nil
}

func (s *AppService) WriteTextSFTP(id, remotePath string, content string) error {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" || strings.HasSuffix(remotePath, "/") {
		return fmt.Errorf("ungültiger Remote-Dateipfad: %s", remotePath)
	}
	if int64(len([]byte(content))) > textEditorMaxBytes {
		return fmt.Errorf("Inhalt zu groß für Editor-Upload (Limit 1 MB)")
	}
	if err := rejectRemoteParentSymlinks(r, remotePath); err != nil {
		return err
	}
	if _, statErr := r.sftp.Lstat(remotePath); statErr == nil {
		if err := rejectRemoteSymlink(r, remotePath); err != nil {
			return err
		}
	}
	if err := ensureRemoteParentDir(r, remotePath); err != nil {
		return err
	}
	if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
		return err
	}
	tmp := remoteSafeTempPath(remotePath)
	f, err := r.sftp.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err = f.Write([]byte(content)); err != nil {
		_ = f.Close()
		_ = r.sftp.Remove(tmp)
		return err
	}
	if err = f.Close(); err != nil {
		_ = r.sftp.Remove(tmp)
		return err
	}
	return finalizeRemoteReplace(r.sftp, tmp, remotePath)
}

func canonicalLocalPathForAccess(p string, mustExist bool) (string, error) {
	orig := filepath.Clean(expand(strings.TrimSpace(p)))
	if orig == "" || !filepath.IsAbs(orig) {
		return "", fmt.Errorf("ungültiger lokaler Pfad")
	}
	check := orig
	if mustExist {
		st, err := os.Lstat(orig)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
		}
	} else {
		check = filepath.Dir(orig)
	}
	realCheck, err := filepath.EvalSymlinks(check)
	if err != nil {
		return "", err
	}
	realCheck = filepath.Clean(realCheck)
	if mustExist {
		return realCheck, nil
	}
	return filepath.Join(realCheck, filepath.Base(orig)), nil
}
func localAllowedRoots() []string {
	roots := []string{}
	if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
		if real, e := filepath.EvalSymlinks(filepath.Clean(h)); e == nil {
			roots = append(roots, filepath.Clean(real))
		} else {
			roots = append(roots, filepath.Clean(h))
		}
	}
	if c, err := configDir(); err == nil && strings.TrimSpace(c) != "" {
		if real, e := filepath.EvalSymlinks(filepath.Clean(c)); e == nil {
			roots = append(roots, filepath.Clean(real))
		} else {
			roots = append(roots, filepath.Clean(c))
		}
	}
	return roots
}
func localPathAllowed(p string) bool {
	p = filepath.Clean(p)
	for _, root := range localAllowedRoots() {
		if p == root || strings.HasPrefix(p, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func localSensitivePath(p string) bool {
	p = filepath.Clean(p)
	home, homeErr := os.UserHomeDir()
	if homeErr == nil && strings.TrimSpace(home) != "" {
		home = filepath.Clean(home)
		if rel, err := filepath.Rel(home, p); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) > 0 {
				first := strings.ToLower(parts[0])
				blockedDirs := map[string]bool{
					".ssh": true, ".aws": true, ".azure": true, ".config": true, ".docker": true, ".gnupg": true, ".kube": true,
					"appdata": runtime.GOOS == "windows",
				}
				if blockedDirs[first] {
					return true
				}
				blockedFiles := map[string]bool{
					".bashrc": true, ".bash_profile": true, ".profile": true, ".zshrc": true, ".git-credentials": true, ".netrc": true,
				}
				if len(parts) == 1 && blockedFiles[first] {
					return true
				}
			}
		}
	}
	if c, err := configDir(); err == nil {
		c = filepath.Clean(c)
		if rel, err := filepath.Rel(c, p); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			// App-owned secrets are accessed through typed APIs only, not generic local editor/listing APIs.
			return true
		}
	}
	return false
}

func requireGenericLocalPathAccess(p string, mustExist bool) (string, error) {
	p, err := requireLocalPathAccess(p, mustExist)
	if err != nil {
		return "", err
	}
	if localSensitivePath(p) {
		return "", fmt.Errorf("lokaler Dateizugriff blockiert: sensibler Pfad darf nicht über generische Datei-APIs gelesen/geändert werden")
	}
	return p, nil
}

func requireLocalPathAccess(p string, mustExist bool) (string, error) {
	p, err := canonicalLocalPathForAccess(p, mustExist)
	if err != nil {
		return "", err
	}
	if !localPathAllowed(p) {
		return "", fmt.Errorf("lokaler Dateizugriff nicht freigegeben: Pfad liegt außerhalb des Nutzer-/App-Bereichs")
	}
	return p, nil
}

func rejectExistingSymlink(p string) error {
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
	}
	return nil
}

func rejectSymlinkPath(p string) error {
	p = filepath.Clean(strings.TrimSpace(p))
	if p == "" {
		return fmt.Errorf("ungültiger lokaler Pfad")
	}
	vol := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, vol)
	current := vol
	if strings.HasPrefix(rest, string(os.PathSeparator)) {
		current += string(os.PathSeparator)
		rest = strings.TrimLeft(rest, string(os.PathSeparator))
	}
	if current == "" {
		current = "."
	}
	for _, part := range strings.Split(rest, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
		}
		if err := rejectWindowsReparsePoint(current); err != nil {
			return err
		}
	}
	return nil
}
func readAllowedSmallLocalFile(p string, maxBytes int64) ([]byte, string, error) {
	p, err := requireLocalPathAccess(p, true)
	if err != nil {
		return nil, "", err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
	}
	if !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("Pfad ist keine reguläre Datei")
	}
	if st.Size() > maxBytes {
		return nil, "", fmt.Errorf("Datei zu groß")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, "", err
	}
	return b, p, nil
}
func tryReadAllowedSmallLocalFile(p string, maxBytes int64) ([]byte, string, bool) {
	b, clean, err := readAllowedSmallLocalFile(p, maxBytes)
	if err != nil {
		return nil, "", false
	}
	return b, clean, true
}
func (s *AppService) ReadTextLocal(localPath string) (TextFileContent, error) {
	var err error
	localPath, err = requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return TextFileContent{}, err
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		return TextFileContent{}, err
	}
	if fi.IsDir() {
		return TextFileContent{}, fmt.Errorf("Ordner kann nicht im Texteditor geöffnet werden")
	}
	if fi.Size() > textEditorMaxBytes {
		return TextFileContent{}, fmt.Errorf("Datei zu groß für Editor: %.1f MB (Limit 1 MB)", float64(fi.Size())/1024/1024)
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return TextFileContent{}, err
	}
	out, err := textFileFromBytes(localPath, fi, data)
	if err != nil {
		return TextFileContent{}, err
	}
	out.Name = filepath.Base(localPath)
	return out, nil
}

func (s *AppService) WriteTextLocal(localPath string, content string) error {
	var err error
	localPath, err = requireGenericLocalPathAccess(localPath, false)
	if err != nil {
		return err
	}
	if int64(len([]byte(content))) > textEditorMaxBytes {
		return fmt.Errorf("Inhalt zu groß für Editor-Speichern (Limit 1 MB)")
	}
	if err := rejectExistingSymlink(localPath); err != nil {
		return err
	}
	return secureWriteFileNoFollow(localPath, []byte(content), 0644)
}

func downloadFileSFTP(sc *sftp.Client, remotePath, localPath string) error {
	src, e := sc.Open(remotePath)
	if e != nil {
		return e
	}
	defer src.Close()
	if e = mkdirAllLocal(filepath.Dir(localPath), 0755); e != nil {
		return e
	}
	if e = rejectExistingSymlink(localPath); e != nil {
		return e
	}
	dst, e := secureCreateFileNoFollow(localPath, 0644)
	if e != nil {
		return e
	}
	defer dst.Close()
	_, e = io.Copy(dst, src)
	return e
}
func downloadAnySFTP(sc *sftp.Client, remotePath, localPath string) error {
	fi, e := sc.Lstat(remotePath)
	if e != nil {
		return e
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SFTP-Symlinks werden beim rekursiven Download blockiert")
	}
	if !fi.IsDir() {
		return downloadFileSFTP(sc, remotePath, localPath)
	}
	if e = mkdirAllLocal(localPath, 0755); e != nil {
		return e
	}
	ents, e := sc.ReadDir(remotePath)
	if e != nil {
		return e
	}
	for _, fi := range ents {
		childName, err := safeLocalChildName(fi.Name())
		if err != nil {
			return err
		}
		childLocal, err := safeJoinUnder(localPath, childName)
		if err != nil {
			return err
		}
		if e = downloadAnySFTP(sc, pathJoinRemote(remotePath, childName), childLocal); e != nil {
			return e
		}
	}
	return nil
}
func (s *AppService) DownloadSFTP(id, remotePath, localDir string) error {
	var accessErr error
	localDir, accessErr = requireGenericLocalPathAccess(localDir, true)
	if accessErr != nil {
		return accessErr
	}
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	dir, err := ensureDownloadDir(localDir)
	if err != nil {
		return err
	}
	target, err := safeJoinUnder(dir, remoteBaseName(remotePath))
	if err != nil {
		return err
	}
	appLog("DownloadSFTP remote=%s localDir=%s target=%s", remotePath, dir, target)
	if err := downloadAnySFTP(r.sftp, remotePath, target); err != nil {
		return fmt.Errorf("Download fehlgeschlagen: %s → %s: %w", remotePath, target, err)
	}
	return nil
}
func (s *AppService) MkdirSFTP(id, remotePath string) error {
	remotePath = path.Clean(strings.TrimSpace(remotePath))
	if remotePath == "." || remotePath == "/" || strings.ContainsRune(remotePath, 0) {
		return fmt.Errorf("ungültiger Remote-Pfad")
	}
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	if err := rejectRemoteParentSymlinks(r, remotePath); err != nil {
		return err
	}
	if err := rejectRemoteExistingSymlink(r, remotePath); err != nil {
		return err
	}
	return r.sftp.Mkdir(remotePath)
}
func (s *AppService) RemoveSFTP(id, remotePath string) error {
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	fi, err := r.sftp.Lstat(remotePath)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return r.sftp.Remove(remotePath)
	}
	if err == nil && fi.IsDir() {
		return r.sftp.RemoveDirectory(remotePath)
	}
	return r.sftp.Remove(remotePath)
}
func (s *AppService) RenameSFTP(id, remotePath string, newName string) error {
	if strings.Contains(newName, "/") || strings.TrimSpace(newName) == "" {
		return fmt.Errorf("ungültiger Name")
	}
	r, unlock, err := s.lockedSFTP(id)
	if err != nil {
		return err
	}
	defer unlock()
	return r.sftp.Rename(remotePath, pathJoinRemote(path.Dir(remotePath), newName))
}
func (s *AppService) LocalMkdir(localPath string) error {
	p, err := requireGenericLocalPathAccess(localPath, false)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0755)
}
func (s *AppService) RemoveLocal(localPath string) error {
	p, err := requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
func (s *AppService) RenameLocal(localPath string, newName string) error {
	if strings.ContainsAny(newName, `/\`) || strings.TrimSpace(newName) == "" {
		return fmt.Errorf("ungültiger Name")
	}
	localPath, err := requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return err
	}
	target, err := requireGenericLocalPathAccess(filepath.Join(filepath.Dir(localPath), newName), false)
	if err != nil {
		return err
	}
	return os.Rename(localPath, target)
}
func localEntry(path string, fi os.FileInfo) FileEntry {
	typ := "file"
	if fi.IsDir() {
		typ = "directory"
	}
	return FileEntry{Name: fi.Name(), Path: path, Type: typ, Size: fi.Size(), Modified: fi.ModTime().UnixMilli(), Mode: fi.Mode().String()}
}
func (s *AppService) LocalHome() (string, error) { return os.UserHomeDir() }
func (s *AppService) LocalList(path string) ([]FileEntry, error) {
	if path == "" {
		path, _ = os.UserHomeDir()
	}
	var accessErr error
	path, accessErr = requireGenericLocalPathAccess(path, true)
	if accessErr != nil {
		return nil, accessErr
	}
	ents, e := os.ReadDir(path)
	if e != nil {
		return nil, e
	}
	out := []FileEntry{}
	for _, de := range ents {
		fi, e := de.Info()
		if e == nil {
			out = append(out, localEntry(filepath.Join(path, de.Name()), fi))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Type == "directory" && !(out[j].Type == "directory")) || (out[i].Type == out[j].Type && strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name))
	})
	return out, nil
}

func currentDarwinAppBundle() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	macosDir := filepath.Dir(exe)
	contentsDir := filepath.Dir(macosDir)
	appDir := filepath.Dir(contentsDir)
	if filepath.Base(macosDir) != "MacOS" || filepath.Base(contentsDir) != "Contents" || !strings.HasSuffix(appDir, ".app") {
		return "", fmt.Errorf("macOS Update braucht eine laufende .app; aktueller Pfad: %s", exe)
	}
	return appDir, nil
}

func startDetachedScript(shell string, args ...string) error {
	cmd := exec.Command(shell, args...)
	cmd.SysProcAttr = detachedSysProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func writeAndStartUpdateScript(script, body string) error {
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		return err
	}
	return startDetachedScript("/bin/sh", script)
}

func archivePathUnsafe(name string) bool {
	clean := path.Clean(strings.TrimSpace(name))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || path.IsAbs(clean) || strings.Contains(name, "\\") {
		return true
	}
	return !regexp.MustCompile(`^[A-Za-z0-9._+@%=-]+(/[A-Za-z0-9._+@%=-]+)*$`).MatchString(clean)
}
func validateLinuxUpdateArchive(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	matches := []string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if archivePathUnsafe(h.Name) {
			return "", fmt.Errorf("unsicherer Archivpfad: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			return "", fmt.Errorf("Archiv enthält Link: %s", h.Name)
		case tar.TypeReg:
			if path.Base(h.Name) == "ssh-vault2" && h.Size > 1024*1024 {
				matches = append(matches, path.Clean(h.Name))
			}
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("Linux-Archiv muss genau ein ssh-vault2 Binary enthalten, gefunden: %d", len(matches))
	}
	return matches[0], nil
}
func validateDarwinUpdateArchive(archivePath string) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	apps := map[string]bool{}
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if archivePathUnsafe(name) {
			return "", fmt.Errorf("unsicherer Archivpfad: %s", f.Name)
		}
		mode := f.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 {
			return "", fmt.Errorf("Archiv enthält Symlink: %s", f.Name)
		}
		parts := strings.Split(name, "/")
		for i, part := range parts {
			if part == "ssh-vault2.app" {
				apps[strings.Join(parts[:i+1], "/")] = true
			}
		}
	}
	if len(apps) != 1 {
		return "", fmt.Errorf("macOS-Archiv muss genau ein ssh-vault2.app Bundle enthalten, gefunden: %d", len(apps))
	}
	for app := range apps {
		return app, nil
	}
	return "", fmt.Errorf("ssh-vault2.app fehlt")
}

func (s *AppService) InstallUpdate(asset ReleaseAsset) (string, error) {
	if asset.Name == "" || asset.URL == "" {
		return "", fmt.Errorf("kein Update ausgewählt")
	}
	if err := validateUpdateAssetForInstall(asset); err != nil {
		return "", err
	}
	signedSums, err := fetchSignedReleaseSums()
	if err != nil {
		return "", err
	}
	expectedSHA := signedSums[filepath.Base(asset.Name)]
	if expectedSHA == "" {
		return "", fmt.Errorf("Update-Artefakt fehlt in signierten Checksums: %s", asset.Name)
	}
	if asset.SHA256 != "" && !strings.EqualFold(asset.SHA256, expectedSHA) {
		return "", fmt.Errorf("Release-Index widerspricht signierten Checksums für %s", asset.Name)
	}
	nameLower := strings.ToLower(asset.Name)
	switch runtime.GOOS {
	case "windows":
		if !strings.HasSuffix(nameLower, "installer.exe") {
			return "", fmt.Errorf("Windows In-Place-Update braucht den Installer (*.installer.exe)")
		}
	case "darwin":
		if !strings.Contains(nameLower, "darwin-") || !strings.HasSuffix(nameLower, ".zip") {
			return "", fmt.Errorf("macOS In-Place-Update braucht das darwin-*.zip Paket")
		}
	case "linux":
		if !strings.Contains(nameLower, "linux-") || !strings.HasSuffix(nameLower, ".tar.gz") {
			return "", fmt.Errorf("Linux In-Place-Update braucht das linux-*.tar.gz Paket")
		}
	default:
		return "", fmt.Errorf("In-Place-Update für %s noch nicht unterstützt", runtime.GOOS)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	dir := filepath.Join(cache, "ssh-vault2", "updates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	target := filepath.Join(dir, filepath.Base(asset.Name))
	res, err := appHTTPClient().Get(releaseServer + asset.URL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail := readErrorBody(res.Body)
		if detail != "" {
			return "", fmt.Errorf("download fehlgeschlagen: HTTP %d: %s", res.StatusCode, detail)
		}
		return "", fmt.Errorf("download fehlgeschlagen: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxReleaseArtifactBytes {
		return "", fmt.Errorf("Update-Artefakt zu groß")
	}
	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(res.Body, maxReleaseArtifactBytes+1))
	if err != nil {
		out.Close()
		_ = os.Remove(target)
		return "", err
	}
	if written > maxReleaseArtifactBytes {
		out.Close()
		_ = os.Remove(target)
		return "", fmt.Errorf("Update-Artefakt zu groß")
	}
	if err = out.Close(); err != nil {
		_ = os.Remove(target)
		return "", err
	}
	sum := fmt.Sprintf("%x", h.Sum(nil))
	if !strings.EqualFold(sum, expectedSHA) {
		return "", fmt.Errorf("SHA256 passt nicht zur signierten Checksum: %s", sum)
	}
	appLog("InstallUpdate downloaded name=%s target=%s sha256=%s", asset.Name, target, sum)
	pid := os.Getpid()
	logPath := filepath.Join(dir, "apply-update.log")
	if runtime.GOOS == "windows" {
		exe := filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "ssh-vault2", "ssh-vault2.exe")
		script := filepath.Join(dir, "apply-update.ps1")
		body := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$pidToWait = %d
$installer = %q
$appExe = %q
$log = %q
$expectedSha = %q
function Log($m) { Add-Content -Path $log -Value ((Get-Date).ToString('s') + ' ' + $m) }
try {
  Log "apply-start pid=$pidToWait installer=$installer app=$appExe"
  while (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 500 }
  Log "parent-exited"
  if (!(Test-Path $installer)) { throw "installer missing: $installer" }
  $actualSha = (Get-FileHash -Algorithm SHA256 -Path $installer).Hash.ToLowerInvariant()
  if ($actualSha -ne $expectedSha.ToLowerInvariant()) { throw "installer sha256 mismatch: $actualSha" }
  $p = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
  Log "installer-exit=$($p.ExitCode)"
  Start-Sleep -Seconds 2
  if (Test-Path $appExe) {
    Log "restart $appExe"
    Start-Process -FilePath $appExe
  } else {
    Log "appExe missing after install: $appExe"
  }
} catch {
  Log ("ERROR " + $_.Exception.Message)
}
`, pid, target, exe, logPath, expectedSHA)
		if err := os.WriteFile(script, []byte(body), 0600); err != nil {
			return "", err
		}
		cmd := exec.Command("powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", script)
		cmd.SysProcAttr = detachedSysProcAttr()
		if err := cmd.Start(); err != nil {
			return "", err
		}
		_ = cmd.Process.Release()
		go func() { time.Sleep(2500 * time.Millisecond); os.Exit(0) }()
		return "Update wird installiert. ssh-vault2 wird geschlossen und danach neu gestartet. Log: " + logPath, nil
	}
	if runtime.GOOS == "darwin" {
		appRel, err := validateDarwinUpdateArchive(target)
		if err != nil {
			_ = os.Remove(target)
			return "", err
		}
		appDir, err := currentDarwinAppBundle()
		if err != nil {
			return "", err
		}
		script := filepath.Join(dir, "apply-update-macos.sh")
		body := fmt.Sprintf(`#!/bin/sh
pid=%d
archive=%q
app=%q
log=%q
expectedSha=%q
logmsg(){ echo "$(date) $1" >> "$log"; }
logmsg "apply-start pid=$pid archive=$archive app=$app"
actualSha="$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')"
if [ "$actualSha" != "$expectedSha" ]; then logmsg "ERROR sha256 mismatch: $actualSha"; exit 1; fi
while kill -0 "$pid" >/dev/null 2>&1; do sleep 0.5; done
work="$(mktemp -d "${TMPDIR:-/tmp}/ssh-vault2-update.XXXXXX")" || exit 1
trap 'rm -rf "$work"' EXIT
if command -v ditto >/dev/null 2>&1; then ditto -x -k "$archive" "$work"; else unzip -q "$archive" -d "$work"; fi
newapp="$work/%s"
if [ ! -d "$newapp" ]; then logmsg "ERROR no verified ssh-vault2.app in archive"; exit 1; fi
rm -rf "$app.old"
if [ -d "$app" ]; then mv "$app" "$app.old"; fi
if command -v ditto >/dev/null 2>&1; then ditto "$newapp" "$app"; else cp -R "$newapp" "$app"; fi
xattr -dr com.apple.quarantine "$app" >/dev/null 2>&1 || true
logmsg "restart $app"
open "$app" >/dev/null 2>&1 || "$app/Contents/MacOS/ssh-vault2" >/dev/null 2>&1 &
`, pid, target, appDir, logPath, expectedSHA, appRel)
		if err := writeAndStartUpdateScript(script, body); err != nil {
			return "", err
		}
		go func() { time.Sleep(2500 * time.Millisecond); os.Exit(0) }()
		return "macOS Update wird installiert. ssh-vault2 wird geschlossen und danach neu gestartet. Log: " + logPath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	binRel, err := validateLinuxUpdateArchive(target)
	if err != nil {
		_ = os.Remove(target)
		return "", err
	}
	script := filepath.Join(dir, "apply-update-linux.sh")
	body := fmt.Sprintf(`#!/bin/sh
pid=%d
archive=%q
exe=%q
log=%q
expectedSha=%q
logmsg(){ echo "$(date) $1" >> "$log"; }
logmsg "apply-start pid=$pid archive=$archive exe=$exe"
actualSha="$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')"
if [ "$actualSha" != "$expectedSha" ]; then logmsg "ERROR sha256 mismatch: $actualSha"; exit 1; fi
while kill -0 "$pid" >/dev/null 2>&1; do sleep 0.5; done
work="$(mktemp -d "${TMPDIR:-/tmp}/ssh-vault2-update.XXXXXX")" || exit 1
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
newbin="$work/%s"
if [ ! -f "$newbin" ]; then logmsg "ERROR no verified ssh-vault2 binary in archive"; exit 1; fi
cp "$exe" "$exe.old" 2>/dev/null || true
install -m 0755 "$newbin" "$exe"
logmsg "restart $exe"
nohup "$exe" >/dev/null 2>&1 &
`, pid, target, exe, logPath, expectedSHA, binRel)
	if err := writeAndStartUpdateScript(script, body); err != nil {
		return "", err
	}
	go func() { time.Sleep(2500 * time.Millisecond); os.Exit(0) }()
	return "Linux Update wird installiert. ssh-vault2 wird geschlossen und danach neu gestartet. Log: " + logPath, nil
}

func syncConfigPath() (string, error) {
	d, e := configDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "sync.json"), nil
}
func (s *AppService) getSyncConfigRaw() (SyncConfig, error) {
	p, e := syncConfigPath()
	if e != nil {
		return SyncConfig{}, e
	}
	c := SyncConfig{Endpoint: releaseServer, IncludeKeys: true}
	b, e := os.ReadFile(p)
	if errors.Is(e, os.ErrNotExist) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	_ = json.Unmarshal(cleanJSONBytes(b), &c)
	c.Endpoint = normalizeSyncEndpoint(c.Endpoint)
	return c, nil
}
func (s *AppService) GetSyncConfig() (SyncConfig, error) {
	c, e := s.getSyncConfigRaw()
	if e != nil {
		return c, e
	}
	c, e = s.decryptSyncSecrets(c, true)
	if e != nil {
		return c, e
	}
	c.Token = ""
	c.AutoPassphrase = ""
	return c, nil
}
func (s *AppService) saveSyncConfigRaw(c SyncConfig) (SyncConfig, error) {
	p, e := syncConfigPath()
	if e != nil {
		return c, e
	}
	c, e = s.encryptSyncSecrets(c)
	if e != nil {
		return c, e
	}
	return c, secureWriteJSON(p, c)
}
func (s *AppService) SaveSyncConfig(c SyncConfig) (SyncConfig, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	existingRaw, _ := s.getSyncConfigRaw()
	existing, _ := s.decryptSyncSecrets(existingRaw, true)
	if strings.TrimSpace(c.Endpoint) == "" {
		c.Endpoint = existing.Endpoint
	}
	c.Endpoint = normalizeSyncEndpoint(c.Endpoint)
	if err := validateSyncEndpoint(c.Endpoint); err != nil {
		return c, err
	}
	c.Account = strings.TrimSpace(c.Account)
	if c.Account == "" {
		c.Account = existing.Account
	}
	c.Token = strings.TrimSpace(c.Token)
	if c.Token == "" {
		if isEncryptedValue(existingRaw.Token) {
			c.Token = existingRaw.Token
		} else {
			c.Token = existing.Token
		}
	}
	if c.AutoPassphrase == "" {
		if isEncryptedValue(existingRaw.AutoPassphrase) {
			c.AutoPassphrase = existingRaw.AutoPassphrase
		} else {
			c.AutoPassphrase = existing.AutoPassphrase
		}
	}
	_, e := s.saveSyncConfigRaw(c)
	if e != nil {
		return c, e
	}
	return s.GetSyncConfig()
}
func (s *AppService) SyncLogin(req SyncAccountRequest) (SyncAccountResult, error) {
	if len(s.localKeyCopy()) == 0 {
		return SyncAccountResult{}, fmt.Errorf("Lokaler Tresor gesperrt: erst entsperren, dann Sync-Login speichern")
	}
	endpoint := normalizeSyncEndpoint(req.Endpoint)
	if err := validateSyncEndpoint(endpoint); err != nil {
		return SyncAccountResult{}, err
	}
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if username == "" || password == "" {
		return SyncAccountResult{}, fmt.Errorf("Benutzername/E-Mail und Passwort nötig")
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = fmt.Sprintf("desktop-%s-%s", runtime.GOOS, runtime.GOARCH)
	}
	payload := map[string]string{"username": username, "password": password, "label": label}
	if strings.TrimSpace(req.TOTP) != "" {
		payload["totp"] = strings.TrimSpace(req.TOTP)
	}
	body, _ := json.Marshal(payload)
	client := appHTTPClient()
	res, err := client.Post(endpoint+"/api/v1/accounts/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return SyncAccountResult{}, err
	}
	defer res.Body.Close()
	resBody, _ := readAllStrict(res.Body, maxReleaseIndexBytes)
	var out SyncAccountResult
	_ = json.Unmarshal(cleanJSONBytes(resBody), &out)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if out.TOTPRequired {
			if res.StatusCode == http.StatusUnauthorized {
				return out, fmt.Errorf("TOTP-Code nötig")
			}
			return out, fmt.Errorf("TOTP-Code ungültig")
		}
		if out.Message != "" {
			return out, errors.New(out.Message)
		}
		if out.Error != "" {
			return out, errors.New(out.Error)
		}
		return out, fmt.Errorf("Sync-Login fehlgeschlagen: HTTP %d", res.StatusCode)
	}
	out.Token = strings.TrimSpace(out.Token)
	out.Account = strings.TrimSpace(out.Account)
	if out.Account == "" {
		out.Account = username
	}
	if out.Token == "" {
		return out, fmt.Errorf("Sync-Server lieferte keinen Token")
	}
	if _, err := s.SaveSyncConfig(SyncConfig{Enabled: true, Endpoint: endpoint, Account: out.Account, Token: out.Token, IncludeKeys: true}); err != nil {
		return out, err
	}
	if out.Message == "" {
		out.Message = "Sync-Login gespeichert"
	}
	out.Token = ""
	return out, nil
}
func syncKey(passphrase string, salt []byte) ([]byte, error) {
	if len(passphrase) < 10 {
		return nil, fmt.Errorf("Sync-Passphrase braucht mindestens 10 Zeichen")
	}
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}
func encryptSync(passphrase string, payload SyncPayload) (EncryptedSyncBlob, error) {
	plain, _ := json.Marshal(payload)
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, e := rand.Read(salt); e != nil {
		return EncryptedSyncBlob{}, e
	}
	if _, e := rand.Read(nonce); e != nil {
		return EncryptedSyncBlob{}, e
	}
	key, e := syncKey(passphrase, salt)
	if e != nil {
		return EncryptedSyncBlob{}, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return EncryptedSyncBlob{}, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return EncryptedSyncBlob{}, e
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return EncryptedSyncBlob{Version: 1, KDF: "scrypt-N32768-r8-p1", Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ct), UpdatedAt: time.Now().UnixMilli()}, nil
}
func decryptSync(passphrase string, blob EncryptedSyncBlob) (SyncPayload, error) {
	salt, e := base64.StdEncoding.DecodeString(blob.Salt)
	if e != nil {
		return SyncPayload{}, e
	}
	nonce, e := base64.StdEncoding.DecodeString(blob.Nonce)
	if e != nil {
		return SyncPayload{}, e
	}
	ct, e := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if e != nil {
		return SyncPayload{}, e
	}
	key, e := syncKey(passphrase, salt)
	if e != nil {
		return SyncPayload{}, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return SyncPayload{}, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return SyncPayload{}, e
	}
	plain, e := gcm.Open(nil, nonce, ct, nil)
	if e != nil {
		return SyncPayload{}, fmt.Errorf("Sync entschlüsseln fehlgeschlagen: Passphrase falsch oder Daten beschädigt")
	}
	var payload SyncPayload
	return payload, json.Unmarshal(plain, &payload)
}
func (s *AppService) syncURL(c SyncConfig) (string, error) {
	if !c.Enabled {
		return "", fmt.Errorf("Sync ist deaktiviert")
	}
	c.Endpoint = normalizeSyncEndpoint(c.Endpoint)
	if c.Endpoint == "" || c.Account == "" {
		return "", fmt.Errorf("Sync-Server und Account fehlen")
	}
	if err := validateSyncEndpoint(c.Endpoint); err != nil {
		return "", err
	}
	return strings.TrimRight(c.Endpoint, "/") + "/api/v1/sync/" + url.PathEscape(c.Account), nil
}
func writeHostsRaw(svc *AppService, hs []HostConfig) error {
	p, e := hostsPath()
	if e != nil {
		return e
	}
	out := append([]HostConfig(nil), hs...)
	for i := range out {
		out[i] = normHost(out[i])
		var err error
		out[i], err = svc.encryptHostSecrets(out[i])
		if err != nil {
			return err
		}
	}
	return secureWriteJSON(p, out)
}
func writeVaultRaw(svc *AppService, vs []VaultCredential) error {
	p, e := vaultPath()
	if e != nil {
		return e
	}
	out := append([]VaultCredential(nil), vs...)
	for i := range out {
		out[i] = normVaultCredential(out[i])
		var err error
		out[i], err = svc.encryptVaultSecrets(out[i])
		if err != nil {
			return err
		}
	}
	return secureWriteJSON(p, out)
}
func localExportDefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, "Downloads", fmt.Sprintf("ssh-vault2-export-%s.sshv2export", time.Now().Format("20060102-150405")))
}
func normalizeLocalExportPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = localExportDefaultPath()
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	p = filepath.Clean(p)
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		p = filepath.Join(p, filepath.Base(localExportDefaultPath()))
	}
	if filepath.Ext(p) == "" {
		p += ".sshv2export"
	}
	return p
}
func sanitizeImportedHost(h HostConfig) HostConfig {
	h = normHost(h)
	h.KeyPath = ""
	return h
}

func sanitizeImportedVault(v VaultCredential) VaultCredential {
	v = normVaultCredential(v)
	v.KeyPath = ""
	return v
}

func trustedKeyPathForExport(p string) (string, bool) {
	clean := filepath.Clean(strings.TrimSpace(p))
	if clean == "" || !filepath.IsAbs(clean) {
		return "", false
	}
	d, err := configDir()
	if err != nil {
		return "", false
	}
	for _, sub := range []string{"imported-keys", "synced-keys"} {
		root := filepath.Clean(filepath.Join(d, sub))
		rel, relErr := filepath.Rel(root, clean)
		if relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return clean, true
		}
	}
	return "", false
}

func (s *AppService) readTrustedKeyForExport(keyPath string) ([]byte, string, bool) {
	cleanKeyPath, trusted := trustedKeyPathForExport(keyPath)
	if !trusted {
		return nil, "", false
	}
	b, cleanKeyPath, ok := tryReadAllowedSmallLocalFile(cleanKeyPath, 1024*1024)
	if !ok {
		return nil, "", false
	}
	if isEncryptedValue(strings.TrimSpace(string(b))) {
		plain, err := s.decryptSecret(strings.TrimSpace(string(b)), false)
		if err != nil {
			return nil, "", false
		}
		return []byte(plain), cleanKeyPath, true
	}
	return b, cleanKeyPath, true
}

func normalizeLocalImportPath(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	return filepath.Clean(p)
}

func mergeHosts(existing, incoming []HostConfig) []HostConfig {
	out := append([]HostConfig{}, existing...)
	idx := map[string]int{}
	for i, h := range out {
		if h.ID != "" {
			idx["id:"+h.ID] = i
		}
		idx["name:"+strings.ToLower(h.Name)] = i
	}
	for _, h := range incoming {
		h = normHost(h)
		key := ""
		if h.ID != "" {
			key = "id:" + h.ID
		}
		if i, ok := idx[key]; ok && key != "" {
			out[i] = h
			continue
		}
		nameKey := "name:" + strings.ToLower(h.Name)
		if i, ok := idx[nameKey]; ok {
			out[i] = h
			continue
		}
		out = append(out, h)
		if h.ID != "" {
			idx["id:"+h.ID] = len(out) - 1
		}
		idx[nameKey] = len(out) - 1
	}
	return out
}
func mergeVault(existing, incoming []VaultCredential) []VaultCredential {
	out := append([]VaultCredential{}, existing...)
	idx := map[string]int{}
	for i, v := range out {
		if v.ID != "" {
			idx["id:"+v.ID] = i
		}
		idx["name:"+strings.ToLower(v.Name)] = i
	}
	for _, v := range incoming {
		v = normVaultCredential(v)
		key := ""
		if v.ID != "" {
			key = "id:" + v.ID
		}
		if i, ok := idx[key]; ok && key != "" {
			out[i] = v
			continue
		}
		nameKey := "name:" + strings.ToLower(v.Name)
		if i, ok := idx[nameKey]; ok {
			out[i] = v
			continue
		}
		out = append(out, v)
		if v.ID != "" {
			idx["id:"+v.ID] = len(out) - 1
		}
		idx[nameKey] = len(out) - 1
	}
	return out
}
func (s *AppService) ExportLocalData(pathOut string, passphrase string) (LocalTransferResult, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	st, _ := s.LocalVaultStatus()
	if st.Configured && !st.Unlocked && st.EncryptedValues > 0 {
		return LocalTransferResult{}, fmt.Errorf("Lokaler Datensafe ist gesperrt: vor Export entsperren, sonst fehlen Tresor-Secrets")
	}
	hs, err := s.listHostsDecrypted(false)
	if err != nil {
		return LocalTransferResult{}, err
	}
	vs, err := s.listVaultDecrypted(false)
	if err != nil {
		return LocalTransferResult{}, err
	}
	if len(hs) == 0 && len(vs) == 0 {
		return LocalTransferResult{}, fmt.Errorf("Nichts zu exportieren: keine Hosts und keine Tresor-Einträge")
	}
	payload := SyncPayload{Version: 2, Hosts: hs, Vault: vs, Settings: map[string]string{"type": "local-export", "platform": runtime.GOOS, "arch": runtime.GOARCH}, SyncedAt: time.Now().UnixMilli()}
	for _, h := range hs {
		if b, cleanKeyPath, ok := s.readTrustedKeyForExport(h.KeyPath); ok {
			payload.Keys = append(payload.Keys, SyncKey{HostID: h.ID, Name: filepath.Base(cleanKeyPath), Content: base64.StdEncoding.EncodeToString(b)})
		}
	}
	blob, err := encryptSync(passphrase, payload)
	if err != nil {
		return LocalTransferResult{}, err
	}
	outPath := normalizeLocalExportPath(pathOut)
	outPath, err = requireLocalPathAccess(outPath, false)
	if err != nil {
		return LocalTransferResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return LocalTransferResult{}, err
	}
	body, _ := json.MarshalIndent(blob, "", "  ")
	if err := secureWriteFile(outPath, append(body, '\n')); err != nil {
		return LocalTransferResult{}, err
	}
	return LocalTransferResult{OK: true, Message: "Lokaler Export geschrieben", Path: outPath, Count: len(hs), VaultCount: len(vs)}, nil
}
func (s *AppService) ImportLocalData(pathIn string, passphrase string, replace bool) (LocalTransferResult, error) {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	st, _ := s.LocalVaultStatus()
	if st.Configured && !st.Unlocked && st.EncryptedValues > 0 {
		return LocalTransferResult{}, fmt.Errorf("Lokaler Datensafe ist gesperrt: vor Import entsperren")
	}
	inPath := normalizeLocalImportPath(pathIn)
	var err error
	inPath, err = requireLocalPathAccess(inPath, true)
	if err != nil {
		return LocalTransferResult{}, err
	}
	info, err := os.Stat(inPath)
	if err != nil {
		return LocalTransferResult{}, err
	}
	if info.IsDir() || info.Size() > 50*1024*1024 {
		return LocalTransferResult{}, fmt.Errorf("ungültige Importdatei")
	}
	b, err := os.ReadFile(inPath)
	if err != nil {
		return LocalTransferResult{}, err
	}
	var blob EncryptedSyncBlob
	if err := json.Unmarshal(cleanJSONBytes(b), &blob); err != nil {
		return LocalTransferResult{}, fmt.Errorf("Importdatei ist kein gültiger ssh-vault2 Export: %w", err)
	}
	payload, err := decryptSync(passphrase, blob)
	if err != nil {
		return LocalTransferResult{}, err
	}
	if len(payload.Hosts) == 0 && len(payload.Vault) == 0 && len(payload.Keys) == 0 {
		return LocalTransferResult{}, fmt.Errorf("Importdatei enthält keine Hosts und keinen Tresor")
	}
	keyDir, _ := configDir()
	keyDir = filepath.Join(keyDir, "imported-keys")
	_ = os.MkdirAll(keyDir, 0700)
	hostIDMap := map[string]string{}
	for i := range payload.Hosts {
		oldID := payload.Hosts[i].ID
		payload.Hosts[i] = sanitizeImportedHost(payload.Hosts[i])
		hostIDMap[oldID] = payload.Hosts[i].ID
	}
	for i := range payload.Vault {
		payload.Vault[i] = sanitizeImportedVault(payload.Vault[i])
	}
	for _, k := range payload.Keys {
		kb, err := base64.StdEncoding.DecodeString(k.Content)
		if err != nil || len(kb) > 1024*1024 {
			continue
		}
		name, err := safeLocalChildName(filepath.Base(k.Name))
		if err != nil {
			name = "id_imported"
		}
		hostID := hostIDMap[k.HostID]
		if hostID == "" {
			hostID = safeRecordID(k.HostID)
		}
		kp, err := safeJoinUnder(keyDir, hostID+"-"+name)
		if err != nil {
			continue
		}
		enc, err := s.encryptSecret(string(kb))
		if err != nil {
			return LocalTransferResult{}, err
		}
		if err = secureWriteFile(kp, []byte(enc)); err == nil {
			for i := range payload.Hosts {
				if payload.Hosts[i].ID == hostID {
					payload.Hosts[i].KeyPath = kp
				}
			}
		}
	}
	finalHosts := payload.Hosts
	finalVault := payload.Vault
	if !replace {
		existingHosts, _ := s.listHostsDecrypted(false)
		existingVault, _ := s.listVaultDecrypted(false)
		finalHosts = mergeHosts(existingHosts, payload.Hosts)
		finalVault = mergeVault(existingVault, payload.Vault)
	}
	if err = writeVaultRaw(s, finalVault); err != nil {
		return LocalTransferResult{}, err
	}
	if err = writeHostsRaw(s, finalHosts); err != nil {
		return LocalTransferResult{}, err
	}
	return LocalTransferResult{OK: true, Message: "Lokaler Export importiert", Path: inPath, Count: len(payload.Hosts), VaultCount: len(payload.Vault)}, nil
}

func (s *AppService) SyncPush(passphrase string) (SyncResult, error) {
	c, e := s.getSyncConfigRaw()
	if e != nil {
		return SyncResult{}, e
	}
	c, e = s.decryptSyncSecrets(c, false)
	if e != nil {
		return SyncResult{}, e
	}
	u, e := s.syncURL(c)
	if e != nil {
		return SyncResult{}, e
	}
	hs, e := s.listHostsDecrypted(false)
	if e != nil {
		return SyncResult{}, e
	}
	vs, e := s.listVaultDecrypted(false)
	if e != nil {
		return SyncResult{}, e
	}
	if len(hs) == 0 && len(vs) == 0 {
		return SyncResult{}, fmt.Errorf("Leerer lokaler Stand wird nicht hochgeladen. Erst Daten anlegen/importieren oder auf einem Gerät mit Daten hochladen.")
	}
	effectivePassphrase := passphrase
	if strings.TrimSpace(effectivePassphrase) == "" && strings.TrimSpace(c.AutoPassphrase) != "" {
		effectivePassphrase = c.AutoPassphrase
	}
	payload := SyncPayload{Version: 1, Hosts: hs, Vault: vs, Settings: map[string]string{"platform": runtime.GOOS}, SyncedAt: time.Now().UnixMilli()}
	if c.IncludeKeys {
		for _, h := range hs {
			if b, cleanKeyPath, ok := s.readTrustedKeyForExport(h.KeyPath); ok {
				payload.Keys = append(payload.Keys, SyncKey{HostID: h.ID, Name: filepath.Base(cleanKeyPath), Content: base64.StdEncoding.EncodeToString(b)})
			}
		}
	}
	blob, e := encryptSync(effectivePassphrase, payload)
	if e != nil {
		return SyncResult{}, e
	}
	body, _ := json.Marshal(blob)
	req, e := http.NewRequest("PUT", u, bytes.NewReader(body))
	if e != nil {
		return SyncResult{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sync-Token", c.Token)
	req.Header.Set("X-Sync-Host-Count", fmt.Sprintf("%d", len(hs)))
	req.Header.Set("X-Sync-Vault-Count", fmt.Sprintf("%d", len(vs)))
	res, e := appHTTPClient().Do(req)
	if e != nil {
		return SyncResult{}, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := readAllStrict(res.Body, maxErrorBodyBytes)
		return SyncResult{}, fmt.Errorf("Sync Push HTTP %d: %s", res.StatusCode, string(b))
	}
	c.LastSync = time.Now().UnixMilli()
	_, _ = s.SaveSyncConfig(c)
	return SyncResult{OK: true, Message: "Sync hochgeladen (verschlüsselt)", Count: len(hs), VaultCount: len(vs)}, nil
}
func (s *AppService) SyncPull(passphrase string) (SyncResult, error) {
	c, e := s.getSyncConfigRaw()
	if e != nil {
		return SyncResult{}, e
	}
	c, e = s.decryptSyncSecrets(c, false)
	if e != nil {
		return SyncResult{}, e
	}
	u, e := s.syncURL(c)
	if e != nil {
		return SyncResult{}, e
	}
	req, e := http.NewRequest("GET", u, nil)
	if e != nil {
		return SyncResult{}, e
	}
	req.Header.Set("X-Sync-Token", c.Token)
	res, e := appHTTPClient().Do(req)
	if e != nil {
		return SyncResult{}, e
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return SyncResult{}, fmt.Errorf("Noch kein Sync auf Server")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := readAllStrict(res.Body, maxErrorBodyBytes)
		return SyncResult{}, fmt.Errorf("Sync Pull HTTP %d: %s", res.StatusCode, string(b))
	}
	var blob EncryptedSyncBlob
	resBody, e := readAllStrict(res.Body, maxSyncBodyBytes)
	if e != nil {
		return SyncResult{}, e
	}
	if e = json.Unmarshal(cleanJSONBytes(resBody), &blob); e != nil {
		return SyncResult{}, e
	}
	effectivePassphrase := passphrase
	if strings.TrimSpace(effectivePassphrase) == "" && strings.TrimSpace(c.AutoPassphrase) != "" {
		effectivePassphrase = c.AutoPassphrase
	}
	payload, e := decryptSync(effectivePassphrase, blob)
	if e != nil {
		return SyncResult{}, e
	}
	if len(payload.Hosts) == 0 && len(payload.Vault) == 0 && len(payload.Keys) == 0 {
		return SyncResult{}, fmt.Errorf("Server-Sync enthält keine Hosts und keinen Tresor. Lokale Daten werden nicht überschrieben.")
	}
	keyDir, _ := configDir()
	keyDir = filepath.Join(keyDir, "synced-keys")
	_ = os.MkdirAll(keyDir, 0700)
	hostIDMap := map[string]string{}
	for i := range payload.Hosts {
		oldID := payload.Hosts[i].ID
		payload.Hosts[i] = sanitizeImportedHost(payload.Hosts[i])
		hostIDMap[oldID] = payload.Hosts[i].ID
	}
	for i := range payload.Vault {
		payload.Vault[i] = sanitizeImportedVault(payload.Vault[i])
	}
	for _, k := range payload.Keys {
		b, e := base64.StdEncoding.DecodeString(k.Content)
		if e != nil || len(b) > 1024*1024 {
			continue
		}
		name, err := safeLocalChildName(filepath.Base(k.Name))
		if err != nil {
			name = "id_synced"
		}
		hostID := hostIDMap[k.HostID]
		if hostID == "" {
			hostID = safeRecordID(k.HostID)
		}
		kp, err := safeJoinUnder(keyDir, hostID+"-"+name)
		if err != nil {
			continue
		}
		enc, e := s.encryptSecret(string(b))
		if e != nil {
			return SyncResult{}, e
		}
		if e = secureWriteFile(kp, []byte(enc)); e == nil {
			for i := range payload.Hosts {
				if payload.Hosts[i].ID == hostID {
					payload.Hosts[i].KeyPath = kp
				}
			}
		}
	}
	if e = writeHostsRaw(s, payload.Hosts); e != nil {
		return SyncResult{}, e
	}
	if e = writeVaultRaw(s, payload.Vault); e != nil {
		return SyncResult{}, e
	}
	c.LastSync = time.Now().UnixMilli()
	_, _ = s.SaveSyncConfig(c)
	return SyncResult{OK: true, Message: "Sync geladen und lokal entschlüsselt", Count: len(payload.Hosts), VaultCount: len(payload.Vault)}, nil
}

func expandSSHPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "\"'")
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if h, e := os.UserHomeDir(); e == nil {
			p = filepath.Join(h, p[2:])
		}
	}
	return filepath.Clean(p)
}
func sshConfigDefaultPath() string {
	if h, e := os.UserHomeDir(); e == nil {
		return filepath.Join(h, ".ssh", "config")
	}
	return ""
}
func (s *AppService) ImportSSHConfig(pathIn string) (ImportResult, error) {
	pathIn = strings.TrimSpace(pathIn)
	if pathIn == "" {
		pathIn = sshConfigDefaultPath()
	}
	var accessErr error
	pathIn, accessErr = requireLocalPathAccess(pathIn, true)
	if accessErr != nil {
		return ImportResult{}, accessErr
	}
	f, e := os.Open(pathIn)
	if e != nil {
		return ImportResult{}, e
	}
	defer f.Close()
	existing, _ := s.ListHosts()
	seen := map[string]bool{}
	for _, h := range existing {
		seen[strings.ToLower(h.Name)] = true
		seen[strings.ToLower(fmt.Sprintf("%s|%s|%d", h.Username, h.Address, h.Port))] = true
	}
	var aliases []string
	props := map[string]string{}
	imported := []HostConfig{}
	flush := func() {
		if len(aliases) == 0 {
			return
		}
		for _, alias := range aliases {
			if alias == "" || strings.ContainsAny(alias, "*?") {
				continue
			}
			addr := props["hostname"]
			if addr == "" {
				addr = alias
			}
			port := 22
			if props["port"] != "" {
				_, _ = fmt.Sscanf(props["port"], "%d", &port)
				if port == 0 {
					port = 22
				}
			}
			user := props["user"]
			keyPath := ""
			if props["identityfile"] != "" {
				keyPath = expandSSHPath(props["identityfile"])
			}
			if keyPath == "" {
				continue
			}
			auth := "key"
			h := normHost(HostConfig{Name: alias, Address: addr, Port: port, Username: user, AuthMode: auth, KeyPath: keyPath, Tags: []string{"ssh-config"}})
			k1 := strings.ToLower(h.Name)
			k2 := strings.ToLower(fmt.Sprintf("%s|%s|%d", h.Username, h.Address, h.Port))
			if seen[k1] || seen[k2] {
				continue
			}
			seen[k1], seen[k2] = true, true
			imported = append(imported, h)
		}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.TrimSpace(strings.Join(parts[1:], " "))
		switch key {
		case "host":
			flush()
			aliases = nil
			props = map[string]string{}
			for _, a := range parts[1:] {
				aliases = append(aliases, strings.TrimSpace(a))
			}
		case "hostname", "user", "port", "identityfile":
			if len(aliases) > 0 {
				props[key] = val
			}
		}
	}
	if e = sc.Err(); e != nil {
		return ImportResult{}, e
	}
	flush()
	if len(imported) == 0 {
		return ImportResult{OK: true, Message: "Keine neuen Hosts in .ssh/config gefunden", Count: 0}, nil
	}
	all := append(existing, imported...)
	if e = writeHostsRaw(s, all); e != nil {
		return ImportResult{}, e
	}
	return ImportResult{OK: true, Message: ".ssh/config importiert", Count: len(imported)}, nil
}

func (s *AppService) ServerReleases() (ReleaseIndex, error) {
	var idx ReleaseIndex
	signedSums, e := fetchSignedReleaseSums()
	if e != nil {
		return idx, e
	}
	res, e := appHTTPClient().Get(releaseServer + "/api/v1/releases")
	if e != nil {
		return idx, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail := readErrorBody(res.Body)
		if detail != "" {
			return idx, fmt.Errorf("Release-Index HTTP %d: %s", res.StatusCode, detail)
		}
		return idx, fmt.Errorf("Release-Index HTTP %d", res.StatusCode)
	}
	body, e := readAllStrict(res.Body, maxReleaseIndexBytes)
	if e != nil {
		return idx, e
	}
	e = json.Unmarshal(cleanJSONBytes(body), &idx)
	if e != nil {
		return idx, e
	}
	validAsset := func(a ReleaseAsset) bool {
		expected := signedSums[filepath.Base(a.Name)]
		return expected != "" && a.SHA256 != "" && strings.EqualFold(a.SHA256, expected) && validateUpdateAssetForInstall(a) == nil
	}
	filteredFiles := make([]ReleaseAsset, 0, len(idx.Files))
	for _, a := range idx.Files {
		if validAsset(a) {
			filteredFiles = append(filteredFiles, a)
		}
	}
	idx.Files = filteredFiles
	filteredVersions := make([]ReleaseVersion, 0, len(idx.Versions))
	for _, v := range idx.Versions {
		assets := make([]ReleaseAsset, 0, len(v.Assets))
		for _, a := range v.Assets {
			if validAsset(a) {
				assets = append(assets, a)
			}
		}
		if len(assets) > 0 {
			v.Assets = assets
			filteredVersions = append(filteredVersions, v)
		}
	}
	idx.Versions = filteredVersions
	return idx, nil
}
