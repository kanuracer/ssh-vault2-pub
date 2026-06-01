package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
)

type IdentityOption struct {
	Name  string `json:"name"`
	ID    uint32 `json:"id"`
	Label string `json:"label"`
}

type IdentityOptions struct {
	Owners []IdentityOption `json:"owners"`
	Groups []IdentityOption `json:"groups"`
}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }

func parseOctalMode(octal string) (os.FileMode, error) {
	octal = strings.TrimSpace(octal)
	if len(octal) == 3 {
		octal = "0" + octal
	}
	if len(octal) != 4 {
		return 0, fmt.Errorf("Oktalwert braucht 3 oder 4 Ziffern")
	}
	n, err := strconv.ParseUint(octal, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("ungültiger Oktalwert")
	}
	return os.FileMode(n), nil
}

func hashForAlgorithm(algo string) (hash.Hash, string, error) {
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "md5":
		return md5.New(), "MD5", nil
	case "sha1", "sha-1":
		return sha1.New(), "SHA1", nil
	case "sha256", "sha-256", "":
		return sha256.New(), "SHA256", nil
	default:
		return nil, "", fmt.Errorf("unbekannte Prüfsumme: %s", algo)
	}
}

func propsSFTPByID(s *AppService, id string) (*sftpRec, func(), error) {
	return s.lockedSFTP(id)
}

func (s *AppService) PropertiesStatSFTP(id string, remotePath string) (FileEntry, error) {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return FileEntry{}, err
	}
	defer unlock()
	fi, err := r.sftp.Lstat(remotePath)
	if err != nil {
		return FileEntry{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return FileEntry{}, fmt.Errorf("SFTP-Symlinks werden für Eigenschaften blockiert")
	}
	out := sftpEntry(path.Dir(remotePath), fi)
	out.Name = path.Base(remotePath)
	out.Path = remotePath
	if sess, err := r.client.NewSession(); err == nil {
		cmd := "sh -lc " + shellQuote("stat -c '%U\t%G' "+shellQuote(remotePath))
		if b, err := sess.CombinedOutput(cmd); err == nil {
			parts := strings.Split(strings.TrimSpace(string(b)), "\t")
			if len(parts) >= 2 {
				out.Owner = parts[0]
				out.Group = parts[1]
			}
		}
		_ = sess.Close()
	}
	if out.Owner == "" {
		if h, err := s.hostByID(r.hostID); err == nil && h.Username != "" {
			out.Owner = h.Username
		}
	}
	if out.Group == "" {
		out.Group = out.Owner
	}
	return out, nil
}

func (s *AppService) PropertiesLocalStat(localPath string) (FileEntry, error) {
	var err error
	localPath, err = requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return FileEntry{}, err
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		return FileEntry{}, err
	}
	return localEntry(localPath, fi), nil
}

func parseIdentityOutput(b []byte) []IdentityOption {
	out := []IdentityOption{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		id64, _ := strconv.ParseUint(parts[1], 10, 32)
		id := uint32(id64)
		out = append(out, IdentityOption{Name: parts[0], ID: id, Label: fmt.Sprintf("%s [%d]", parts[0], id)})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (s *AppService) PropertiesIdentityOptionsSFTP(id string) (IdentityOptions, error) {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return IdentityOptions{}, err
	}
	defer unlock()
	owners, groups := []IdentityOption{}, []IdentityOption{}
	if sess, err := r.client.NewSession(); err == nil {
		b, e := sess.CombinedOutput("sh -lc " + shellQuote("(getent passwd || cat /etc/passwd) 2>/dev/null | awk -F: '{print $1\"\t\"$3}' | head -200"))
		_ = sess.Close()
		if e == nil {
			owners = parseIdentityOutput(b)
		}
	}
	if sess, err := r.client.NewSession(); err == nil {
		b, e := sess.CombinedOutput("sh -lc " + shellQuote("(getent group || cat /etc/group) 2>/dev/null | awk -F: '{print $1\"\t\"$3}' | head -200"))
		_ = sess.Close()
		if e == nil {
			groups = parseIdentityOutput(b)
		}
	}
	return IdentityOptions{Owners: owners, Groups: groups}, nil
}

func propsDirSizeSFTP(sc *sftp.Client, p string) (int64, error) {
	fi, err := sc.Lstat(p)
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("SFTP-Symlinks werden für rekursive Eigenschaften blockiert")
	}
	if !fi.IsDir() {
		return fi.Size(), nil
	}
	ents, err := sc.ReadDir(p)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range ents {
		n, err := propsDirSizeSFTP(sc, pathJoinRemote(p, e.Name()))
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func (s *AppService) PropertiesSizeSFTP(id string, remotePath string) (int64, error) {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return propsDirSizeSFTP(r.sftp, remotePath)
}

func (s *AppService) PropertiesSizeLocal(localPath string) (int64, error) {
	var total int64
	var err error
	localPath, err = requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		return 0, err
	}
	if !fi.IsDir() {
		return fi.Size(), nil
	}
	err = filepath.WalkDir(localPath, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}

func (s *AppService) PropertiesChecksumSFTP(id string, remotePath string, algo string) (string, error) {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return "", err
	}
	defer unlock()
	fi, err := r.sftp.Lstat(remotePath)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("SFTP-Symlinks werden für Prüfsummen blockiert")
	}
	if fi.IsDir() {
		return "", fmt.Errorf("Prüfsumme nur für Dateien")
	}
	f, err := r.sftp.Open(remotePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h, name, err := hashForAlgorithm(algo)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return name + ": " + fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (s *AppService) PropertiesChecksumLocal(localPath string, algo string) (string, error) {
	var err error
	localPath, err = requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("Prüfsumme nur für Dateien")
	}
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h, name, err := hashForAlgorithm(algo)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return name + ": " + fmt.Sprintf("%x", h.Sum(nil)), nil
}

func propsChmodSFTP(sc *sftp.Client, p string, mode os.FileMode, recursive bool) error {
	fi, err := sc.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SFTP-Symlinks werden für Rechteänderungen blockiert")
	}
	if err := sc.Chmod(p, mode); err != nil {
		return err
	}
	if !recursive || !fi.IsDir() {
		return nil
	}
	ents, err := sc.ReadDir(p)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := propsChmodSFTP(sc, pathJoinRemote(p, e.Name()), mode, recursive); err != nil {
			return err
		}
	}
	return nil
}

func (s *AppService) PropertiesChmodSFTP(id string, remotePath string, octal string, recursive bool) error {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return err
	}
	defer unlock()
	mode, err := parseOctalMode(octal)
	if err != nil {
		return err
	}
	return propsChmodSFTP(r.sftp, remotePath, mode, recursive)
}

func (s *AppService) PropertiesChmodLocal(localPath string, octal string, recursive bool) error {
	mode, err := parseOctalMode(octal)
	if err != nil {
		return err
	}
	localPath, err = requireGenericLocalPathAccess(localPath, true)
	if err != nil {
		return err
	}
	if !recursive {
		return os.Chmod(localPath, mode)
	}
	return filepath.WalkDir(localPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Chmod(p, mode)
	})
}

func (s *AppService) PropertiesChownSFTP(id string, remotePath string, owner string, group string, recursive bool) error {
	r, unlock, err := propsSFTPByID(s, id)
	if err != nil {
		return err
	}
	defer unlock()
	owner = strings.TrimSpace(owner)
	group = strings.TrimSpace(group)
	if owner == "" && group == "" {
		return nil
	}
	target := owner
	if group != "" {
		target += ":" + group
	}
	if err := rejectRemoteSymlink(r, remotePath); err != nil {
		return err
	}
	sess, err := r.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	var cmdText string
	if recursive {
		cmdText = "find -P " + shellQuote(remotePath) + " -type l -prune -o -exec chown -h " + shellQuote(target) + " {} +"
	} else {
		cmdText = "chown -h " + shellQuote(target) + " " + shellQuote(remotePath)
	}
	cmd := "sh -lc " + shellQuote(cmdText)
	if b, err := sess.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("chown fehlgeschlagen: %s", strings.TrimSpace(string(b)))
	}
	return nil
}
