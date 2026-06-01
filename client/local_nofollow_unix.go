//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func rejectWindowsReparsePoint(p string) error { return nil }

func secureCreateFileNoFollow(p string, perm os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(perm))
	if err != nil {
		if err == syscall.ELOOP {
			return nil, fmt.Errorf("Symlinks sind für lokale Dateizugriffe blockiert")
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("Pfad ist keine reguläre Datei")
	}
	return f, nil
}

func secureWriteFileNoFollow(p string, data []byte, perm os.FileMode) error {
	f, err := secureCreateFileNoFollow(p, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
