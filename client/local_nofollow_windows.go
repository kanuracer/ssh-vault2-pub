//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func rejectWindowsReparsePoint(p string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(p))
	if err != nil {
		if errorsIsNotExist(err) {
			return nil
		}
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("Windows-Reparse-Point blockiert: %s", p)
	}
	return nil
}

func errorsIsNotExist(err error) bool {
	return err == syscall.ERROR_FILE_NOT_FOUND || err == syscall.ERROR_PATH_NOT_FOUND || os.IsNotExist(err)
}

func secureCreateFileNoFollow(p string, perm os.FileMode) (*os.File, error) {
	if err := rejectSymlinkPath(p); err != nil {
		return nil, err
	}
	if err := rejectWindowsReparsePoint(p); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), p)
	if f == nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("Datei öffnen fehlgeschlagen")
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("Pfad ist keine reguläre Datei")
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return nil, err
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
