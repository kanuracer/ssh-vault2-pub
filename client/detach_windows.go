//go:build windows

package main

import "syscall"

func detachedSysProcAttr() *syscall.SysProcAttr {
	const createBreakawayFromJob = 0x01000000
	const createNoWindow = 0x08000000
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | createBreakawayFromJob | createNoWindow}
}
