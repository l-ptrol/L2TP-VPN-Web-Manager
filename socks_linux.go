//go:build linux

package main

import (
	"syscall"
)

func bindToDevice(fd uintptr, deviceName string) error {
	if deviceName == "" {
		return nil
	}
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, deviceName)
}
