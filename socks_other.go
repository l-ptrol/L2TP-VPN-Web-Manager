//go:build !linux

package main

func bindToDevice(fd uintptr, deviceName string) error {
	return nil
}
