//go:build windows
// +build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"time"
)

func restartSelf() {
	time.Sleep(1 * time.Second)
	log.Printf("[L2TP] Restarting process (Windows)...")
	
	args := filterArgs(os.Args)
	exePath, err := os.Executable()
	if err != nil {
		exePath = args[0]
	}
	
	cmd := exec.Command(exePath, args[1:]...)
	_ = cmd.Start()
	os.Exit(0)
}
