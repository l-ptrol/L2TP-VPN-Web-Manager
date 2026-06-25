//go:build !windows
// +build !windows

package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func restartSelf() {
	time.Sleep(1 * time.Second)
	log.Printf("[L2TP] Restarting process (Linux)...")
	
	args := filterArgs(os.Args)
	exePath, err := os.Executable()
	if err != nil {
		exePath = args[0]
	}
	
	binary, err := exec.LookPath(exePath)
	if err == nil {
		err = syscall.Exec(binary, args, os.Environ())
		if err != nil {
			log.Printf("[L2TP] syscall.Exec failed: %v, falling back to os/exec...", err)
			cmd := exec.Command(binary, args[1:]...)
			_ = cmd.Start()
			os.Exit(0)
		}
	} else {
		log.Fatalf("[L2TP] LookPath failed: %v", err)
	}
}

