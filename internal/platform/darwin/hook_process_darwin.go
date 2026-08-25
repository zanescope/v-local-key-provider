//go:build darwin

package darwin

import (
	"os/exec"
	"syscall"
)

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalProcessTerminate(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Signal(syscall.SIGTERM)
	}
}

func killCurrentProcessGroup() {
	_ = syscall.Kill(-syscall.Getpgrp(), syscall.SIGKILL)
}

func killProcessGroup(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
