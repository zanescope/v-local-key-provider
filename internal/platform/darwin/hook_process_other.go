//go:build !darwin

package darwin

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}

func signalProcessTerminate(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
}

func killCurrentProcessGroup() {}

func killProcessGroup(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
}
