//go:build darwin

package provider

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
)

var errDarwinCommandOutputLimit = errors.New("darwin command output exceeded the safety limit")

// darwinCleanEnvironment deliberately excludes caller-controlled loader,
// debugger and language-runtime variables. Every supported child is addressed
// by an absolute path, so it does not need the ambient environment to resolve
// another executable.
func darwinCleanEnvironment() []string {
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/var/empty",
		"TMPDIR=/tmp",
	}
}

// runDarwinCommand owns a fresh process group. Cancellation therefore stops
// both the requested executable and any descendants it creates.
func runDarwinCommand(ctx context.Context, command *exec.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if command.Env == nil {
		command.Env = darwinCleanEnvironment()
	}
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Setpgid = true
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		select {
		case err := <-finished:
			return err
		default:
		}
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		<-finished
		return ctx.Err()
	}
}

type failClosedDarwinOutput struct {
	sensitiveOutputBuffer
	onLimit func()
}

func (buffer *failClosedDarwinOutput) Write(value []byte) (int, error) {
	written, _ := buffer.sensitiveOutputBuffer.Write(value)
	if buffer.over {
		if buffer.onLimit != nil {
			buffer.onLimit()
		}
		return written, errDarwinCommandOutputLimit
	}
	return written, nil
}

// runBoundedDarwinCommand is the single entry point for short-lived macOS
// tools. It fixes the executable path, cleans the environment, bounds both
// streams while the process is running, and applies process-group cleanup.
func runBoundedDarwinCommand(
	ctx context.Context,
	path string,
	arguments []string,
	stdin io.Reader,
	directory string,
	stdoutLimit int,
	stderrLimit int,
) ([]byte, []byte, error) {
	if !filepath.IsAbs(path) || stdoutLimit <= 0 || stderrLimit <= 0 {
		return nil, nil, errors.New("darwin command contract is invalid")
	}
	command := exec.Command(path, arguments...)
	command.Env = darwinCleanEnvironment()
	command.Stdin = stdin
	command.Dir = directory
	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := failClosedDarwinOutput{
		sensitiveOutputBuffer: sensitiveOutputBuffer{limit: stdoutLimit}, onLimit: cancel,
	}
	stderr := failClosedDarwinOutput{
		sensitiveOutputBuffer: sensitiveOutputBuffer{limit: stderrLimit}, onLimit: cancel,
	}
	defer stdout.Clear()
	defer stderr.Clear()
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := runDarwinCommand(commandContext, command)
	if stdout.over || stderr.over {
		return nil, nil, errDarwinCommandOutputLimit
	}
	return cloneSensitiveBytes(stdout.Bytes()), cloneSensitiveBytes(stderr.Bytes()), err
}

func runBoundedDarwinOutput(ctx context.Context, path string, arguments []string, limit int) ([]byte, error) {
	stdout, stderr, err := runBoundedDarwinCommand(ctx, path, arguments, nil, "", limit, limit)
	zeroBytes(stderr)
	if err != nil {
		zeroBytes(stdout)
		return nil, err
	}
	return stdout, nil
}

func runBoundedDarwinCombinedOutput(ctx context.Context, path string, arguments []string, limit int) ([]byte, error) {
	stdout, stderr, commandErr := runBoundedDarwinCommand(ctx, path, arguments, nil, "", limit, limit)
	defer zeroBytes(stdout)
	defer zeroBytes(stderr)
	combined := sensitiveOutputBuffer{limit: limit}
	defer combined.Clear()
	_, _ = combined.Write(stdout)
	_, _ = combined.Write(stderr)
	if combined.over {
		return nil, errDarwinCommandOutputLimit
	}
	return cloneSensitiveBytes(combined.Bytes()), commandErr
}
