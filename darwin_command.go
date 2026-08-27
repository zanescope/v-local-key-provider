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

// darwinCleanEnvironment 主动排除调用方可控的 loader、debugger 和 language runtime
// 变量。所有受支持的子进程均使用绝对路径，因此不需要借助环境变量解析其他可执行文件。
func darwinCleanEnvironment() []string {
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/var/empty",
		"TMPDIR=/tmp",
	}
}

// runDarwinCommand 持有一个新 process group，因此取消操作会同时停止请求的可执行文件
// 及其创建的全部后代进程。
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

// runBoundedDarwinCommand 是短生命周期 macOS 工具的唯一入口。它固定可执行文件路径、
// 清理环境变量、在进程运行期间限制两个 stream，并执行 process group 清理。
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
