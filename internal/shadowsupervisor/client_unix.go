//go:build !windows

package shadowsupervisor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type StartConfig struct {
	SupervisorPath   string
	SupervisorDigest string
	Init             Frame
	ResponseTimeout  time.Duration
}

type Client struct {
	mu         sync.Mutex
	control    net.Conn
	reader     *bufio.Reader
	command    *exec.Cmd
	init       Frame
	supervisor Frame
	bound      Frame
	done       chan struct{}
	waitErr    error
	closed     bool
}

func supervisorExecutable(path, expectedDigest string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !validDigest(expectedDigest) {
		return "", errors.New("supervisor executable binding is invalid")
	}
	info, err := os.Lstat(path)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || resolveErr != nil || resolved != path || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("supervisor executable is not an exact executable file")
	}
	digest, err := digestFile(path)
	if err != nil || digest != expectedDigest {
		return "", errors.New("supervisor executable digest drifted")
	}
	return path, nil
}

func newControlSocketPair() (net.Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parent := os.NewFile(uintptr(fds[0]), "shadow-supervisor-parent")
	child := os.NewFile(uintptr(fds[1]), "shadow-supervisor-child")
	connection, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	return connection, child, nil
}

func responseDeadline(ctx context.Context, fallback time.Duration) time.Time {
	deadline := time.Now().Add(fallback)
	if candidate, ok := ctx.Deadline(); ok && candidate.Before(deadline) {
		deadline = candidate
	}
	return deadline
}

func (value *Client) readResponseLocked(ctx context.Context, timeout time.Duration) (Frame, error) {
	if value.closed || value.control == nil || value.reader == nil || ctx == nil {
		return Frame{}, errors.New("supervisor client is closed")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := value.control.SetReadDeadline(responseDeadline(ctx, timeout)); err != nil {
		return Frame{}, err
	}
	frame, err := readLine(value.reader)
	_ = value.control.SetReadDeadline(time.Time{})
	if err != nil {
		return Frame{}, errors.New("supervisor response is unavailable")
	}
	return frame, nil
}

func (value *Client) writeRequestLocked(ctx context.Context, request Frame, timeout time.Duration) error {
	if value.closed || value.control == nil || ctx == nil {
		return errors.New("supervisor client is closed")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := value.control.SetWriteDeadline(responseDeadline(ctx, timeout)); err != nil {
		return err
	}
	err := writeFrame(value.control, request)
	_ = value.control.SetWriteDeadline(time.Time{})
	if err != nil {
		return errors.New("supervisor control write failed")
	}
	return nil
}

func (value *Client) exchangeLocked(ctx context.Context, request Frame, timeout time.Duration) (Frame, error) {
	if err := value.writeRequestLocked(ctx, request, timeout); err != nil {
		return Frame{}, err
	}
	return value.readResponseLocked(ctx, timeout)
}

func (value *Client) closeControlLocked() {
	value.closed = true
	if value.control != nil {
		_ = value.control.Close()
	}
	value.control = nil
	value.reader = nil
}

func (value *Client) wait(ctx context.Context) error {
	if value == nil || ctx == nil {
		return errors.New("supervisor wait input is invalid")
	}
	select {
	case <-value.done:
		value.mu.Lock()
		err := value.waitErr
		value.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (value *Client) exited(ctx context.Context) bool {
	if value == nil || ctx == nil {
		return false
	}
	select {
	case <-value.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (value *Client) terminate() {
	if value == nil || value.command == nil || value.command.Process == nil {
		return
	}
	// Closing the control descriptor is the primary cleanup route. Give Serve
	// enough time to observe EOF and stop its exact child group before using a
	// process signal as a bounded last resort.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	exited := value.exited(ctx)
	cancel()
	if exited {
		return
	}
	_ = value.command.Process.Signal(syscall.SIGTERM)
	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	exited = value.exited(ctx)
	cancel()
	if exited {
		return
	}
	_ = value.command.Process.Kill()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_ = value.exited(ctx)
	cancel()
}

func Start(ctx context.Context, config StartConfig) (*Client, Frame, error) {
	config.Init.SupervisorDigest = config.SupervisorDigest
	if ctx == nil || config.Init.validateInit() != nil {
		return nil, Frame{}, errors.New("supervisor start input is invalid")
	}
	path, err := supervisorExecutable(config.SupervisorPath, config.SupervisorDigest)
	if err != nil {
		return nil, Frame{}, err
	}
	parent, child, err := newControlSocketPair()
	if err != nil {
		return nil, Frame{}, errors.New("supervisor control socket creation failed")
	}
	command := exec.Command(path, "serve-fd", "3")
	command.Dir = filepath.Dir(path)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{child}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		_ = parent.Close()
		_ = child.Close()
		return nil, Frame{}, errors.New("supervisor process could not start")
	}
	_ = child.Close()
	client := &Client{
		control: parent, reader: bufio.NewReaderSize(parent, maxFrameBytes+1), command: command,
		init: config.Init, done: make(chan struct{}),
	}
	go func() {
		err := command.Wait()
		client.mu.Lock()
		client.waitErr = err
		client.mu.Unlock()
		close(client.done)
	}()
	client.mu.Lock()
	if err := client.writeRequestLocked(ctx, config.Init, config.ResponseTimeout); err != nil {
		client.closeControlLocked()
		client.mu.Unlock()
		client.terminate()
		return nil, Frame{}, errors.New("supervisor init could not be sent")
	}
	supervisor, err := client.readResponseLocked(ctx, config.ResponseTimeout)
	if err == nil {
		err = supervisor.validateSupervisorBound(command.Process.Pid, config.SupervisorDigest)
	}
	if err == nil {
		client.supervisor = supervisor
	}
	client.mu.Unlock()
	if err != nil {
		client.mu.Lock()
		client.closeControlLocked()
		client.mu.Unlock()
		client.terminate()
		return nil, Frame{}, err
	}
	return client, supervisor, nil
}

func (value *Client) SupervisorBound() Frame {
	if value == nil {
		return Frame{}
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.supervisor
}

func (value *Client) Prepare(ctx context.Context) (Frame, error) {
	if value == nil || ctx == nil {
		return Frame{}, errors.New("supervisor prepare input is invalid")
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.bound.PID != 0 || value.supervisor.SupervisorPID <= 0 {
		return Frame{}, errors.New("supervisor child preparation is not available")
	}
	bound, err := value.exchangeLocked(ctx, Frame{
		Version: ProtocolVersion, Type: "prepare", SupervisorPID: value.supervisor.SupervisorPID,
		SupervisorStartNS: value.supervisor.SupervisorStartNS, SupervisorDigest: value.supervisor.SupervisorDigest,
	}, 5*time.Second)
	if err == nil {
		err = bound.validateBound(value.init, value.supervisor)
	}
	if err != nil {
		return Frame{}, err
	}
	value.bound = bound
	return bound, nil
}

func (value *Client) Bound() Frame {
	if value == nil {
		return Frame{}
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.bound
}

func (value *Client) controlFrame(ctx context.Context, kind string, pid int, start uint64) (Frame, error) {
	if value == nil || ctx == nil || (kind != "release" && kind != "stop") {
		return Frame{}, errors.New("supervisor control input is invalid")
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.exchangeLocked(ctx, Frame{
		Version: ProtocolVersion, Type: kind, PID: pid, StartNS: start,
	}, 5*time.Second)
}

func (value *Client) Release(ctx context.Context) error {
	bound := value.Bound()
	frame, err := value.controlFrame(ctx, "release", bound.PID, bound.StartNS)
	if err != nil || frame.validateAcknowledgement("released", bound) != nil {
		return errors.New("supervisor release was not acknowledged")
	}
	return nil
}

func (value *Client) Stop(ctx context.Context) (bool, error) {
	bound := value.Bound()
	if bound.PID == 0 {
		return value.CloseProvider(ctx)
	}
	frame, err := value.controlFrame(ctx, "stop", bound.PID, bound.StartNS)
	if err != nil || frame.validateAcknowledgement("stopped", bound) != nil {
		return false, errors.New("supervisor stop was not acknowledged")
	}
	value.mu.Lock()
	value.closeControlLocked()
	value.mu.Unlock()
	if err := value.wait(ctx); err != nil {
		return false, errors.New("supervisor process did not exit")
	}
	return true, nil
}

func (value *Client) CloseProvider(ctx context.Context) (bool, error) {
	if value == nil || ctx == nil {
		return false, errors.New("supervisor close input is invalid")
	}
	value.mu.Lock()
	if !value.closed {
		value.closeControlLocked()
	}
	value.mu.Unlock()
	if err := value.wait(ctx); err != nil {
		return false, errors.New("supervisor did not exit after Provider EOF")
	}
	return true, nil
}
