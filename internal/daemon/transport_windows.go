//go:build windows

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"golang.org/x/sys/windows"
)

const WindowsTransport = "windows_named_pipe"

type namedPipeAddress string

func (value namedPipeAddress) Network() string { return WindowsTransport }
func (value namedPipeAddress) String() string  { return string(value) }

type namedPipeTimeoutError struct{}

func (namedPipeTimeoutError) Error() string   { return "named pipe accept timed out" }
func (namedPipeTimeoutError) Timeout() bool   { return true }
func (namedPipeTimeoutError) Temporary() bool { return true }

type namedPipeConnection struct {
	file    *os.File
	path    string
	peerPID uint32
}

func (value *namedPipeConnection) Read(data []byte) (int, error)  { return value.file.Read(data) }
func (value *namedPipeConnection) Write(data []byte) (int, error) { return value.file.Write(data) }
func (value *namedPipeConnection) Close() error                   { return value.file.Close() }
func (value *namedPipeConnection) LocalAddr() net.Addr            { return namedPipeAddress(value.path) }
func (value *namedPipeConnection) RemoteAddr() net.Addr           { return namedPipeAddress(value.path) }
func (value *namedPipeConnection) SetDeadline(deadline time.Time) error {
	return value.file.SetDeadline(deadline)
}
func (value *namedPipeConnection) SetReadDeadline(deadline time.Time) error {
	return value.file.SetReadDeadline(deadline)
}
func (value *namedPipeConnection) SetWriteDeadline(deadline time.Time) error {
	return value.file.SetWriteDeadline(deadline)
}
func (value *namedPipeConnection) acquisitionPeerPID() uint32 { return value.peerPID }

type namedPipeListener struct {
	mu          sync.Mutex
	path        string
	security    *windows.SECURITY_DESCRIPTOR
	firstHandle windows.Handle
	pending     windows.Handle
	deadline    time.Time
	closed      bool
}

func currentUserPipeSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, errors.New("current Windows user SID is unavailable")
	}
	return windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")")
}

func createNamedPipeHandle(path string, security *windows.SECURITY_DESCRIPTOR, first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security,
	}
	return windows.CreateNamedPipe(name, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, protocolmodel.MaxResponseBytes, protocolmodel.MaxRequestBytes, 5000, attributes)
}

func newNamedPipeListener(path string) (*namedPipeListener, error) {
	security, err := currentUserPipeSecurity()
	if err != nil {
		return nil, err
	}
	first, err := createNamedPipeHandle(path, security, true)
	if err != nil {
		return nil, err
	}
	return &namedPipeListener{path: path, security: security, firstHandle: first, pending: windows.InvalidHandle}, nil
}

func (value *namedPipeListener) nextHandle() (windows.Handle, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.closed {
		return windows.InvalidHandle, net.ErrClosed
	}
	if value.firstHandle != windows.InvalidHandle {
		handle := value.firstHandle
		value.firstHandle = windows.InvalidHandle
		value.pending = handle
		return handle, nil
	}
	handle, err := createNamedPipeHandle(value.path, value.security, false)
	if err == nil {
		value.pending = handle
	}
	return handle, err
}

func (value *namedPipeListener) clearPending(handle windows.Handle) {
	value.mu.Lock()
	if value.pending == handle {
		value.pending = windows.InvalidHandle
	}
	value.mu.Unlock()
}

func (value *namedPipeListener) acceptDeadline() time.Time {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.deadline
}

func (value *namedPipeListener) isClosed() bool {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.closed
}

func (value *namedPipeListener) Accept() (net.Conn, error) {
	handle, err := value.nextHandle()
	if err != nil {
		return nil, err
	}
	connected := false
	defer func() {
		value.clearPending(handle)
		if !connected {
			_ = windows.CloseHandle(handle)
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(handle, &overlapped)
	switch {
	case err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED):
	case errors.Is(err, windows.ERROR_IO_PENDING):
		waitMilliseconds := uint32(windows.INFINITE)
		if deadline := value.acceptDeadline(); !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				_ = windows.CancelIoEx(handle, &overlapped)
				return nil, namedPipeTimeoutError{}
			}
			waitMilliseconds = uint32((remaining + time.Millisecond - 1) / time.Millisecond)
		}
		status, waitErr := windows.WaitForSingleObject(event, waitMilliseconds)
		if waitErr != nil {
			_ = windows.CancelIoEx(handle, &overlapped)
			if value.isClosed() {
				return nil, net.ErrClosed
			}
			return nil, waitErr
		}
		if status == uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIoEx(handle, &overlapped)
			return nil, namedPipeTimeoutError{}
		}
		if status != uint32(windows.WAIT_OBJECT_0) {
			return nil, fmt.Errorf("unexpected named pipe wait status %d", status)
		}
		var transferred uint32
		if err := windows.GetOverlappedResult(handle, &overlapped, &transferred, false); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			if value.isClosed() || errors.Is(err, windows.ERROR_OPERATION_ABORTED) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
				return nil, net.ErrClosed
			}
			return nil, err
		}
	default:
		if value.isClosed() || errors.Is(err, windows.ERROR_OPERATION_ABORTED) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	var peerPID uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &peerPID); err != nil || peerPID == 0 {
		return nil, errors.New("named pipe client PID is unavailable")
	}
	file := os.NewFile(uintptr(handle), value.path)
	if file == nil {
		return nil, errors.New("named pipe handle could not be attached to the Go poller")
	}
	connected = true
	return &namedPipeConnection{file: file, path: value.path, peerPID: peerPID}, nil
}

func (value *namedPipeListener) Close() error {
	value.mu.Lock()
	if value.closed {
		value.mu.Unlock()
		return nil
	}
	value.closed = true
	first := value.firstHandle
	pending := value.pending
	value.firstHandle = windows.InvalidHandle
	value.pending = windows.InvalidHandle
	value.mu.Unlock()
	if pending != windows.InvalidHandle {
		_ = windows.CancelIoEx(pending, nil)
		_ = windows.CloseHandle(pending)
	}
	if first != windows.InvalidHandle && first != pending {
		_ = windows.CloseHandle(first)
	}
	return nil
}

func (value *namedPipeListener) Addr() net.Addr { return namedPipeAddress(value.path) }
func (value *namedPipeListener) SetDeadline(deadline time.Time) error {
	value.mu.Lock()
	value.deadline = deadline
	value.mu.Unlock()
	return nil
}

func listen(_ Config, _ string, token string, developmentTCP bool) (net.Listener, string, string, func(), error) {
	if developmentTCP {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, "", "", func() {}, err
		}
		return listener, "tcp4-development", listener.Addr().String(), func() {}, nil
	}
	path := `\\.\pipe\LOCAL\v-local-key-provider-` + token[:24]
	listener, err := newNamedPipeListener(path)
	if err != nil {
		return nil, "", "", func() {}, err
	}
	return listener, WindowsTransport, path, func() {}, nil
}

// ProcessExecutablePath returns the image path of a concrete Windows process.
func ProcessExecutablePath(pid uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil || size == 0 {
		return "", errors.New("daemon client process image is unavailable")
	}
	return filepath.Clean(windows.UTF16ToString(buffer[:size])), nil
}

func processUserMatchesCurrent(pid uint32) (bool, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(process) //nolint:errcheck -- read-only peer identity cleanup
	var peerToken windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &peerToken); err != nil {
		return false, err
	}
	defer peerToken.Close()
	peerUser, err := peerToken.GetTokenUser()
	if err != nil || peerUser == nil || peerUser.User.Sid == nil {
		return false, errors.New("named pipe peer user SID is unavailable")
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return false, errors.New("daemon user SID is unavailable")
	}
	return peerUser.User.Sid.Equals(currentUser.User.Sid), nil
}

func verifyPeer(config Config, connection net.Conn, transport, clientPath string) (string, error) {
	trustedPath, err := config.ValidateClientPath(clientPath)
	if err != nil {
		return "", err
	}
	if transport == "tcp4-development" && !config.ReleaseBuild {
		return "development:" + strings.ToLower(trustedPath), nil
	}
	if transport != WindowsTransport {
		return "", errors.New("release daemon transport is not a Windows named pipe")
	}
	peer, ok := connection.(interface{ acquisitionPeerPID() uint32 })
	if !ok || peer.acquisitionPeerPID() == 0 {
		return "", errors.New("named pipe peer PID is unavailable")
	}
	peerPID := peer.acquisitionPeerPID()
	sameUser, err := processUserMatchesCurrent(peerPID)
	if err != nil || !sameUser {
		return "", errors.New("named pipe peer user does not match the daemon user")
	}
	actualPath, err := ProcessExecutablePath(peerPID)
	if err != nil || !config.SamePath(actualPath, trustedPath) {
		return "", errors.New("named pipe peer image does not match the trusted CLI")
	}
	if config.ReleaseBuild {
		if _, err := config.ValidateClientPath(actualPath); err != nil {
			return "", err
		}
	}
	return "windows:" + strings.ToLower(filepath.Clean(trustedPath)), nil
}

// DialNamedPipeContext connects to a local daemon named pipe with cancellation.
func DialNamedPipeContext(ctx context.Context, path string) (net.Conn, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	for {
		handle, openErr := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
		if openErr == nil {
			file := os.NewFile(uintptr(handle), path)
			if file == nil {
				_ = windows.CloseHandle(handle)
				return nil, errors.New("named pipe client handle could not be attached to the Go poller")
			}
			return &namedPipeConnection{file: file, path: path}, nil
		}
		if !errors.Is(openErr, windows.ERROR_PIPE_BUSY) && !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
			return nil, openErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
