//go:build darwin

package daemon

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const DarwinTransport = "darwin_unix"

func listen(_ Config, endpointPath, token string, developmentTCP bool) (net.Listener, string, string, func(), error) {
	if developmentTCP {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, "", "", func() {}, err
		}
		return listener, "tcp4-development", listener.Addr().String(), func() {}, nil
	}
	socketPath := filepath.Join(filepath.Dir(endpointPath), ".v-local-key-provider-"+token[:24]+".sock")
	if len(socketPath) >= 100 {
		return nil, "", "", func() {}, errors.New("daemon Unix socket path exceeds the platform limit")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, "", "", func() {}, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, "", "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(socketPath) }
	return listener, DarwinTransport, socketPath, cleanup, nil
}

func darwinPeerIdentity(connection net.Conn) (int, uint32, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("daemon peer is not a Unix-domain connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	pid := 0
	var socketErr error
	var credentials *unix.Xucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		pid, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		credentials, credentialErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil || pid <= 0 {
		return 0, 0, errors.New("daemon Unix peer PID is unavailable")
	}
	if credentialErr != nil || credentials == nil {
		return 0, 0, errors.New("daemon Unix peer credentials are unavailable")
	}
	return pid, credentials.Uid, nil
}

// ProcessExecutablePath returns the executable path reported by the Darwin
// kernel for a concrete process instance.
func ProcessExecutablePath(pid uint32) (string, error) {
	const kernProcArgs2 = 49
	mib := []int32{unix.CTL_KERN, kernProcArgs2, int32(pid)}
	var size uintptr
	_, _, errno := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&size)), 0, 0)
	if errno != 0 || size <= 4 || size > 1024*1024 {
		return "", errors.New("daemon peer process arguments are unavailable")
	}
	payload := make([]byte, size)
	_, _, errno = syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if errno != 0 || size <= 4 {
		return "", errors.New("daemon peer process arguments could not be read")
	}
	payload = payload[4:size]
	end := bytes.IndexByte(payload, 0)
	if end <= 0 {
		return "", errors.New("daemon peer executable path is missing")
	}
	return filepath.Clean(string(payload[:end])), nil
}

func verifyPeer(config Config, connection net.Conn, transport, clientPath string) (string, error) {
	trustedPath, err := config.ValidateClientPath(clientPath)
	if err != nil {
		return "", err
	}
	if transport == "tcp4-development" && !config.ReleaseBuild {
		return "development:" + trustedPath, nil
	}
	if transport != DarwinTransport {
		return "", errors.New("release daemon transport is not a Unix socket")
	}
	pid, uid, err := darwinPeerIdentity(connection)
	if err != nil {
		return "", err
	}
	if uid != uint32(os.Geteuid()) {
		return "", errors.New("Unix peer user does not match the daemon user")
	}
	actualPath, err := ProcessExecutablePath(uint32(pid))
	if err != nil || !config.SamePath(actualPath, trustedPath) {
		return "", errors.New("Unix peer image does not match the trusted CLI")
	}
	if config.ReleaseBuild {
		if _, err := config.ValidateClientPath(actualPath); err != nil {
			return "", err
		}
	}
	return "darwin:" + trustedPath, nil
}
