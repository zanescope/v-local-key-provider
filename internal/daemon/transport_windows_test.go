//go:build windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type peerPIDTestConnection struct {
	net.Conn
	pid uint32
}

func (value peerPIDTestConnection) acquisitionPeerPID() uint32 { return value.pid }

func TestNamedPipeRejectsSameUserImpostorImage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	impostor := filepath.Join(t.TempDir(), "impostor.exe")
	if err := os.WriteFile(impostor, []byte("not the running CLI"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ValidateClientPath: func(path string) (string, error) { return filepath.Abs(path) },
		SamePath: func(left, right string) bool {
			return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
		},
	}
	_, err := verifyPeer(config, peerPIDTestConnection{Conn: server, pid: uint32(os.Getpid())}, WindowsTransport, impostor)
	if err == nil {
		t.Fatal("same-user process with a different executable image passed peer verification")
	}
}

func TestNamedPipePeerUserMatchesCurrentProcess(t *testing.T) {
	matched, err := processUserMatchesCurrent(uint32(os.Getpid()))
	if err != nil || !matched {
		t.Fatalf("current process user did not match the daemon user: matched=%v err=%v", matched, err)
	}
}

func TestNamedPipePendingHandleHasSingleCleanupOwner(t *testing.T) {
	t.Run("Accept 先取得清理权", func(t *testing.T) {
		event, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		listener := &namedPipeListener{
			firstHandle: windows.InvalidHandle,
			pending:     event,
		}
		if !listener.takePending(event) {
			t.Fatal("Accept 未取得 pending handle 的清理权")
		}
		if listener.takePending(event) {
			t.Fatal("同一个 pending handle 被重复认领")
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if err := windows.CloseHandle(event); err != nil {
			t.Fatal("listener.Close 关闭了已由 Accept 认领的 handle")
		}
	})

	t.Run("Close 先取得清理权", func(t *testing.T) {
		event, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		listener := &namedPipeListener{
			firstHandle: windows.InvalidHandle,
			pending:     event,
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if listener.takePending(event) {
			t.Fatal("Close 已清理的 pending handle 被 Accept 再次认领")
		}
	})
}
