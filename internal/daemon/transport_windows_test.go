//go:build windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
