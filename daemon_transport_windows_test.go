//go:build windows

package provider

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func namedPipeDaemonExchange(t *testing.T, endpoint acquisitionDaemonEndpoint, token, command string) acquisitionDaemonResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := dialNamedPipeContext(ctx, endpoint.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(acquisitionDaemonRequest{
		SchemaVersion: acquisitionDaemonSchemaVersion, Token: token, Command: command,
	}); err != nil {
		t.Fatal(err)
	}
	var result acquisitionDaemonResponse
	if err := json.NewDecoder(connection).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWindowsNamedPipeBindsPeerImageBeforeTokenAuthentication(t *testing.T) {
	endpointPath := filepath.Join(secureDaemonTestDirectory(t), "endpoint.json")
	clientPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	clientPath, err = filepath.EvalSymlinks(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- serveAcquisitionDaemonForClient(endpointPath, clientPath) }()
	endpoint := waitForAcquisitionEndpoint(t, endpointPath, finished)
	if endpoint.Transport != windowsDaemonTransport || endpoint.ClientPath != clientPath {
		t.Fatalf("daemon did not publish a client-bound named pipe endpoint: %+v", endpoint)
	}
	guessed := namedPipeDaemonExchange(t, endpoint, strings.Repeat("0", 64), "shutdown")
	if guessed.Error == nil || guessed.Error.Code != "unauthorized" {
		t.Fatalf("stolen/guessed token was accepted over the trusted pipe: %+v", guessed)
	}
	if ping := namedPipeDaemonExchange(t, endpoint, endpoint.Token, "ping"); ping.Status != "ready" {
		t.Fatalf("trusted CLI peer could not ping the named pipe daemon: %+v", ping)
	}
	if stopping := namedPipeDaemonExchange(t, endpoint, endpoint.Token, "shutdown"); stopping.Status != "stopping" {
		t.Fatalf("trusted CLI peer could not stop the named pipe daemon: %+v", stopping)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("named pipe daemon did not stop")
	}
}

type peerPIDTestConnection struct {
	net.Conn
	pid uint32
}

func (value peerPIDTestConnection) acquisitionPeerPID() uint32 { return value.pid }

func TestWindowsNamedPipeRejectsSameUserImpostorImage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	impostor := filepath.Join(t.TempDir(), "impostor.exe")
	if err := os.WriteFile(impostor, []byte("not the running CLI"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := verifyAcquisitionDaemonPeer(peerPIDTestConnection{Conn: server, pid: uint32(os.Getpid())}, windowsDaemonTransport, impostor)
	if err == nil {
		t.Fatal("same-user process with a different executable image passed peer verification")
	}
}

func TestWindowsNamedPipePeerUserMatchesCurrentProcess(t *testing.T) {
	matched, err := windowsProcessUserMatchesCurrent(uint32(os.Getpid()))
	if err != nil || !matched {
		t.Fatalf("current process user did not match the daemon user: matched=%v err=%v", matched, err)
	}
}
