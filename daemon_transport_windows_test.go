//go:build windows

package provider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
)

func namedPipeDaemonExchange(t *testing.T, endpoint acquisitionDaemonEndpoint, token, command string) acquisitionDaemonResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := daemonmodel.DialNamedPipeContext(ctx, endpoint.Address)
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
	go func() { finished <- serveTestAcquisitionDaemonForClient(endpointPath, clientPath) }()
	endpoint := waitForAcquisitionEndpoint(t, endpointPath, finished)
	if endpoint.Transport != daemonmodel.WindowsTransport || endpoint.ClientPath != clientPath {
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
