package provider

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func daemonRawExchange(t *testing.T, endpoint acquisitionDaemonEndpoint, request acquisitionDaemonRequest) acquisitionDaemonResponse {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", endpoint.Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	var result acquisitionDaemonResponse
	if err := json.NewDecoder(connection).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func waitForAcquisitionEndpoint(t *testing.T, path string, finished <-chan error) acquisitionDaemonEndpoint {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-finished:
			t.Fatalf("acquisition daemon stopped before publishing its endpoint: %v", err)
		default:
		}
		payload, err := os.ReadFile(path)
		if err == nil {
			var endpoint acquisitionDaemonEndpoint
			if json.Unmarshal(payload, &endpoint) == nil && endpoint.Address != "" && endpoint.Token != "" {
				return endpoint
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("acquisition daemon endpoint was not published")
	return acquisitionDaemonEndpoint{}
}

func daemonTestExchange(t *testing.T, endpoint acquisitionDaemonEndpoint, command string, request *acquireRequest) acquisitionDaemonResponse {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", endpoint.Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(acquisitionDaemonRequest{
		SchemaVersion: acquisitionDaemonSchemaVersion, Token: endpoint.Token, Command: command, Acquire: request,
	}); err != nil {
		t.Fatal(err)
	}
	var result acquisitionDaemonResponse
	if err := json.NewDecoder(connection).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Error != nil {
		t.Fatalf("daemon returned error: %+v", result.Error)
	}
	return result
}

func TestAcquisitionDaemonHelperContextUsesOriginalEntrypoint(t *testing.T) {
	if helperMode, helperStatus := acquisitionDaemonHelperContext(""); helperMode || helperStatus != "" {
		t.Fatalf("ordinary daemon was marked as helper: mode=%v status=%q", helperMode, helperStatus)
	}
	if helperMode, helperStatus := acquisitionDaemonHelperContext("/installed/v-local-key-provider"); !helperMode || helperStatus != "used" {
		t.Fatalf("helper daemon context was lost: mode=%v status=%q", helperMode, helperStatus)
	}
}

func TestAcquisitionDaemonHelperRequiresExactProviderVersion(t *testing.T) {
	if err := validateAcquisitionDaemonProviderVersion(version); err != nil {
		t.Fatalf("current Provider/helper version rejected: %v", err)
	}
	for _, value := range []string{"", " ", version + "-stale", "0.0.0"} {
		if value == version {
			continue
		}
		if err := validateAcquisitionDaemonProviderVersion(value); err == nil {
			t.Fatalf("mismatched helper launcher version accepted: %q", value)
		}
	}
}

func TestAcquisitionDaemonServesSessionAndCleansEndpoint(t *testing.T) {
	endpointPath := filepath.Join(secureDaemonTestDirectory(t), "endpoint.json")
	finished := make(chan error, 1)
	go func() { finished <- serveAcquisitionDaemon(endpointPath) }()
	endpoint := waitForAcquisitionEndpoint(t, endpointPath, finished)
	if ping := daemonTestExchange(t, endpoint, "ping", nil); ping.Status != "ready" {
		t.Fatalf("daemon ping status = %q", ping.Status)
	}
	prepare := sessionRequestFixture(t, "prepare")
	prepared := daemonTestExchange(t, endpoint, "acquire", &prepare)
	if prepared.Result == nil || prepared.Result.Diagnostics.SessionID == "" || prepared.Result.CatalogID == "" {
		t.Fatalf("prepare response is incomplete: %+v", prepared)
	}
	cancel := prepare
	cancel.RequestID = "request-cancel"
	cancel.Workflow = workflowRequest{Operation: "cancel", SessionID: prepared.Result.Diagnostics.SessionID}
	cancelled := daemonTestExchange(t, endpoint, "acquire", &cancel)
	if cancelled.Result == nil || cancelled.Result.Diagnostics.ResultCode != "cancelled" {
		t.Fatalf("cancel response is invalid: %+v", cancelled)
	}
	if stopping := daemonTestExchange(t, endpoint, "shutdown", nil); stopping.Status != "stopping" {
		t.Fatalf("shutdown status = %q", stopping.Status)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("acquisition daemon did not stop")
	}
	if _, err := os.Stat(endpointPath); !os.IsNotExist(err) {
		t.Fatalf("daemon endpoint remained after shutdown: %v", err)
	}
}

func TestAcquisitionDaemonDoesNotLetSlowUnauthenticatedClientBlockPing(t *testing.T) {
	endpointPath := filepath.Join(secureDaemonTestDirectory(t), "endpoint.json")
	finished := make(chan error, 1)
	go func() { finished <- serveAcquisitionDaemon(endpointPath) }()
	endpoint := waitForAcquisitionEndpoint(t, endpointPath, finished)
	slow, err := net.DialTimeout("tcp4", endpoint.Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	pingDone := make(chan acquisitionDaemonResponse, 1)
	go func() { pingDone <- daemonTestExchange(t, endpoint, "ping", nil) }()
	select {
	case ping := <-pingDone:
		if ping.Status != "ready" {
			t.Fatalf("daemon ping status = %q", ping.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("slow unauthenticated connection blocked an authenticated ping")
	}
	_ = slow.Close()
	if stopping := daemonTestExchange(t, endpoint, "shutdown", nil); stopping.Status != "stopping" {
		t.Fatalf("shutdown status = %q", stopping.Status)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("acquisition daemon did not stop")
	}
}

func TestPhase2DaemonRejectsGuessedTokenWithoutAffectingAuthenticatedSession(t *testing.T) {
	endpointPath := filepath.Join(secureDaemonTestDirectory(t), "endpoint.json")
	finished := make(chan error, 1)
	go func() { finished <- serveAcquisitionDaemon(endpointPath) }()
	endpoint := waitForAcquisitionEndpoint(t, endpointPath, finished)

	guessed := daemonRawExchange(t, endpoint, acquisitionDaemonRequest{
		SchemaVersion: acquisitionDaemonSchemaVersion,
		Token:         strings.Repeat("0", 64),
		Command:       "shutdown",
	})
	if guessed.Error == nil || guessed.Error.Code != "unauthorized" {
		t.Fatalf("guessed daemon token was not rejected: %+v", guessed)
	}
	if ping := daemonTestExchange(t, endpoint, "ping", nil); ping.Status != "ready" {
		t.Fatalf("unauthorized request affected the live daemon: %+v", ping)
	}
	if stopping := daemonTestExchange(t, endpoint, "shutdown", nil); stopping.Status != "stopping" {
		t.Fatalf("shutdown status = %q", stopping.Status)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("acquisition daemon did not stop")
	}
}
