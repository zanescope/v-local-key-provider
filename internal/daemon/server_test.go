package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"testing"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func testConfig(backend Backend) Config {
	return Config{
		Version:      "test-version",
		ReleaseBuild: false,
		NewBackend:   func(BackendContext) Backend { return backend },
		RuntimeContext: func(advertised string) (bool, string, error) {
			context := ContextForProvider(advertised)
			return context.HelperMode, context.HelperStatus, nil
		},
		ValidateClientPath: filepath.Abs,
		IsLinkOrReparse:    func(string, fs.FileMode) (bool, error) { return false, nil },
		SamePath:           func(left, right string) bool { return filepath.Clean(left) == filepath.Clean(right) },
		MarkSensitive:      func([]byte) {},
		ZeroSensitive: func(value []byte) {
			for index := range value {
				value[index] = 0
			}
		},
	}
}

func TestNewRejectsIncompleteSecurityBoundary(t *testing.T) {
	if _, err := New(Config{Version: "test"}); err == nil {
		t.Fatal("incomplete daemon configuration was accepted")
	}
}

func TestHelperContextAndVersionRemainExact(t *testing.T) {
	ordinary := ContextForProvider("")
	if ordinary.HelperMode || ordinary.HelperStatus != "" {
		t.Fatalf("ordinary daemon context changed: %+v", ordinary)
	}
	helper := ContextForProvider("/installed/provider")
	if !helper.HelperMode || helper.HelperStatus != "used" {
		t.Fatalf("helper daemon context changed: %+v", helper)
	}
	if err := ValidateProviderVersion("1.2.3", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	for _, advertised := range []string{"", " ", "1.2.2"} {
		if err := ValidateProviderVersion(advertised, "1.2.3"); err == nil {
			t.Fatalf("mismatched helper version accepted: %q", advertised)
		}
	}
}

func TestRunStdioUsesInjectedBackendAndWireDefaults(t *testing.T) {
	var handled protocolmodel.AcquireRequest
	closed := false
	backend := Backend{
		HandleContext: func(_ context.Context, request protocolmodel.AcquireRequest) (protocolmodel.Response, error) {
			handled = request
			return protocolmodel.Response{}, nil
		},
		CancelSession: func(string) {},
		ActiveCount:   func() int { return 0 },
		Close:         func() { closed = true },
	}
	service, err := New(testConfig(backend))
	if err != nil {
		t.Fatal(err)
	}
	request := protocolmodel.AcquireRequest{
		Protocol: protocolmodel.Name, RequestID: "request-daemon", Action: "acquire",
		AccountDir: "account", DBDir: "database", Scopes: []string{"database"}, DeadlineMS: 75_000,
		Workflow: protocolmodel.WorkflowRequest{Operation: "finalize"},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	var output bytes.Buffer
	if err := service.RunStdio(bytes.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	if !closed || handled.RequestID != request.RequestID {
		t.Fatalf("injected backend lifecycle was not used: closed=%v request=%+v", closed, handled)
	}
	var response protocolmodel.Response
	if err := json.NewDecoder(&output).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Protocol != protocolmodel.Name || response.RequestID != request.RequestID {
		t.Fatalf("stdio wire defaults changed: %+v", response)
	}
}
