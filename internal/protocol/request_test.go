package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func validRequest() AcquireRequest {
	return AcquireRequest{
		Protocol: Name, RequestID: "request-1", Action: "acquire",
		AccountDir: "account", DBDir: "database", Scopes: []string{"database"},
		DeadlineMS: 75_000, Workflow: WorkflowRequest{Operation: "finalize"},
	}
}

func TestDecodeRequestPreservesSchemaAndRejectsUnknownFields(t *testing.T) {
	payload, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeRequest(strings.NewReader(string(payload)))
	if err != nil || request.RequestID != "request-1" || request.Protocol != Name {
		t.Fatalf("valid request was not preserved: request=%+v err=%v", request, err)
	}
	if request.PeerIdentity != "" {
		t.Fatal("transport-only peer identity was populated from JSON")
	}
	unknown := strings.TrimSuffix(string(payload), "}") + `,"secret":"x"}`
	if _, err := DecodeRequest(strings.NewReader(unknown)); err == nil {
		t.Fatal("unknown request field was accepted")
	}
}

func TestWorkflowOperationsRemainFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AcquireRequest)
	}{
		{name: "prepare with session", mutate: func(value *AcquireRequest) {
			value.Workflow = WorkflowRequest{Operation: "prepare", SessionID: "old"}
		}},
		{name: "observe without catalog", mutate: func(value *AcquireRequest) {
			value.Workflow = WorkflowRequest{Operation: "observe", SessionID: "session"}
		}},
		{name: "finalize with receipt", mutate: func(value *AcquireRequest) {
			value.Workflow.ActionReceipt = &ActionReceipt{Action: "restart_wechat"}
		}},
		{name: "cancel without session", mutate: func(value *AcquireRequest) {
			value.Workflow = WorkflowRequest{Operation: "cancel"}
		}},
		{name: "posture with old state", mutate: func(value *AcquireRequest) {
			value.Workflow = WorkflowRequest{Operation: "revalidate_security_posture", ExpectedCatalogID: "old"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.mutate(&request)
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequestData(payload); err == nil {
				t.Fatal("invalid workflow state was accepted")
			}
		})
	}
}

func TestResponseSchemaKeepsDiagnosticsRequired(t *testing.T) {
	response := Response{Protocol: Name, RequestID: "request-1"}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"diagnostics":`) || strings.Contains(string(encoded), `"database_keys":`) {
		t.Fatalf("response omitempty/required fields changed: %s", encoded)
	}
}
