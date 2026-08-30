package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

func secretResponseFixture() Response {
	return Response{
		DatabaseKeys:     map[string]string{"message.db": strings.Repeat("b", 64)},
		DatabaseProfiles: map[string]string{"message.db": "profile"},
		DatabaseCredential: &credentialmodel.DatabaseCredential{
			Mode: "per_database_enc_key",
		},
		ImageKeys: &ImageKeys{AES: "1234567890abcdef", XOR: 7},
	}
}

func TestSecretPolicyFailsClosedForUnsafeOutcomes(t *testing.T) {
	tests := []struct {
		name string
		diag diagnosticmodel.Diagnostics
	}{
		{"waiting", diagnosticmodel.Diagnostics{ResultCode: "action_required", WorkflowStatus: "waiting_action"}},
		{"blocked", diagnosticmodel.Diagnostics{ResultCode: "unsupported", WorkflowStatus: "blocked"}},
		{"catalog drift", diagnosticmodel.Diagnostics{ResultCode: "complete", WorkflowStatus: "terminal", BlockingReasons: []string{"catalog_drift"}}},
		{"mismatched partial", diagnosticmodel.Diagnostics{ResultCode: "partial", WorkflowStatus: "terminal", TargetBindingStatus: "mismatch"}},
		{"other account complete", diagnosticmodel.Diagnostics{ResultCode: "complete", WorkflowStatus: "terminal", SessionAccountStatus: "known_other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := secretResponseFixture()
			value.Diagnostics = test.diag
			value = EnforceSecretPolicy(value)
			if value.DatabaseKeys != nil || value.DatabaseProfiles != nil || value.DatabaseCredential != nil || value.ImageKeys != nil {
				t.Fatalf("unsafe outcome retained secrets: %+v", value)
			}
		})
	}
}

func TestSecretPolicyAllowsVerifiedTerminalAndCompleteRestorationOutcomes(t *testing.T) {
	tests := []struct {
		name string
		diag diagnosticmodel.Diagnostics
	}{
		{
			"complete", diagnosticmodel.Diagnostics{
				ResultCode: "complete", WorkflowStatus: "terminal", TargetBindingStatus: "hmac_verified",
			},
		},
		{
			"partial", diagnosticmodel.Diagnostics{
				ResultCode: "partial", WorkflowStatus: "terminal", TargetBindingStatus: "hmac_verified",
			},
		},
		{
			"deadline partial", diagnosticmodel.Diagnostics{
				ResultCode: "deadline_exhausted", WorkflowStatus: "terminal", TargetBindingStatus: "hmac_verified",
			},
		},
		{
			"SIP restoration", diagnosticmodel.Diagnostics{
				ResultCode: "action_required", WorkflowStatus: "waiting_action", NextAction: "reenable_sip",
				SecurityPostureStatus: "restoration_required", RequestedScopes: []string{"database"},
				DatabaseCoverageStatus: "complete", TargetBindingStatus: "hmac_verified",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := secretResponseFixture()
			value.Diagnostics = test.diag
			value = EnforceSecretPolicy(value)
			if value.DatabaseKeys == nil || value.DatabaseCredential == nil || value.ImageKeys == nil {
				t.Fatalf("safe outcome lost secrets: %+v", value)
			}
		})
	}

	incomplete := secretResponseFixture()
	incomplete.Diagnostics = diagnosticmodel.Diagnostics{
		ResultCode: "action_required", WorkflowStatus: "waiting_action", NextAction: "reenable_sip",
		SecurityPostureStatus: "restoration_required", RequestedScopes: []string{"database"},
		DatabaseCoverageStatus: "partial", TargetBindingStatus: "hmac_verified",
	}
	if value := EnforceSecretPolicy(incomplete); value.DatabaseKeys != nil || value.DatabaseCredential != nil || value.ImageKeys != nil {
		t.Fatalf("incomplete restoration retained secrets: %+v", value)
	}
}

func readyShadowResult(t *testing.T) shadowmodel.Result {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "testdata", "shadow-contract-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors shadowmodel.GoldenVectors
	if err := shadowmodel.DecodeStrict(payload, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors.ReadyResult
}

func TestSecretPolicyRequiresValidatedReadyShadowCleanup(t *testing.T) {
	ready := readyShadowResult(t)
	tests := []struct {
		name   string
		mutate func(*shadowmodel.Result)
		allow  bool
	}{
		{name: "ready", allow: true},
		{name: "failed despite outer complete", mutate: func(value *shadowmodel.Result) {
			value.Status = "failed"
			value.ErrorCode = shadowmodel.ErrorCapture
			value.CredentialReleased = false
			value.Receipt = nil
		}},
		{name: "cleanup pending despite outer complete", mutate: func(value *shadowmodel.Result) {
			value.Status = "cleanup_pending"
			value.ErrorCode = shadowmodel.ErrorCleanup
			value.CredentialReleased = false
			value.Receipt.Cleanup.SocketAbsent = false
		}},
		{name: "forged ready with residue", mutate: func(value *shadowmodel.Result) {
			value.Receipt.Cleanup.CloneAbsent = false
		}},
		{name: "forged ready without release", mutate: func(value *shadowmodel.Result) {
			value.CredentialReleased = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempt := ready

			// The receipt contains slices and a pointer, so isolate every mutation.
			receipt := *ready.Receipt
			receipt.Resources = append([]shadowmodel.ResourceBinding(nil), ready.Receipt.Resources...)
			attempt.Receipt = &receipt
			if test.mutate != nil {
				test.mutate(&attempt)
			}
			response := secretResponseFixture()
			response.Diagnostics = diagnosticmodel.Diagnostics{
				ResultCode: "complete", WorkflowStatus: "terminal", TargetBindingStatus: "hmac_verified",
				ShadowAttempt: &attempt,
			}
			permitted := EnforceSecretPolicy(response).DatabaseKeys != nil
			if permitted != test.allow {
				t.Fatalf("Shadow secret policy permit=%v want %v for %+v", permitted, test.allow, attempt)
			}
		})
	}
}
