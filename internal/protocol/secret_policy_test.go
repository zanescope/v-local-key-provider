package protocol

import (
	"strings"
	"testing"

	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
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
