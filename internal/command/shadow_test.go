package command

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

const (
	commandShadowAccount = "/fixture/account"
	commandShadowDB      = "/fixture/account/db"
	commandShadowKey     = "abababababababababababababababababababababababababababababababab"
)

func commandShadowOptions(t *testing.T) string {
	t.Helper()
	key, err := hex.DecodeString(commandShadowKey)
	if err != nil {
		t.Fatal(err)
	}
	return catalogmodel.HMAC(key, shadowOptionsDomain, commandShadowAccount, commandShadowDB, "database")
}

type shadowRunnerStub struct {
	qualified shadowmodel.Output
	executed  shadowmodel.Output
}

func (value shadowRunnerStub) Qualify(context.Context, contract.Request) (shadowmodel.Output, error) {
	return value.qualified, nil
}

func (value shadowRunnerStub) Execute(context.Context, contract.Request) (shadowmodel.Output, error) {
	return value.executed, nil
}

func commandShadowVectors(t *testing.T) contract.GoldenVectors {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "testdata", "shadow-contract-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors contract.GoldenVectors
	if err := contract.DecodeStrict(payload, &vectors); err != nil {
		t.Fatalf("invalid Shadow vectors: %v", err)
	}
	options := commandShadowOptions(t)
	vectors.Challenge.OptionsDigest = options
	vectors.QualifyRequest.OptionsDigest = options
	vectors.ExecuteRequest.OptionsDigest = options
	vectors.Qualification.OptionsDigest = options
	vectors.CleanupReceipt.OptionsDigest = options
	vectors.ReadyResult.Receipt.OptionsDigest = options
	if err := vectors.Validate(); err != nil {
		t.Fatalf("invalid rebound Shadow vectors: %v", err)
	}
	return vectors
}

func commandShadowRequest(inner contract.Request) protocolmodel.AcquireRequest {
	return protocolmodel.AcquireRequest{
		Protocol: protocolmodel.Name, RequestID: inner.RequestID, Action: "acquire",
		CatalogKey: commandShadowKey, AccountDir: commandShadowAccount, DBDir: commandShadowDB,
		Scopes: []string{"database"}, DeadlineMS: 120_000,
		Workflow: protocolmodel.WorkflowRequest{Operation: "shadow", Shadow: &inner},
	}
}

func validShadowCredentialJSON(t *testing.T) []byte {
	t.Helper()
	// Keep this fixture at the wire boundary so the command test does not rely
	// on catalog discovery. ExecuteShadow still maps the canonical catalog DTO.
	return []byte(`{"catalog_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","catalog_entries":[{"database_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","relative_path":"message.db","canonical_file_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":4096,"mtime_ns":1,"first_page_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","classification":"encrypted_eligible","required_for_key_coverage":true,"profile_id":"wcdb-v4-sha512-256000-r80"}],"database_keys":{"message.db":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"database_profiles":{"message.db":"wcdb-v4-sha512-256000-r80"}}`)
}

func TestExecuteShadowKeepsProductionRouteDisabledAndSecretFree(t *testing.T) {
	vectors := commandShadowVectors(t)
	inner := vectors.ExecuteRequest
	inner.Operation = "execute"
	response, err := ExecuteShadow(context.Background(), commandShadowRequest(inner), nil)
	if err != nil {
		t.Fatal(err)
	}
	attempt := response.Diagnostics.ShadowAttempt
	if attempt == nil || attempt.Status != "failed" || attempt.ErrorCode != contract.ErrorProductionRouteDisabled ||
		response.Diagnostics.ShadowRouteStatus != "unavailable_in_build" || len(response.Diagnostics.RoutesAttempted) != 0 ||
		response.DatabaseKeys != nil || response.DatabaseCredential != nil || response.ImageKeys != nil {
		t.Fatalf("disabled Shadow route did not fail closed: %+v", response)
	}
}

func TestExecuteShadowRejectsReadyResultWithoutBoundCredentialEvidence(t *testing.T) {
	vectors := commandShadowVectors(t)
	credential := []byte(`{"database_keys":{"message.db":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}`)
	runner := shadowRunnerStub{executed: shadowmodel.Output{Result: vectors.ReadyResult, Credential: credential}}
	response, err := ExecuteShadow(context.Background(), commandShadowRequest(vectors.ExecuteRequest), runner)
	if err != nil {
		t.Fatal(err)
	}
	attempt := response.Diagnostics.ShadowAttempt
	if attempt == nil || attempt.Status != "failed" || attempt.ErrorCode != contract.ErrorCredentialInvalid ||
		response.DatabaseKeys != nil || response.DatabaseCredential != nil || response.ImageKeys != nil {
		t.Fatalf("invalid Shadow credential escaped fail-closed mapping: %+v", response)
	}
	for _, value := range credential {
		if value != 0 {
			t.Fatal("Provider command retained the rejected credential payload")
		}
	}
}

func TestExecuteShadowMapsSyntheticReadyWithoutClaimingRealRoute(t *testing.T) {
	vectors := commandShadowVectors(t)
	credential := validShadowCredentialJSON(t)
	runner := shadowRunnerStub{executed: shadowmodel.Output{Result: vectors.ReadyResult, Credential: credential}}
	response, err := ExecuteShadow(context.Background(), commandShadowRequest(vectors.ExecuteRequest), runner)
	if err != nil {
		t.Fatal(err)
	}
	if response.DatabaseKeys["message.db"] != strings.Repeat("d", 64) || len(response.CatalogEntries) != 1 ||
		response.Diagnostics.ResultCode != "complete" || response.Diagnostics.DatabaseTargetStatus != "present" ||
		response.Diagnostics.ShadowRouteStatus != "not_evaluated" || len(response.Diagnostics.RoutesAttempted) != 0 ||
		response.Diagnostics.RouteSelected != "" || response.Diagnostics.SecurityPostureStatus != "not_evaluated" {
		t.Fatalf("synthetic Shadow mapping fabricated real-machine evidence or lost credential: %+v", response)
	}
	for _, value := range credential {
		if value != 0 {
			t.Fatal("Provider command retained the released credential payload")
		}
	}
}

func TestExecuteShadowRejectsUnrequestedCredentialScope(t *testing.T) {
	vectors := commandShadowVectors(t)
	credential := append([]byte(nil), validShadowCredentialJSON(t)...)
	credential = bytes.TrimSuffix(credential, []byte("}"))
	credential = append(credential, []byte(`,"image_keys":{"aes":"1234567890abcdef","xor":7}}`)...)
	runner := shadowRunnerStub{executed: shadowmodel.Output{Result: vectors.ReadyResult, Credential: credential}}
	response, err := ExecuteShadow(context.Background(), commandShadowRequest(vectors.ExecuteRequest), runner)
	if err != nil {
		t.Fatal(err)
	}
	if response.Diagnostics.ShadowAttempt == nil ||
		response.Diagnostics.ShadowAttempt.ErrorCode != contract.ErrorCredentialInvalid ||
		response.DatabaseKeys != nil || response.DatabaseCredential != nil || response.ImageKeys != nil {
		t.Fatalf("unrequested media credential escaped database-only policy: %+v", response)
	}
}

func TestExecuteShadowRejectsNonCanonicalScopesBeforeRunner(t *testing.T) {
	vectors := commandShadowVectors(t)
	for name, scopes := range map[string][]string{
		"empty": {}, "duplicate": {"database", "database"},
		"unknown": {"database", "other"}, "order": {"media", "database"},
	} {
		t.Run(name, func(t *testing.T) {
			request := commandShadowRequest(vectors.ExecuteRequest)
			request.Scopes = scopes
			if _, err := ExecuteShadow(context.Background(), request, shadowRunnerStub{}); err == nil {
				t.Fatal("non-canonical Shadow scopes reached the runner")
			}
		})
	}
}

func TestExecuteShadowRejectsOuterOptionsBindingDrift(t *testing.T) {
	vectors := commandShadowVectors(t)
	request := commandShadowRequest(vectors.ExecuteRequest)
	request.DBDir = "/fixture/other-account/db"
	if _, err := ExecuteShadow(context.Background(), request, shadowRunnerStub{}); err == nil {
		t.Fatal("outer Shadow options drift reached the runner")
	}
}

func TestExecuteShadowRevalidatesOuterAndInnerRequestBoundary(t *testing.T) {
	vectors := commandShadowVectors(t)
	tests := map[string]func(*protocolmodel.AcquireRequest){
		"outer request": func(request *protocolmodel.AcquireRequest) {
			request.RequestID = "0123456789abcdef0123456789abcdef"
		},
		"outer workflow residue": func(request *protocolmodel.AcquireRequest) {
			request.Workflow.SessionID = "forbidden-session"
		},
		"inner operation": func(request *protocolmodel.AcquireRequest) {
			request.Workflow.Shadow.Operation = "unknown"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := commandShadowRequest(vectors.ExecuteRequest)
			inner := *request.Workflow.Shadow
			request.Workflow.Shadow = &inner
			mutate(&request)
			if _, err := ExecuteShadow(context.Background(), request, shadowRunnerStub{}); err == nil {
				t.Fatal("invalid direct Shadow command boundary reached the runner")
			}
		})
	}
}

func TestExecuteShadowRejectsRunnerCrossRequestBindingDrift(t *testing.T) {
	vectors := commandShadowVectors(t)
	tests := map[string]func(*contract.Result){
		"request": func(result *contract.Result) {
			result.RequestID = "0123456789abcdef0123456789abcdef"
		},
		"receipt": func(result *contract.Result) {
			receipt := *result.Receipt
			receipt.OptionsDigest = strings.Repeat("9", 64)
			result.Receipt = &receipt
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := vectors.ReadyResult
			mutate(&result)
			runner := shadowRunnerStub{executed: shadowmodel.Output{Result: result, Credential: validShadowCredentialJSON(t)}}
			if _, err := ExecuteShadow(context.Background(), commandShadowRequest(vectors.ExecuteRequest), runner); err == nil {
				t.Fatal("cross-request Shadow runner result was accepted")
			}
		})
	}
}
