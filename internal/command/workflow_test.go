package command

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

func commandRequestFixture(t *testing.T, operation string) protocolmodel.AcquireRequest {
	t.Helper()
	account := filepath.Join(t.TempDir(), "account")
	database := filepath.Join(account, "db")
	if err := os.MkdirAll(database, 0o700); err != nil {
		t.Fatal(err)
	}
	return protocolmodel.AcquireRequest{
		Protocol: protocolmodel.Name, RequestID: "request-1", Action: "acquire",
		AccountDir: account, DBDir: database, Scopes: []string{"media"}, DeadlineMS: 30_000,
		Workflow: protocolmodel.WorkflowRequest{Operation: operation},
	}
}

func commandRuntimeFixture(t *testing.T) Runtime {
	t.Helper()
	return Runtime{
		OptionPolicy: acquisitionmodel.OptionPolicy{
			IsLinkOrReparse: func(_ string, mode fs.FileMode) (bool, error) {
				return mode&fs.ModeSymlink != 0, nil
			},
		},
		Acquisition: acquisitionmodel.WorkflowRuntime{
			DiscoverMedia: func(string, workbudget.Budget) acquisitionmodel.MediaEvidence {
				return acquisitionmodel.MediaEvidence{}
			},
			Driver: acquisitionmodel.PlatformDriverFunc(func(
				_ acquisitionmodel.Targets,
				_ acquisitionmodel.MediaEvidence,
				request acquisitionmodel.PlatformRequest,
			) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
				if !request.Media || request.Database || !request.HelperMode || request.HelperStatus != "elevated" {
					t.Fatalf("helper state was not transferred to platform acquisition: %+v", request)
				}
				return protocolmodel.Response{
					ImageKeys: &protocolmodel.ImageKeys{AES: "1234567890abcdef", XOR: 7},
				}, diagnosticmodel.New("fixture", []string{"media"}, "not_applicable"), nil
			}),
		},
	}
}

func TestExecuteOneShotOwnsGenericCommandWorkflow(t *testing.T) {
	runtime := commandRuntimeFixture(t)
	result, err := ExecuteOneShot(commandRequestFixture(t, "finalize"), true, "elevated", runtime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Protocol != protocolmodel.Name || result.RequestID != "request-1" || result.ImageKeys == nil ||
		result.Diagnostics.ResultCode != "complete" || result.Diagnostics.MediaCoverageStatus != "complete" {
		t.Fatalf("one-shot command result changed: %+v", result)
	}
}

func TestExecuteOneShotRejectsSessionOperations(t *testing.T) {
	if _, err := ExecuteOneShot(commandRequestFixture(t, "prepare"), false, "", commandRuntimeFixture(t)); err == nil {
		t.Fatal("one-shot command accepted a session operation")
	}
}

func TestSecurityPostureRevalidationIsPathIndependent(t *testing.T) {
	request := protocolmodel.AcquireRequest{
		Protocol: protocolmodel.Name, RequestID: "posture-1",
		AccountDir: filepath.Join(t.TempDir(), "removed-account"), DBDir: "removed-db",
		Scopes: []string{"database"}, DeadlineMS: 1_000,
		Workflow: protocolmodel.WorkflowRequest{Operation: "revalidate_security_posture"},
	}
	runtime := Runtime{
		OptionPolicy: acquisitionmodel.OptionPolicy{
			IsLinkOrReparse: func(string, fs.FileMode) (bool, error) {
				t.Fatal("posture revalidation touched an acquisition path")
				return false, nil
			},
		},
		PlatformName:    func() string { return "darwin" },
		SecurityPosture: func() string { return "sip_enabled_verified" },
		DiagnosticDefaults: func() diagnosticmodel.PlatformDefaults {
			return diagnosticmodel.PlatformDefaults{
				SecurityPostureStatus: "sip_enabled_verified", DarwinShadowRouteStatus: "unavailable_in_build",
			}
		},
	}
	result, err := ExecuteSecurityPostureRevalidation(request, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.ResultCode != "complete" || result.Diagnostics.WorkflowStatus != "terminal" ||
		result.Diagnostics.NextAction != "none" || result.Diagnostics.ActionStage != "security_posture_revalidation" ||
		result.DatabaseKeys != nil || result.DatabaseCredential != nil || result.ImageKeys != nil {
		t.Fatalf("posture-only command performed acquisition or changed outcome: %+v", result)
	}
}

func TestSecurityPostureResponseRequiresRestorationForDisabledSIP(t *testing.T) {
	request := protocolmodel.AcquireRequest{Protocol: protocolmodel.Name, RequestID: "posture-1"}
	result := SecurityPostureResponse(
		request, acquisitionmodel.Options{Database: true}, "darwin", "sip_disabled_verified",
		diagnosticmodel.PlatformDefaults{DarwinShadowRouteStatus: "unavailable_in_build"},
	)
	if result.Diagnostics.ResultCode != "action_required" || result.Diagnostics.WorkflowStatus != "waiting_action" ||
		result.Diagnostics.NextAction != "reenable_sip" || result.Diagnostics.SecurityPostureStatus != "restoration_required" {
		t.Fatalf("disabled SIP did not require restoration: %+v", result.Diagnostics)
	}
}
