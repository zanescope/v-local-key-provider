package acquisition

import (
	"bytes"
	"errors"
	"testing"
	"time"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

func workflowTargetsFixture() Targets {
	return Targets{
		Count: 1,
		Catalog: catalogmodel.Catalog{
			CatalogID: "catalog-1",
			Databases: []catalogmodel.Database{{
				DatabaseID: "database-1", RelativePath: "message.db",
				Classification: catalogmodel.ClassificationEncrypted, RequiredForKeyCoverage: true,
			}},
		},
	}
}

func workflowRuntimeFixture(t *testing.T, targets Targets) WorkflowRuntime {
	t.Helper()
	return WorkflowRuntime{
		DiscoverTargets: func(dbDir string, budget workbudget.Budget, key []byte) (Targets, error) {
			if dbDir != "db" || !budget.IsUnlimited() || len(key) != 32 {
				t.Fatalf("target discovery lost options: dir=%q budget=%+v key=%x", dbDir, budget, key)
			}
			return targets, nil
		},
		DiscoverMedia: func(accountDir string, budget workbudget.Budget) MediaEvidence {
			if accountDir != "account" || !budget.IsUnlimited() {
				t.Fatalf("media discovery lost options: dir=%q budget=%+v", accountDir, budget)
			}
			return MediaEvidence{XORCandidates: map[byte]int{7: 1}}
		},
		Driver: PlatformDriverFunc(func(gotTargets Targets, media MediaEvidence, request PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
			if gotTargets.Catalog.CatalogID != targets.Catalog.CatalogID || media.XORCandidates[7] != 1 ||
				!request.Database || !request.Media || request.HelperStatus != "not_used" {
				t.Fatalf("platform driver lost workflow evidence: targets=%+v media=%+v request=%+v", gotTargets, media, request)
			}
			return protocolmodel.Response{
				DatabaseKeys:       map[string]string{"message.db": string(bytes.Repeat([]byte{'1'}, 64))},
				DatabaseCredential: &credentialmodel.DatabaseCredential{Mode: "per_database_enc_key"},
				ImageKeys:          &protocolmodel.ImageKeys{AES: "1234567890abcdef", XOR: 7},
			}, diagnosticmodel.New("fixture", []string{"database", "media"}, "not_applicable"), nil
		}),
		CatalogHMAC: func(key []byte, values ...string) string {
			if len(key) != 32 || len(values) != 2 || values[0] != "account" || values[1] != "account" {
				t.Fatalf("account binding inputs changed: key=%x values=%v", key, values)
			}
			return "account-binding"
		},
		ProfileSummaries: func() []providercrypto.Summary {
			return []providercrypto.Summary{{ID: "profile-1"}}
		},
	}
}

func TestRunOwnsOneShotDiscoveryFinalizationAndSecretCleanup(t *testing.T) {
	targets := workflowTargetsFixture()
	key := bytes.Repeat([]byte{0x5a}, 32)
	result, err := Run(Options{
		AccountDir: "account", DBDir: "db", Database: true, Media: true,
		Budget: workbudget.Unlimited(), CatalogKey: key, HelperStatus: "not_used",
	}, workflowRuntimeFixture(t, targets))
	if err != nil {
		t.Fatal(err)
	}
	if result.CatalogID != "catalog-1" || len(result.CatalogEntries) != 1 ||
		result.DatabaseCredential == nil || result.DatabaseCredential.AccountBindingID != "account-binding" ||
		len(result.Profiles) != 1 || result.Profiles[0].ID != "profile-1" ||
		result.Diagnostics.ResultCode != "complete" || result.Diagnostics.DatabaseCoverageStatus != "complete" ||
		result.Diagnostics.MediaCoverageStatus != "complete" {
		t.Fatalf("one-shot response assembly changed: %+v", result)
	}
	if result.Diagnostics.PhaseTimingsMS == nil {
		t.Fatal("one-shot phase timings were not initialized")
	}
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatalf("Run did not clear its catalog key: %x", key)
	}
}

func TestRunClearsGeneratedCatalogKeyAfterDiscoveryFailure(t *testing.T) {
	generated := bytes.Repeat([]byte{0x7b}, 32)
	runtime := WorkflowRuntime{
		RandomCatalogKey: func() ([]byte, error) { return generated, nil },
		DiscoverTargets: func(string, workbudget.Budget, []byte) (Targets, error) {
			return Targets{}, errors.New("discovery failed")
		},
	}
	if _, err := Run(Options{Database: true, Budget: workbudget.Unlimited()}, runtime); err == nil {
		t.Fatal("target discovery failure was swallowed")
	}
	if !bytes.Equal(generated, make([]byte, len(generated))) {
		t.Fatalf("generated catalog key was not cleared: %x", generated)
	}
}

func TestRunPreparedLeavesCatalogKeyOwnershipWithCaller(t *testing.T) {
	targets := workflowTargetsFixture()
	key := bytes.Repeat([]byte{0x3c}, 32)
	options := Options{
		AccountDir: "account", DBDir: "db", Database: true, Media: true,
		Budget: workbudget.Unlimited(), CatalogKey: key, HelperStatus: "not_used",
	}
	if _, err := RunPrepared(options, targets, MediaEvidence{XORCandidates: map[byte]int{7: 1}}, time.Now(), workflowRuntimeFixture(t, targets)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0x3c}, 32)) {
		t.Fatal("RunPrepared took ownership of the caller's catalog key")
	}
}
