package provider

import (
	"bytes"
	"testing"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
)

func TestPreparedAcquisitionUsesPlatformDriverSeam(t *testing.T) {
	previous := platformDriver
	t.Cleanup(func() { platformDriver = previous })
	called := false
	platformDriver = acquisitionmodel.PlatformDriverFunc(func(targets acquisitionmodel.Targets, _ acquisitionmodel.MediaEvidence, request acquisitionmodel.PlatformRequest) (response, diagnostics, error) {
		called = true
		if !request.Database || !request.Budget.IsUnlimited() || targets.Count != 1 {
			t.Fatalf("driver request lost acquisition state: request=%+v targets=%+v", request, targets)
		}
		return response{DatabaseKeys: map[string]string{"message.db": string(bytes.Repeat([]byte{'1'}, 64))}},
			newDiagnostics("fixture", []string{"database"}), nil
	})

	targets := databaseTargets{
		Count: 1,
		Catalog: databaseCatalog{CatalogID: "catalog", Databases: []catalogDatabase{{
			DatabaseID: "database", RelativePath: "message.db", RequiredForKeyCoverage: true,
		}}},
	}
	result, err := acquisitionmodel.RunPrepared(acquireOptions{
		AccountDir: t.TempDir(), Database: true, Budget: unlimitedBudget().value, CatalogKey: bytes.Repeat([]byte{0x5a}, 32),
	}, targets, mediaEvidence{}, time.Now(), acquisitionWorkflowRuntime())
	if err != nil {
		t.Fatal(err)
	}
	if !called || result.Diagnostics.Platform != "fixture" || result.DatabaseKeys["message.db"] == "" {
		t.Fatalf("prepared acquisition bypassed or lost driver output: called=%v result=%+v", called, result)
	}
}
