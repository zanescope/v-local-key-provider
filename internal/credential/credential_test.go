package credential

import (
	"reflect"
	"testing"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
)

func TestEvidenceSeparatesProcessIdentity(t *testing.T) {
	origins := map[string]bool{
		"global_passphrase":                       true,
		"macos_pbkdf_hook":                        true,
		ProcessInstanceSourcePrefix + "process-b": true,
		ProcessInstanceSourcePrefix + "process-a": true,
	}
	if actual := OverrideEvidence(origins); !reflect.DeepEqual(actual, []string{"macos_pbkdf_hook", "passphrase_validation_unproven_global"}) {
		t.Fatalf("unexpected override evidence: %v", actual)
	}
	if actual := ProcessInstanceEvidence(origins); !reflect.DeepEqual(actual, []string{"process-a", "process-b"}) {
		t.Fatalf("unexpected process evidence: %v", actual)
	}
}

func TestBuildPromotesOnlyCompleteMultipleSaltEvidence(t *testing.T) {
	key := "001122"
	input := BuildInput{
		Keys: map[string]string{"a.db": key, "b.db": key},
		Catalog: catalogmodel.Catalog{CatalogID: "catalog", Databases: []catalogmodel.Database{
			{DatabaseID: "a", RelativePath: "a.db", Salt: "salt-a"},
			{DatabaseID: "b", RelativePath: "b.db", Salt: "salt-b"},
		}},
		Candidates: map[string]map[string]CandidateEvidence{
			"a.db": {key: {ProfileID: "profile", Origins: map[string]bool{"global_passphrase": true}}},
			"b.db": {key: {ProfileID: "profile", Origins: map[string]bool{"global_passphrase": true}}},
		},
		GlobalPassphrases: map[string]PassphraseEvidence{
			"passphrase": {
				Secret: make([]byte, 32), Paths: map[string]bool{"a.db": true, "b.db": true},
				Sources: map[string]bool{"macos_pbkdf_hook": true}, CompleteCallEvidence: true,
			},
		},
	}
	identifiers := []string{"epoch", "root"}
	result, err := Build(input, func() (string, error) {
		value := identifiers[0]
		identifiers = identifiers[1:]
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "global_passphrase" || len(result.Roots) != 1 || len(result.Overrides) != 0 || result.Roots[0].CredentialID != "root" {
		t.Fatalf("unexpected promoted credential: %+v", result)
	}
}

func TestBuildKeepsSingleSaltEvidencePerDatabase(t *testing.T) {
	key := "001122"
	input := BuildInput{
		Keys:    map[string]string{"a.db": key},
		Catalog: catalogmodel.Catalog{Databases: []catalogmodel.Database{{DatabaseID: "a", RelativePath: "a.db", Salt: "salt-a"}}},
		Candidates: map[string]map[string]CandidateEvidence{
			"a.db": {key: {ProfileID: "profile", Origins: map[string]bool{"global_passphrase": true}}},
		},
		GlobalPassphrases: map[string]PassphraseEvidence{
			"passphrase": {Secret: make([]byte, 32), Paths: map[string]bool{"a.db": true}, CompleteCallEvidence: true},
		},
	}
	result, err := Build(input, func() (string, error) { return "epoch", nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "per_database" || len(result.Roots) != 0 || len(result.Overrides) != 1 {
		t.Fatalf("single-salt evidence was over-promoted: %+v", result)
	}
}
