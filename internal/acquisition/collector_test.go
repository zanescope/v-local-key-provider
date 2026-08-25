package acquisition

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
)

func TestRuntimePreservesIntentionalEmptyProfileRegistry(t *testing.T) {
	runtime := (Runtime{Profiles: []providercrypto.Profile{}}).normalized()
	if runtime.Profiles == nil || len(runtime.Profiles) != 0 {
		t.Fatalf("intentional empty profile registry was replaced: %#v", runtime.Profiles)
	}
}

func TestCandidateCollectorClearsMutableSecretBuffers(t *testing.T) {
	first := []byte{1, 2, 3}
	second := []byte{4, 5, 6}
	passphrase := []byte{7, 8, 9}
	collector := newCandidateCollector(databaseTargets{}, mediaEvidence{})
	collector.binaryCandidates = [][]byte{first}
	collector.internalXORKeys = [][]byte{second}
	collector.globalPassphrases["passphrase"] = &globalPassphraseEvidence{secret: passphrase}
	collector.ClearSensitiveBuffers()
	for _, values := range [][]byte{first, second, passphrase} {
		for _, value := range values {
			if value != 0 {
				t.Fatalf("mutable candidate buffer was not cleared: first=%v second=%v passphrase=%v", first, second, passphrase)
			}
		}
	}
}

func TestSameEffectiveKeyFromMultipleSourcesIsDeduplicated(t *testing.T) {
	targets := databaseTargets{
		Pages: []databasePage{{Path: "message.db", ProfileID: defaultProfileID}},
		Count: 1,
		Catalog: databaseCatalog{Databases: []catalogDatabase{{
			DatabaseID: "db", RelativePath: "message.db", RequiredForKeyCoverage: true,
		}}},
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	key := strings.Repeat("a1", 32)
	collector.addDatabaseCandidate("message.db", key, defaultProfileID, "commoncrypto_cccrypt")
	collector.addDatabaseCandidate("message.db", key, defaultProfileID, "macos_pbkdf_hook")

	keys, ambiguous := collector.DatabaseKeys(targets)
	if ambiguous != 0 || keys["message.db"] != key {
		t.Fatalf("the same verified key from two sources became ambiguous: keys=%v ambiguous=%d", keys, ambiguous)
	}
	origins := collector.databaseCandidates["message.db"][key].origins
	if !reflect.DeepEqual(origins, map[string]bool{
		"commoncrypto_cccrypt": true,
		"macos_pbkdf_hook":     true,
	}) {
		t.Fatalf("candidate provenance was not preserved during deduplication: %v", origins)
	}
}

func TestSameSaltFilesAreVerifiedIndependently(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	firstKey := strings.Repeat("12", 32)
	secondKey := strings.Repeat("34", 32)
	first := encryptedDatabasePage(t, firstKey, salt)
	first.Path = "one.db"
	second := encryptedDatabasePage(t, secondKey, salt)
	second.Path = "two.db"
	if bytes.Equal(first.Data, second.Data) {
		t.Fatal("fixtures unexpectedly match")
	}
	targets := databaseTargets{
		BySalt: map[string][]string{salt: {first.Path, second.Path}},
		Pages:  []databasePage{first, second}, Count: 2,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.validateDatabaseCandidate(firstKey, salt, targets)
	collector.validateDatabaseCandidate(secondKey, salt, targets)
	keys, ambiguous := collector.DatabaseKeys(targets)
	if ambiguous != 0 || keys[first.Path] != firstKey || keys[second.Path] != secondKey {
		t.Fatalf("same-salt files reused a validation result: keys=%v ambiguous=%d", keys, ambiguous)
	}
}
