package acquisition

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDatabaseCredentialSeparatesGlobalRootAndOverrides(t *testing.T) {
	globalKey := strings.Repeat("11", 32)
	overrideKey := strings.Repeat("22", 32)
	targets := databaseTargets{Catalog: databaseCatalog{CatalogID: "catalog-1", Databases: []catalogDatabase{
		{DatabaseID: "db-global", RelativePath: "message.db", Salt: strings.Repeat("a", 32), RequiredForKeyCoverage: true},
		{DatabaseID: "db-global-2", RelativePath: "message_1.db", Salt: strings.Repeat("b", 32), RequiredForKeyCoverage: true},
		{DatabaseID: "db-override", RelativePath: "contact.db", RequiredForKeyCoverage: true},
	}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	passphrase := bytes.Repeat([]byte{0x7b}, 32)
	collector.globalPassphrases[hex.EncodeToString(passphrase)] = &globalPassphraseEvidence{
		secret: passphrase, paths: map[string]bool{"message.db": true, "message_1.db": true},
		sources: map[string]bool{"macos_pbkdf_hook": true}, completeCallEvidence: true,
	}
	collector.addDatabaseCandidate("message.db", globalKey, defaultProfileID, "global_passphrase")
	collector.addDatabaseCandidate("message_1.db", globalKey, defaultProfileID, "global_passphrase")
	collector.addDatabaseCandidate("contact.db", overrideKey, defaultProfileID, "raw_enc_key")
	credential, err := collector.databaseCredential(map[string]string{
		"message.db": globalKey, "message_1.db": globalKey, "contact.db": overrideKey,
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if credential == nil || credential.Mode != "mixed" || len(credential.Roots) != 1 || len(credential.Overrides) != 1 {
		t.Fatalf("unexpected credential: %+v", credential)
	}
	if credential.Roots[0].Secret != strings.Repeat("7b", 32) || credential.Overrides["db-override"].Secret != overrideKey {
		t.Fatal("credential root and override semantics were mixed")
	}
}

func TestDatabaseCredentialDoesNotPromoteSingleSaltPassphraseToAccountRoot(t *testing.T) {
	effectiveKey := strings.Repeat("33", 32)
	targets := databaseTargets{Catalog: databaseCatalog{CatalogID: "catalog-single", Databases: []catalogDatabase{{
		DatabaseID: "db-single", RelativePath: "message.db", Salt: strings.Repeat("c", 32), RequiredForKeyCoverage: true,
	}}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	passphrase := bytes.Repeat([]byte{0x7b}, 32)
	collector.globalPassphrases[hex.EncodeToString(passphrase)] = &globalPassphraseEvidence{
		secret: passphrase, paths: map[string]bool{"message.db": true},
		sources: map[string]bool{"macos_pbkdf_hook": true}, completeCallEvidence: true,
	}
	collector.addDatabaseCandidate("message.db", effectiveKey, defaultProfileID, "global_passphrase")
	credential, err := collector.databaseCredential(map[string]string{"message.db": effectiveKey}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if credential == nil || credential.Mode != "per_database" || len(credential.Roots) != 0 ||
		credential.Overrides["db-single"].Secret != effectiveKey ||
		credential.Overrides["db-single"].SourceEvidence[0] != "passphrase_validation_unproven_global" {
		t.Fatalf("single-salt passphrase was incorrectly promoted: %+v", credential)
	}
}

func TestDatabaseCredentialDoesNotCombineDifferentPassphrasesIntoGlobalProof(t *testing.T) {
	firstKey := strings.Repeat("44", 32)
	secondKey := strings.Repeat("55", 32)
	targets := databaseTargets{Catalog: databaseCatalog{CatalogID: "catalog-split", Databases: []catalogDatabase{
		{DatabaseID: "db-first", RelativePath: "first.db", Salt: strings.Repeat("d", 32), RequiredForKeyCoverage: true},
		{DatabaseID: "db-second", RelativePath: "second.db", Salt: strings.Repeat("e", 32), RequiredForKeyCoverage: true},
	}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	firstPassphrase := bytes.Repeat([]byte{0x61}, 32)
	secondPassphrase := bytes.Repeat([]byte{0x62}, 32)
	collector.globalPassphrases[hex.EncodeToString(firstPassphrase)] = &globalPassphraseEvidence{
		secret: firstPassphrase, paths: map[string]bool{"first.db": true},
		sources: map[string]bool{"macos_pbkdf_hook": true}, completeCallEvidence: true,
	}
	collector.globalPassphrases[hex.EncodeToString(secondPassphrase)] = &globalPassphraseEvidence{
		secret: secondPassphrase, paths: map[string]bool{"second.db": true},
		sources: map[string]bool{"macos_pbkdf_hook": true}, completeCallEvidence: true,
	}
	collector.addDatabaseCandidate("first.db", firstKey, defaultProfileID, "global_passphrase")
	collector.addDatabaseCandidate("second.db", secondKey, defaultProfileID, "global_passphrase")
	credential, err := collector.databaseCredential(map[string]string{"first.db": firstKey, "second.db": secondKey}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Mode != "per_database" || len(credential.Roots) != 0 || len(credential.Overrides) != 2 {
		t.Fatalf("different passphrases were combined into global proof: %+v", credential)
	}
}

func TestPassphraseEvidenceStaysBoundAcrossTwoSalts(t *testing.T) {
	passphraseHex := strings.Repeat("7b", 32)
	first := encryptedV4PassphrasePage(t, passphraseHex, strings.Repeat("1a", 16))
	first.Path = "first.db"
	second := encryptedV4PassphrasePage(t, passphraseHex, strings.Repeat("2b", 16))
	second.Path = "second.db"
	targets := databaseTargets{
		Catalog: databaseCatalog{CatalogID: "catalog-passphrase", Databases: []catalogDatabase{
			{DatabaseID: "db-first", RelativePath: first.Path, Salt: first.Salt, RequiredForKeyCoverage: true},
			{DatabaseID: "db-second", RelativePath: second.Path, Salt: second.Salt, RequiredForKeyCoverage: true},
		}},
		Pages: []databasePage{first, second}, Count: 2,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	passphrase, _ := hex.DecodeString(passphraseHex)
	if !collector.ConsiderGlobalPassphrase(passphrase) {
		t.Fatal("valid passphrase did not record per-database evidence")
	}
	keys, ambiguous := collector.DatabaseKeys(targets)
	credential, err := collector.databaseCredential(keys, targets)
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous != 0 || len(keys) != 2 || credential == nil || credential.Mode != "global_passphrase" ||
		len(credential.Roots) != 1 || len(credential.Roots[0].VerifiedDatabaseIDs) != 2 {
		t.Fatalf("multi-salt passphrase evidence was not preserved: keys=%v ambiguous=%d credential=%+v", keys, ambiguous, credential)
	}
}

func TestMultiSaltProbeWithoutKDFCallEvidenceStaysPerDatabase(t *testing.T) {
	firstKey := strings.Repeat("66", 32)
	secondKey := strings.Repeat("77", 32)
	targets := databaseTargets{Catalog: databaseCatalog{CatalogID: "catalog-probe", Databases: []catalogDatabase{
		{DatabaseID: "db-first", RelativePath: "first.db", Salt: strings.Repeat("3c", 16), RequiredForKeyCoverage: true},
		{DatabaseID: "db-second", RelativePath: "second.db", Salt: strings.Repeat("4d", 16), RequiredForKeyCoverage: true},
	}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	passphrase := bytes.Repeat([]byte{0x70}, 32)
	collector.globalPassphrases[hex.EncodeToString(passphrase)] = &globalPassphraseEvidence{
		secret: passphrase, paths: map[string]bool{"first.db": true, "second.db": true},
		sources: map[string]bool{"bounded_memory_passphrase_probe": true}, completeCallEvidence: false,
	}
	collector.addDatabaseCandidate("first.db", firstKey, defaultProfileID, "global_passphrase")
	collector.addDatabaseCandidate("second.db", secondKey, defaultProfileID, "global_passphrase")
	credential, err := collector.databaseCredential(map[string]string{"first.db": firstKey, "second.db": secondKey}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Mode != "per_database" || len(credential.Roots) != 0 || len(credential.Overrides) != 2 {
		t.Fatalf("probe without KDF call evidence was promoted: %+v", credential)
	}
}

func TestConfigCipherPassphraseCannotBecomeAccountRoot(t *testing.T) {
	passphraseHex := strings.Repeat("7b", 32)
	first := encryptedV4PassphrasePage(t, passphraseHex, strings.Repeat("1c", 16))
	first.Path = "first.db"
	second := encryptedV4PassphrasePage(t, passphraseHex, strings.Repeat("2d", 16))
	second.Path = "second.db"
	targets := databaseTargets{
		Catalog: databaseCatalog{CatalogID: "phase4-config-cipher", Databases: []catalogDatabase{
			{DatabaseID: "db-first", RelativePath: first.Path, Salt: first.Salt, RequiredForKeyCoverage: true},
			{DatabaseID: "db-second", RelativePath: second.Path, Salt: second.Salt, RequiredForKeyCoverage: true},
		}},
		Pages: []databasePage{first, second}, Count: 2,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.processInstanceID = "windows-process:" + strings.Repeat("e", 64)
	passphrase, err := hex.DecodeString(passphraseHex)
	if err != nil {
		t.Fatal(err)
	}
	if !collector.RecordGlobalPassphrase(passphrase, "windows_config_cipher", false) {
		t.Fatal("Config.Cipher fixture passphrase did not validate current catalog pages")
	}
	keys, ambiguous := collector.DatabaseKeys(targets)
	credential, err := collector.databaseCredential(keys, targets)
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous != 0 || credential == nil || credential.Mode != "per_database" ||
		len(credential.Roots) != 0 || len(credential.Overrides) != 2 {
		t.Fatalf("fixed-layout passphrase was promoted beyond per-database evidence: %+v", credential)
	}
	for _, override := range credential.Overrides {
		sources := map[string]bool{}
		for _, source := range override.SourceEvidence {
			sources[source] = true
		}
		if !sources["windows_config_cipher"] || !sources["passphrase_validation_unproven_global"] {
			t.Fatalf("Config.Cipher override lost bounded provenance: %+v", override.SourceEvidence)
		}
		if len(override.ProcessInstanceIDs) != 1 || override.ProcessInstanceIDs[0] != collector.processInstanceID {
			t.Fatalf("Config.Cipher override lost process-instance provenance: %+v", override.ProcessInstanceIDs)
		}
	}
}

func TestGlobalRootRequiresTwoSaltsWithinTheSameProfile(t *testing.T) {
	targets := databaseTargets{Catalog: databaseCatalog{CatalogID: "catalog-profiles", Databases: []catalogDatabase{
		{DatabaseID: "db-a", RelativePath: "a.db", Salt: strings.Repeat("a", 32), RequiredForKeyCoverage: true},
		{DatabaseID: "db-b", RelativePath: "b.db", Salt: strings.Repeat("b", 32), RequiredForKeyCoverage: true},
	}}}
	collector := newCandidateCollector(targets, mediaEvidence{})
	passphrase := bytes.Repeat([]byte{0x7b}, 32)
	collector.globalPassphrases[hex.EncodeToString(passphrase)] = &globalPassphraseEvidence{
		secret: passphrase, paths: map[string]bool{"a.db": true, "b.db": true},
		sources: map[string]bool{"macos_pbkdf_hook": true}, completeCallEvidence: true,
	}
	keyA, keyB := strings.Repeat("11", 32), strings.Repeat("22", 32)
	collector.addDatabaseCandidate("a.db", keyA, "profile-a", "global_passphrase")
	collector.addDatabaseCandidate("b.db", keyB, "profile-b", "global_passphrase")
	credential, err := collector.databaseCredential(map[string]string{"a.db": keyA, "b.db": keyB}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Mode != "per_database" || len(credential.Roots) != 0 || len(credential.Overrides) != 2 {
		t.Fatalf("cross-profile salts were incorrectly combined into a root: %+v", credential)
	}
}
