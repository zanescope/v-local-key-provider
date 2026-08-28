package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogClassifiesEveryDatabaseWithoutTreatingWALAsDatabase(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "encrypted.db"), bytes.Repeat([]byte{0x42}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain.db"), append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0}, 4080)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "short.db"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "encrypted.db-wal"), bytes.Repeat([]byte{0x11}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x99}, 32)
	catalog, pages, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Databases) != 3 || len(pages) != 1 || catalog.CatalogID == "" {
		t.Fatalf("unexpected catalog: catalog=%+v pages=%d", catalog, len(pages))
	}
	classifications := map[string]databaseClassification{}
	for _, database := range catalog.Databases {
		classifications[database.RelativePath] = database.Classification
		if database.DatabaseID == "" || strings.Contains(database.DatabaseID, database.RelativePath) {
			t.Fatalf("database ID is not opaque: %+v", database)
		}
	}
	if classifications["encrypted.db"] != classificationEncrypted || classifications["plain.db"] != classificationPlaintext || classifications["short.db"] != classificationTruncated {
		t.Fatalf("unexpected classifications: %v", classifications)
	}
}

func TestCatalogIdentifiersAreStableForOneMachineKey(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "message.db"), bytes.Repeat([]byte{0x42}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x77}, 32)
	first, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	if first.CatalogID != second.CatalogID || first.Databases[0].DatabaseID != second.Databases[0].DatabaseID {
		t.Fatalf("catalog identifiers drifted: first=%+v second=%+v", first, second)
	}
}

func TestCatalogPathKeyNormalizesUnicode(t *testing.T) {
	if catalogPathKey("cafe\u0301.db") != catalogPathKey("caf\u00e9.db") {
		t.Fatal("catalog path key did not normalize canonically equivalent Unicode")
	}
}
