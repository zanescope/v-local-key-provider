package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhase0CatalogProofChangesWhenPhysicalFileChanges(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "message.db")
	key := bytes.Repeat([]byte{0x73}, 32)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x11}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the size while changing the proof. Some filesystems have coarse timestamp
	// granularity, so force a distinct mtime as well.
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x22}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	second, _, err := discoverDatabaseCatalog(root, unlimitedBudget(), key)
	if err != nil {
		t.Fatal(err)
	}
	if first.CatalogID == second.CatalogID {
		t.Fatal("catalog ID did not bind the changed physical-file proof")
	}
	if first.Databases[0].DatabaseID != second.Databases[0].DatabaseID {
		t.Fatal("opaque database ID should remain stable for the same normalized path and machine key")
	}
	if first.Databases[0].FirstPageSHA256 == second.Databases[0].FirstPageSHA256 {
		t.Fatal("first-page proof did not change with file contents")
	}
}
