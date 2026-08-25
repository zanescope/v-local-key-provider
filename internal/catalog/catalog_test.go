package catalog

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func testPolicy() PlatformPolicy {
	return PlatformPolicy{
		FileIdentity: func(file *os.File) (string, error) {
			info, err := file.Stat()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s:%d", info.Name(), info.Size()), nil
		},
		IsLinkOrReparse: func(_ string, mode fs.FileMode) (bool, error) {
			return mode&os.ModeSymlink != 0, nil
		},
		CanonicalPathKey: filepath.ToSlash,
	}
}

func TestDiscoverClassifiesAndStabilizesCatalog(t *testing.T) {
	root := t.TempDir()
	plain := make([]byte, 4096)
	copy(plain, []byte("SQLite format 3\x00"))
	if err := os.WriteFile(filepath.Join(root, "plain.db"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, 4096)
	for index := range encrypted {
		encrypted[index] = byte(index + 1)
	}
	if err := os.WriteFile(filepath.Join(root, "encrypted.db"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	first, pages, err := Discover(root, key, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Discover(root, key, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if first.CatalogID == "" || first.CatalogID != second.CatalogID || len(first.Databases) != 2 || len(pages) != 1 {
		t.Fatalf("unstable or incomplete catalog: first=%+v second=%+v pages=%d", first, second, len(pages))
	}
	if pages[0].Path != "encrypted.db" || pages[0].Salt == "" {
		t.Fatalf("unexpected encrypted page evidence: %+v", pages[0])
	}
}

func TestDiscoverRequiresPlatformSafetyPolicy(t *testing.T) {
	if _, _, err := Discover(t.TempDir(), []byte("0123456789abcdef"), PlatformPolicy{}); err == nil {
		t.Fatal("missing platform policy was accepted")
	}
}

func TestMissingRequiredPreservesIdentityAndFiltersCoverage(t *testing.T) {
	catalog := Catalog{CatalogID: "catalog", DiscoveryErrors: []string{"evidence"}, Databases: []Database{
		{DatabaseID: "a", RelativePath: "a.db", RequiredForKeyCoverage: true},
		{DatabaseID: "b", RelativePath: "b.db", RequiredForKeyCoverage: true},
		{DatabaseID: "plain", RelativePath: "plain.db"},
	}}
	subset, paths := MissingRequired(catalog, map[string]string{"a.db": "key"})
	if subset.CatalogID != catalog.CatalogID || len(subset.DiscoveryErrors) != 1 ||
		len(subset.Databases) != 1 || subset.Databases[0].DatabaseID != "b" || !paths["b.db"] || paths["a.db"] {
		t.Fatalf("missing required catalog subset is invalid: subset=%+v paths=%v", subset, paths)
	}
	subset.DiscoveryErrors[0] = "changed"
	if catalog.DiscoveryErrors[0] != "evidence" {
		t.Fatal("missing required subset retained mutable discovery error storage")
	}
}
