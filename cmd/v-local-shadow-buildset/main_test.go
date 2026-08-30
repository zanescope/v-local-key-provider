package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
)

func testStagingRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "stage")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	files := map[string][]byte{
		"v-local-cli":                            []byte("cli"),
		"shadow-contract-v1.json":                []byte("contract"),
		"v-local-key-provider":                   []byte("provider"),
		"shadow-source-manifest-v1.json":         []byte("source"),
		"v-local-shadow-supervisor":              []byte("supervisor"),
		"shadow-transformation-manifest-v1.json": []byte("transform"),
	}
	for leaf, payload := range files {
		mode := os.FileMode(0o444)
		if leaf == "v-local-cli" || leaf == "v-local-key-provider" || leaf == "v-local-shadow-supervisor" {
			mode = 0o555
		}
		path := filepath.Join(root, leaf)
		if err := os.WriteFile(path, payload, 0o600); err != nil || os.Chmod(path, mode) != nil {
			t.Fatalf("cannot create staging artifact %s: %v", leaf, err)
		}
	}
	entitlement := []byte("<plist><dict/></plist>\n")
	sum := sha256.Sum256(entitlement)
	leaf := "shadow-entitlements-" + hex.EncodeToString(sum[:]) + ".plist"
	path := filepath.Join(root, leaf)
	if err := os.WriteFile(path, entitlement, 0o600); err != nil || os.Chmod(path, 0o444) != nil {
		t.Fatal(err)
	}
	return root
}

func TestFreezeRootPublishesOnceAndImmediatelyVerifies(t *testing.T) {
	root := testStagingRoot(t)
	result, err := freezeRoot(root, shadowbuildset.RouteSyntheticOnly)
	if err != nil || !result.Frozen || !result.Verified || result.BuildSetDigest == "" {
		t.Fatalf("freeze result=%+v err=%v", result, err)
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("frozen root mode is invalid: %v", err)
	}
	verified, err := verifyRoot(root)
	if err != nil || verified.BuildSetDigest != result.BuildSetDigest {
		t.Fatalf("verification result=%+v err=%v", verified, err)
	}
	if _, err := freezeRoot(root, shadowbuildset.RouteSyntheticOnly); err == nil {
		t.Fatal("build-set freezer accepted a second freeze")
	}
}
