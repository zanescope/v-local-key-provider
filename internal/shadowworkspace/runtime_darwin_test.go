//go:build darwin

package shadowworkspace

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowinventory "github.com/zanescope/v-local-key-provider/internal/shadowinventory"
)

func testAccount(t *testing.T) shadowaccount.Record {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(home, "Library"),
		filepath.Join(home, "Library", "Application Support"),
		filepath.Join(home, "Library", "Containers"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	uid := os.Geteuid()
	// Resolve through the public account database contract by temporarily using
	// the same identity shape in a helper process is unnecessary here; construct
	// the record from the home inode and validate the exact derivation instead.
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	payload := make([]byte, 4+8+8)
	binary.BigEndian.PutUint32(payload[0:4], uint32(uid))
	binary.BigEndian.PutUint64(payload[4:12], uint64(stat.Dev))
	binary.BigEndian.PutUint64(payload[12:20], uint64(stat.Ino))
	digest := sha256.Sum256(append([]byte("v-local-shadow-account/v1\x00"), payload...))
	return shadowaccount.Record{
		UID: uint32(uid), Home: home, HomeDevice: uint64(stat.Dev), HomeInode: uint64(stat.Ino),
		SecurityRoot:   filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime"),
		ContainersRoot: filepath.Join(home, "Library", "Containers"), BindingID: hex.EncodeToString(digest[:16]),
	}
}

func TestPrepareCreatesAPFSCloneAndExactBindings(t *testing.T) {
	account := testAccount(t)
	source := filepath.Join(account.Home, "Source", cloneLeaf)
	if err := os.MkdirAll(filepath.Join(source, "Contents", "Resources"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "Contents", "Resources", "sentinel"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, digest, err := shadowinventory.Scan(source)
	if err != nil {
		t.Fatal(err)
	}
	runtime := New()
	filesystem, err := runtime.Filesystem(account.Home)
	if err != nil || filesystem.Type != "apfs" {
		t.Skipf("APFS fixture unavailable: identity=%#v err=%v", filesystem, err)
	}
	rootLeaf := "attempt-0123456789abcdef0123456789abcdef"
	sourceIdentity, err := runtime.DirectoryIdentity(source)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := runtime.Prepare(context.Background(), account, source, rootLeaf, sourceIdentity, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 || resources[0].Kind != "workspace" || resources[0].Leaf != rootLeaf ||
		resources[1].Kind != "clone_app" || resources[1].Leaf != rootLeaf+"/"+cloneLeaf || resources[1].DigestSHA256 != digest {
		t.Fatalf("unexpected workspace bindings: %#v", resources)
	}
	if err := RemoveClone(context.Background(), account, rootLeaf, resources[1]); err != nil {
		t.Fatal(err)
	}
	if err := RemoveWorkspace(context.Background(), account, rootLeaf, resources[0]); err != nil {
		t.Fatal(err)
	}
	if _, after, err := shadowinventory.Scan(source); err != nil || after != digest {
		t.Fatalf("source drifted after workspace lifecycle: digest=%s err=%v", after, err)
	}
}

func TestPrepareRejectsNonAPFSBeforeAttemptDirectory(t *testing.T) {
	account := testAccount(t)
	source := filepath.Join(account.Home, "Source", cloneLeaf)
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sentinel"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, digest, err := shadowinventory.Scan(source)
	if err != nil {
		t.Fatal(err)
	}
	cloneCalled := false
	runtime := Runtime{
		Clone:      func(string, string, string) error { cloneCalled = true; return nil },
		Filesystem: func(string) (FilesystemIdentity, error) { return FilesystemIdentity{Device: 1, Type: "hfs"}, nil },
		DirectoryIdentity: func(string) (DirectoryIdentity, error) {
			return DirectoryIdentity{Device: 1, Inode: 2, UID: account.UID, Mode: 0o700, LinkCount: 1}, nil
		},
		PrepareSecurityRoot: func(shadowaccount.Record) (string, error) {
			t.Fatal("security root preparation crossed the filesystem gate")
			return "", nil
		},
		CreatePrivateDir: func(string, string, uint32) error {
			t.Fatal("attempt directory creation crossed the filesystem gate")
			return nil
		},
	}
	rootLeaf := "attempt-fedcba9876543210fedcba9876543210"
	expectedSource, err := runtime.DirectoryIdentity(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Prepare(context.Background(), account, source, rootLeaf, expectedSource, digest); err == nil {
		t.Fatal("non-APFS workspace was accepted")
	}
	if cloneCalled {
		t.Fatal("clone ran after the filesystem gate failed")
	}
}
