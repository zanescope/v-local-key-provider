//go:build darwin

package shadowlaunch

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcleanup "github.com/zanescope/v-local-key-provider/internal/shadowcleanup"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

func launchFixture(t *testing.T) (shadowaccount.Record, shadowmodel.RecoveryRecord, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(home, "Library"), filepath.Join(home, "Library", "Application Support"),
		filepath.Join(home, "Library", "Containers"), filepath.Join(home, "Library", "Application Support", "v-local"),
		filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	payload := make([]byte, 20)
	binary.BigEndian.PutUint32(payload[0:4], stat.Uid)
	binary.BigEndian.PutUint64(payload[4:12], uint64(stat.Dev))
	binary.BigEndian.PutUint64(payload[12:20], uint64(stat.Ino))
	digest := sha256.Sum256(append([]byte("v-local-shadow-account/v1\x00"), payload...))
	account := shadowaccount.Record{
		UID: stat.Uid, Home: home, HomeDevice: uint64(stat.Dev), HomeInode: uint64(stat.Ino),
		SecurityRoot:   filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime"),
		ContainersRoot: filepath.Join(home, "Library", "Containers"), BindingID: hex.EncodeToString(digest[:16]),
	}
	id := "0123456789abcdef0123456789abcdef"
	record := shadowmodel.RecoveryRecord{
		AttemptID: id, RootLeaf: "attempt-" + id, BundleID: "com.zanescope.vlocal.shadow." + id,
	}
	workspace, err := shadowcleanup.CreateExactDirectory(context.Background(), account.SecurityRoot, record.RootLeaf, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	clone, err := shadowcleanup.CreateExactDirectory(context.Background(), filepath.Join(account.SecurityRoot, record.RootLeaf), "WeChat.app", "clone_app")
	if err != nil {
		t.Fatal(err)
	}
	workspace.Leaf = record.RootLeaf
	clone.Leaf = filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app"))
	record.Resources = []contract.ResourceBinding{workspace, clone}
	return account, record, filepath.Join(account.SecurityRoot, record.RootLeaf, "WeChat.app")
}

type fakeRegistry struct {
	paths map[string][]string
	calls []string
}

func (value *fakeRegistry) runtime() Runtime {
	return Runtime{
		Register: func(_ context.Context, path, bundle string) error {
			value.calls = append(value.calls, "register\x00"+path+"\x00"+bundle)
			value.paths[bundle] = []string{path}
			return nil
		},
		Unregister: func(_ context.Context, path, bundle string) error {
			value.calls = append(value.calls, "unregister\x00"+path+"\x00"+bundle)
			delete(value.paths, bundle)
			return nil
		},
		RegisteredPaths: func(_ context.Context, bundle string) ([]string, error) {
			return append([]string(nil), value.paths[bundle]...), nil
		},
	}
}

func TestRuntimeRegistersAndUnregistersOnlyJournaledClone(t *testing.T) {
	account, record, clone := launchFixture(t)
	registry := &fakeRegistry{paths: map[string][]string{}}
	runtime := registry.runtime()
	if err := runtime.RegisterExact(context.Background(), account, record); err != nil {
		t.Fatal(err)
	}
	if len(registry.calls) != 1 || registry.paths[record.BundleID][0] != clone {
		t.Fatalf("unexpected registration calls=%v paths=%v", registry.calls, registry.paths)
	}
	if err := runtime.UnregisterExact(context.Background(), account, record); err != nil {
		t.Fatal(err)
	}
	if !runtime.Absent(context.Background(), record) || len(registry.calls) != 2 {
		t.Fatalf("registration residue: calls=%v paths=%v", registry.calls, registry.paths)
	}
}

func TestRuntimeRejectsCloneReplacementBeforeRegistryMutation(t *testing.T) {
	account, record, clone := launchFixture(t)
	displaced := clone + ".displaced"
	if err := os.Rename(clone, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(clone, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := &fakeRegistry{paths: map[string][]string{}}
	if err := registry.runtime().RegisterExact(context.Background(), account, record); err == nil {
		t.Fatal("replacement clone was registered")
	}
	if len(registry.calls) != 0 {
		t.Fatalf("registry mutated before clone rejection: %v", registry.calls)
	}
}

func TestRuntimeRejectsAdditionalPathForRandomBundleID(t *testing.T) {
	account, record, clone := launchFixture(t)
	registry := &fakeRegistry{paths: map[string][]string{}}
	runtime := registry.runtime()
	runtime.Register = func(_ context.Context, path, bundle string) error {
		registry.paths[bundle] = []string{path, filepath.Join(account.Home, "unexpected.app")}
		return nil
	}
	if err := runtime.RegisterExact(context.Background(), account, record); err == nil {
		t.Fatal("ambiguous random bundle registration was accepted")
	}
	if registry.paths[record.BundleID][0] != clone {
		t.Fatal("test registry lost the exact clone path")
	}
}

func TestRuntimeRejectsPreexistingRandomIdentityBeforeRegistryMutation(t *testing.T) {
	account, record, _ := launchFixture(t)
	registry := &fakeRegistry{paths: map[string][]string{
		record.BundleID: {filepath.Join(account.Home, "unexpected.app")},
	}}
	if err := registry.runtime().RegisterExact(context.Background(), account, record); err == nil {
		t.Fatal("preexisting random identity was overwritten")
	}
	if len(registry.calls) != 0 {
		t.Fatalf("registry mutated before collision rejection: %v", registry.calls)
	}
}
