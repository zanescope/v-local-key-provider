//go:build !windows

package shadowcontainer

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
)

func containerAccount(t *testing.T) shadowaccount.Record {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(home, "Library"), filepath.Join(home, "Library", "Application Support"),
		filepath.Join(home, "Library", "Containers"),
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
	return shadowaccount.Record{
		UID: stat.Uid, Home: home, HomeDevice: uint64(stat.Dev), HomeInode: uint64(stat.Ino),
		SecurityRoot:   filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime"),
		ContainersRoot: filepath.Join(home, "Library", "Containers"), BindingID: hex.EncodeToString(digest[:16]),
	}
}

func containerRecord(id string) shadowmodel.RecoveryRecord {
	return shadowmodel.RecoveryRecord{AttemptID: id, BundleID: "com.zanescope.vlocal.shadow." + id}
}

func TestRuntimeCreatesAndRemovesOnlyExactAttemptContainer(t *testing.T) {
	account := containerAccount(t)
	record := containerRecord("0123456789abcdef0123456789abcdef")
	runtime := Runtime{}
	binding, err := runtime.Create(context.Background(), account, record)
	if err != nil || binding.Kind != "container" || binding.Leaf != record.BundleID {
		t.Fatalf("create binding=%+v err=%v", binding, err)
	}
	record.Resources = append(record.Resources, binding)
	target := filepath.Join(account.ContainersRoot, record.BundleID)
	if err := os.Mkdir(filepath.Join(target, "Data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Data", "sentinel"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), account, record); err != nil {
		t.Fatal(err)
	}
	if !runtime.Absent(account, record) {
		t.Fatal("exact attempt container remains after cleanup")
	}
}

func TestRuntimeReconcilesCreateBeforeJournalBinding(t *testing.T) {
	account := containerAccount(t)
	record := containerRecord("abcdefabcdefabcdefabcdefabcdefab")
	runtime := Runtime{}
	if _, err := runtime.Create(context.Background(), account, record); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), account, record); err != nil {
		t.Fatal(err)
	}
	if !runtime.Absent(account, record) {
		t.Fatal("pending-action reconciliation left a container")
	}
}

func TestRuntimeRejectsSameLeafReplacement(t *testing.T) {
	account := containerAccount(t)
	record := containerRecord("fedcbafedcbafedcbafedcbafedcbafe")
	runtime := Runtime{}
	binding, err := runtime.Create(context.Background(), account, record)
	if err != nil {
		t.Fatal(err)
	}
	record.Resources = append(record.Resources, binding)
	target := filepath.Join(account.ContainersRoot, record.BundleID)
	displaced := target + ".displaced"
	if err := os.Rename(target, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), account, record); err == nil {
		t.Fatal("same-leaf replacement was removed using a stale binding")
	}
	for _, leaf := range []string{record.BundleID, filepath.Base(displaced)} {
		current, err := shadowcleanup.BindDirectory(account.ContainersRoot, leaf, "container")
		if err != nil {
			t.Fatal(err)
		}
		if err := shadowcleanup.RemoveExactDirectory(context.Background(), account.ContainersRoot, current); err != nil {
			t.Fatal(err)
		}
	}
}
