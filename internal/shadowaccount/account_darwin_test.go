//go:build darwin

package shadowaccount

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestResolveCurrentUsesAccountDatabaseAndIgnoresEnvironmentPaths(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "untrusted-home"))
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "untrusted-temp"))
	uid := os.Geteuid()
	record, err := resolveCurrent(func(id string) (*user.User, error) {
		if id != strconv.Itoa(uid) {
			t.Fatalf("lookup used unexpected UID %q", id)
		}
		return &user.User{Uid: strconv.Itoa(uid), HomeDir: home}, nil
	}, uid)
	if err != nil {
		t.Fatal(err)
	}
	if record.Home != home || record.SecurityRoot != filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime") ||
		record.ContainersRoot != filepath.Join(home, "Library", "Containers") || len(record.BindingID) != 32 {
		t.Fatalf("unexpected account binding: %#v", record)
	}
}

func TestResolveCurrentRejectsLinkedHome(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(filepath.Dir(base), filepath.Base(base)+"-linked")
	if err := os.Symlink(base, linked); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(linked)
	uid := os.Geteuid()
	_, err = resolveCurrent(func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(uid), HomeDir: linked}, nil
	}, uid)
	if err == nil {
		t.Fatal("linked account home was accepted")
	}
}
