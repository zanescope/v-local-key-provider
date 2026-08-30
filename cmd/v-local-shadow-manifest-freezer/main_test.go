package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFrozenFilesIsExclusiveAndRollsBackItsOwnOutputs(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "stage")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	values := []frozenFile{{leaf: "one.plist", payload: []byte("one")}, {leaf: "two.plist", payload: []byte("two")}}
	if err := writeFrozenFiles(root, values); err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		info, err := os.Lstat(filepath.Join(root, value.leaf))
		if err != nil || info.Mode().Perm() != 0o444 {
			t.Fatalf("frozen output mode is invalid: %s err=%v", value.leaf, err)
		}
	}
	if err := writeFrozenFiles(root, []frozenFile{
		{leaf: "new.plist", payload: []byte("new")},
		{leaf: "two.plist", payload: []byte("collision")},
	}); err == nil {
		t.Fatal("manifest-freezer overwrote an existing output")
	}
	if _, err := os.Lstat(filepath.Join(root, "new.plist")); !os.IsNotExist(err) {
		t.Fatal("manifest-freezer failure retained its partial output")
	}
}
