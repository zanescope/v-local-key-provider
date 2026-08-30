//go:build !windows

package shadowcleanup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

func privateRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDirectSyntheticContainerQualificationIsExactAndResidueFree(t *testing.T) {
	root := privateRoot(t)
	qualification, err := QualifyDirect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if qualification.Route != contract.CleanupRouteDirect || !qualification.NestedRemoved || !qualification.ReplacementRejected {
		t.Fatalf("qualification=%+v", qualification)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("synthetic cleanup qualification left residue: entries=%v err=%v", entries, err)
	}
}

func TestDirectCleanupRejectsHardLinkedChildWithoutExpandingScope(t *testing.T) {
	root := privateRoot(t)
	leaf := "container"
	target := filepath.Join(root, leaf)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(target, "first")
	second := filepath.Join(target, "second")
	if err := os.WriteFile(first, []byte("bound"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}
	binding, err := BindDirectory(root, leaf, "container")
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveExactDirectory(context.Background(), root, binding); err == nil {
		t.Fatal("hard-linked child was deleted by broad recursive cleanup")
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatal("failed exact cleanup damaged the hard-linked target")
	}
}

func TestDirectCleanupHonorsCancellationBeforeMutation(t *testing.T) {
	root := privateRoot(t)
	if err := os.Mkdir(filepath.Join(root, "container"), 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := BindDirectory(root, "container", "container")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RemoveExactDirectory(ctx, root, binding); err == nil {
		t.Fatal("cancelled direct cleanup mutated its target")
	}
	if _, err := os.Stat(filepath.Join(root, "container")); err != nil {
		t.Fatal("cancelled direct cleanup removed its target")
	}
}

func TestDirectCleanupRejectsNilContextWithoutMutation(t *testing.T) {
	root := privateRoot(t)
	if err := os.Mkdir(filepath.Join(root, "container"), 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := BindDirectory(root, "container", "container")
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveExactDirectory(nil, root, binding); err == nil {
		t.Fatal("nil cleanup context was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "container")); err != nil {
		t.Fatal("nil-context cleanup removed its target")
	}
}
