//go:build darwin

package shadow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func privateTempRoot(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(resolved, "shadow")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFileJournalAndLockerRejectReplacedRootDirectory(t *testing.T) {
	root := privateTempRoot(t)
	journal, err := NewFileJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := NewFileLocker(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := journal.Save(recoveryFixture()); err == nil {
		t.Fatal("journal accepted a replacement root inode")
	}
	if _, err := locker.Acquire(context.Background()); err == nil {
		t.Fatal("attempt locker accepted a replacement root inode")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement root was mutated: entries=%d err=%v", len(entries), err)
	}
}

func TestFileJournalAtomicallyReplacesAndExactlyRemovesCurrentIdentity(t *testing.T) {
	root := privateTempRoot(t)
	journal, err := NewFileJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	record := recoveryFixture()
	if err := journal.Save(record); err != nil {
		t.Fatal(err)
	}
	first, err := journal.Binding()
	if err != nil {
		t.Fatal(err)
	}
	record.PendingAction = ActionPrepareWorkspace
	if err := journal.Save(record); err != nil {
		t.Fatal(err)
	}
	second, err := journal.Binding()
	if err != nil {
		t.Fatal(err)
	}
	if first.Inode == second.Inode {
		t.Fatal("atomic recovery replacement unexpectedly reused the old inode")
	}
	loaded, err := journal.Load()
	if err != nil || loaded.PendingAction != ActionPrepareWorkspace {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err := journal.Remove(first); err == nil {
		t.Fatal("stale recovery identity was allowed to remove a replacement")
	}
	if err := journal.Remove(second); err != nil {
		t.Fatal(err)
	}
	if absent, err := journal.Absent(); err != nil || !absent {
		t.Fatalf("absent=%v err=%v", absent, err)
	}
}

func TestFileJournalNeverPromotesInterruptedNextRecord(t *testing.T) {
	root := privateTempRoot(t)
	journal, err := NewFileJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "recovery.next"), []byte("not authoritative"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrNoRecoveryRecord) {
		t.Fatalf("interrupted next record was promoted: %v", err)
	}
	if absent, err := journal.Absent(); err != nil || !absent {
		t.Fatalf("interrupted next record remained: absent=%v err=%v", absent, err)
	}
}

func TestFileJournalRejectsSymlinkAndHardlinkTargets(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := privateTempRoot(t)
		journal, err := NewFileJournal(root)
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "recovery.json")); err != nil {
			t.Fatal(err)
		}
		if err := journal.Save(recoveryFixture()); err == nil {
			t.Fatal("journal overwrote a symlink target")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		root := privateTempRoot(t)
		journal, err := NewFileJournal(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Save(recoveryFixture()); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(root, "recovery.json"), filepath.Join(root, "recovery.alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Load(); err == nil {
			t.Fatal("hard-linked recovery record was trusted")
		}
	})
}

func TestFileLockerSerializesWithoutPersistingState(t *testing.T) {
	root := privateTempRoot(t)
	first, err := NewFileLocker(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileLocker(root)
	if err != nil {
		t.Fatal(err)
	}
	release, err := first.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := second.Acquire(ctx); err == nil {
		t.Fatal("second Shadow attempt acquired an already held lock")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = second.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "attempt.lock"))
	if err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock is not the allowed empty owner-only serializer: info=%v err=%v", info, err)
	}
}
