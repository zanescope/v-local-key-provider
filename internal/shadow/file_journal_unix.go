//go:build darwin

package shadow

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	"golang.org/x/sys/unix"
)

const (
	recoveryLeaf           = "recovery.json"
	recoveryNextLeaf       = "recovery.next"
	maxRecoveryRecordBytes = 256 * 1024
)

type FileJournal struct {
	root   string
	uid    uint32
	device uint64
	inode  uint64
}

func NewFileJournal(root string) (*FileJournal, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("shadow recovery root must be absolute")
	}
	root = filepath.Clean(root)
	if err := ensurePrivateRoot(root); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	fd, stat, err := openRecoveryRoot(root, uid, 0, 0, false)
	if err != nil {
		return nil, err
	}
	_ = unix.Close(fd)
	return &FileJournal{root: root, uid: uid, device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

// ensurePrivateRoot validates an existing root. Creation belongs to the
// account-bound macOS workspace preparation and is never implicit here.
func ensurePrivateRoot(path string) error {
	if err := validateExistingHierarchy(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("shadow recovery root is not an owner-only ordinary directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Dev == 0 || stat.Ino == 0 {
		return errors.New("shadow recovery root owner or identity is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("shadow recovery root contains a symlink")
	}
	return nil
}

func validateExistingHierarchy(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return errors.New("private hierarchy must be absolute")
	}
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("shadow private hierarchy contains a missing, linked, or non-directory component")
		}
	}
	return nil
}

func openRecoveryRoot(root string, uid uint32, device, inode uint64, bound bool) (int, unix.Stat_t, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("shadow recovery root could not be opened")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o777 != 0o700 || stat.Uid != uid || bound &&
		(uint64(stat.Dev) != device || uint64(stat.Ino) != inode) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("shadow recovery root identity drifted")
	}
	return fd, stat, nil
}

func (value *FileJournal) withRoot(action func(int) error) error {
	if value == nil || action == nil {
		return errors.New("shadow recovery journal is unconfigured")
	}
	fd, _, err := openRecoveryRoot(value.root, value.uid, value.device, value.inode, true)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return action(fd)
}

func journalStat(rootFD int, leaf string, allowEmpty bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		(!allowEmpty && stat.Size <= 0) || stat.Size > maxRecoveryRecordBytes {
		return stat, errors.New("shadow recovery record identity is unsafe")
	}
	return stat, nil
}

func sameJournalStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Uid == right.Uid &&
		left.Mode == right.Mode && left.Nlink == right.Nlink && left.Size == right.Size
}

func bindingFromJournalStat(leaf string, stat unix.Stat_t) (contract.ResourceBinding, error) {
	binding := contract.ResourceBinding{
		Kind: "recovery_record", Leaf: leaf, Device: uint64(stat.Dev), Inode: uint64(stat.Ino),
		UID: stat.Uid, Mode: uint32(stat.Mode & 0o777), LinkCount: uint64(stat.Nlink),
	}
	if err := binding.Validate(); err != nil {
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}

func journalBinding(rootFD int, leaf string) (contract.ResourceBinding, error) {
	stat, err := journalStat(rootFD, leaf, false)
	if err != nil {
		return contract.ResourceBinding{}, err
	}
	return bindingFromJournalStat(leaf, stat)
}

func removeJournalLeaf(rootFD int, leaf string, allowEmpty bool) error {
	before, err := journalStat(rootFD, leaf, allowEmpty)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	after, err := journalStat(rootFD, leaf, allowEmpty)
	if err != nil || !sameJournalStat(before, after) {
		return errors.New("shadow recovery removal target drifted")
	}
	if err := unix.Unlinkat(rootFD, leaf, 0); err != nil {
		return err
	}
	return unix.Fsync(rootFD)
}

func readRecovery(rootFD int) (RecoveryRecord, error) {
	stat, err := journalStat(rootFD, recoveryLeaf, false)
	if errors.Is(err, unix.ENOENT) {
		return RecoveryRecord{}, ErrNoRecoveryRecord
	}
	if err != nil {
		return RecoveryRecord{}, err
	}
	fd, err := unix.Openat(rootFD, recoveryLeaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return RecoveryRecord{}, err
	}
	file := os.NewFile(uintptr(fd), recoveryLeaf)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameJournalStat(stat, opened) {
		_ = file.Close()
		return RecoveryRecord{}, errors.New("shadow recovery record changed during open")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxRecoveryRecordBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(payload) == 0 || int64(len(payload)) != stat.Size ||
		len(payload) > maxRecoveryRecordBytes {
		return RecoveryRecord{}, errors.New("shadow recovery record is empty, drifted, or oversized")
	}
	var record RecoveryRecord
	if err := contract.DecodeStrict(payload, &record); err != nil || record.Validate() != nil {
		return RecoveryRecord{}, errors.New("shadow recovery record is not valid strict JSON")
	}
	return record, nil
}

func (value *FileJournal) Load() (RecoveryRecord, error) {
	var record RecoveryRecord
	err := value.withRoot(func(rootFD int) error {
		if err := removeJournalLeaf(rootFD, recoveryNextLeaf, true); err != nil {
			return err
		}
		var err error
		record, err = readRecovery(rootFD)
		return err
	})
	return record, err
}

func (value *FileJournal) Save(record RecoveryRecord) error {
	if value == nil || record.Validate() != nil {
		return errors.New("shadow recovery record is invalid")
	}
	payload, err := json.Marshal(record)
	if err != nil || len(payload) > maxRecoveryRecordBytes-1 {
		return errors.New("shadow recovery record encoding is invalid")
	}
	payload = append(payload, '\n')
	return value.withRoot(func(rootFD int) error {
		if err := removeJournalLeaf(rootFD, recoveryNextLeaf, true); err != nil {
			return err
		}
		current, currentErr := journalStat(rootFD, recoveryLeaf, false)
		if currentErr != nil && !errors.Is(currentErr, unix.ENOENT) {
			return currentErr
		}
		fd, err := unix.Openat(rootFD, recoveryNextLeaf,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), recoveryNextLeaf)
		published := false
		defer func() {
			_ = file.Close()
			if !published {
				_ = unix.Unlinkat(rootFD, recoveryNextLeaf, 0)
			}
		}()
		if _, err := file.Write(payload); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if errors.Is(currentErr, unix.ENOENT) {
			if err := unix.RenameatxNp(rootFD, recoveryNextLeaf, rootFD, recoveryLeaf, unix.RENAME_EXCL); err != nil {
				return err
			}
			published = true
			return unix.Fsync(rootFD)
		}
		if err := unix.RenameatxNp(rootFD, recoveryNextLeaf, rootFD, recoveryLeaf, unix.RENAME_SWAP); err != nil {
			return err
		}
		published = true
		swapped, err := journalStat(rootFD, recoveryNextLeaf, false)
		if err != nil || !sameJournalStat(current, swapped) {
			return errors.New("replaced shadow recovery record identity drifted")
		}
		if err := unix.Unlinkat(rootFD, recoveryNextLeaf, 0); err != nil {
			return err
		}
		return unix.Fsync(rootFD)
	})
}

func (value *FileJournal) Binding() (contract.ResourceBinding, error) {
	var binding contract.ResourceBinding
	err := value.withRoot(func(rootFD int) error {
		var err error
		binding, err = journalBinding(rootFD, recoveryLeaf)
		return err
	})
	return binding, err
}

func (value *FileJournal) Remove(expected contract.ResourceBinding) error {
	if value == nil || expected.Validate() != nil || expected.Kind != "recovery_record" || expected.Leaf != recoveryLeaf {
		return errors.New("shadow recovery removal binding is invalid")
	}
	return value.withRoot(func(rootFD int) error {
		actual, err := journalBinding(rootFD, recoveryLeaf)
		if errors.Is(err, unix.ENOENT) {
			return removeJournalLeaf(rootFD, recoveryNextLeaf, true)
		}
		if err != nil || actual != expected {
			return errors.New("shadow recovery record identity changed before removal")
		}
		current, err := journalBinding(rootFD, recoveryLeaf)
		if err != nil || current != expected {
			return errors.New("shadow recovery record drifted at removal")
		}
		if err := unix.Unlinkat(rootFD, recoveryLeaf, 0); err != nil {
			return err
		}
		if err := removeJournalLeaf(rootFD, recoveryNextLeaf, true); err != nil {
			return err
		}
		return unix.Fsync(rootFD)
	})
}

func (value *FileJournal) Absent() (bool, error) {
	absent := true
	err := value.withRoot(func(rootFD int) error {
		for _, leaf := range []string{recoveryLeaf, recoveryNextLeaf} {
			var stat unix.Stat_t
			err := unix.Fstatat(rootFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil {
				absent = false
				return nil
			}
			if !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		return nil
	})
	return absent, err
}
