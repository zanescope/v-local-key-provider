//go:build darwin

package shadowworkspace

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	"golang.org/x/sys/unix"
)

func fsType(value [16]byte) string {
	payload := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		payload = append(payload, character)
	}
	return string(payload)
}

func filesystemIdentity(path string) (FilesystemIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return FilesystemIdentity{}, errors.New("Shadow filesystem target is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 {
		return FilesystemIdentity{}, errors.New("Shadow filesystem identity is unavailable")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return FilesystemIdentity{}, err
	}
	return FilesystemIdentity{Device: uint64(stat.Dev), Type: fsType(filesystem.Fstypename)}, nil
}

func directoryIdentity(path string) (DirectoryIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return DirectoryIdentity{}, errors.New("Shadow directory identity is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return DirectoryIdentity{}, errors.New("Shadow directory identity contains a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 || stat.Nlink == 0 {
		return DirectoryIdentity{}, errors.New("Shadow directory identity is unavailable")
	}
	return DirectoryIdentity{
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: stat.Uid,
		Mode: uint32(info.Mode().Perm()), LinkCount: uint64(stat.Nlink),
	}, nil
}

func verifyDirectory(path string, uid uint32, private bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Shadow runtime ancestor is not an ordinary directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || private && info.Mode().Perm()&0o077 != 0 {
		return errors.New("Shadow runtime ancestor owner or mode is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return errors.New("Shadow runtime ancestor contains a symlink")
	}
	return nil
}

func validLeaf(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value
}

func openDirectory(path string, uid uint32, private bool) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uid ||
		private && uint32(stat.Mode&0o777)&0o077 != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("Shadow directory descriptor owner or mode is invalid")
	}
	return fd, nil
}

func ensurePrivateChild(parent, leaf string, uid uint32, allowExisting bool) (string, error) {
	if !validLeaf(leaf) {
		return "", errors.New("Shadow runtime leaf is invalid")
	}
	parentFD, err := openDirectory(parent, uid, false)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	err = unix.Mkdirat(parentFD, leaf, 0o700)
	if err != nil && !(allowExisting && errors.Is(err, unix.EEXIST)) {
		return "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || uint32(stat.Mode&0o777)&0o077 != 0 {
		return "", errors.New("Shadow runtime child identity is invalid")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return "", err
	}
	target := filepath.Join(parent, leaf)
	if err := verifyDirectory(target, uid, true); err != nil {
		return "", err
	}
	return target, nil
}

func createPrivateDirectory(parent, leaf string, uid uint32) error {
	_, err := ensurePrivateChild(parent, leaf, uid, false)
	return err
}

func cloneExact(source, destinationParent, destinationLeaf string) error {
	if !validLeaf(filepath.Base(source)) || !validLeaf(destinationLeaf) {
		return errors.New("Shadow APFS clone leaf is invalid")
	}
	sourceParent := filepath.Dir(source)
	sourceFD, err := unix.Open(sourceParent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)
	destinationFD, err := unix.Open(destinationParent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(destinationFD)
	var sourceStat unix.Stat_t
	if err := unix.Fstatat(sourceFD, filepath.Base(source), &sourceStat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		sourceStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("Shadow APFS clone source is not an ordinary directory")
	}
	if err := unix.Clonefileat(sourceFD, filepath.Base(source), destinationFD, destinationLeaf, unix.CLONE_NOFOLLOW); err != nil {
		return err
	}
	return unix.Fsync(destinationFD)
}

func prepareSecurityRoot(account shadowaccount.Record) (string, error) {
	if err := shadowaccount.Revalidate(account); err != nil {
		return "", err
	}
	library := filepath.Join(account.Home, "Library")
	applicationSupport := filepath.Join(library, "Application Support")
	for _, ancestor := range []string{library, applicationSupport} {
		if err := verifyDirectory(ancestor, account.UID, false); err != nil {
			return "", err
		}
	}
	productRoot, err := ensurePrivateChild(applicationSupport, "v-local", account.UID, true)
	if err != nil {
		return "", err
	}
	runtimeRoot, err := ensurePrivateChild(productRoot, "shadow-runtime", account.UID, true)
	if err != nil || runtimeRoot != account.SecurityRoot {
		return "", errors.New("Shadow runtime root does not match the account binding")
	}
	return runtimeRoot, nil
}

func New() Runtime {
	return Runtime{
		Clone:               cloneExact,
		Filesystem:          filesystemIdentity,
		DirectoryIdentity:   directoryIdentity,
		PrepareSecurityRoot: prepareSecurityRoot,
		CreatePrivateDir:    createPrivateDirectory,
	}
}
