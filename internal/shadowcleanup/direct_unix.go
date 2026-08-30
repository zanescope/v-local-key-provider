//go:build !windows

// Package shadowcleanup provides exact, route-frozen cleanup primitives. It
// never discovers targets by name prefix or scans outside one bound root.
package shadowcleanup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	"golang.org/x/sys/unix"
)

func privateDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("direct cleanup parent must be absolute")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("direct cleanup parent is not an owner-only directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("direct cleanup parent owner is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("direct cleanup parent contains a symlink")
	}
	return path, nil
}

func openPrivateDirectory(path string) (string, int, error) {
	path, err := privateDirectory(path)
	if err != nil {
		return "", -1, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", -1, errors.New("direct cleanup parent identity is unavailable")
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return "", -1, errors.New("direct cleanup parent identity is unavailable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", -1, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(opened.Dev) != uint64(beforeStat.Dev) || uint64(opened.Ino) != uint64(beforeStat.Ino) ||
		opened.Uid != beforeStat.Uid || uint32(opened.Mode&0o777)&0o077 != 0 {
		_ = unix.Close(fd)
		return "", -1, errors.New("direct cleanup parent drifted while opening")
	}
	return path, fd, nil
}

func validLeaf(leaf string) bool {
	return leaf != "" && leaf != "." && leaf != ".." && filepath.Base(leaf) == leaf &&
		!strings.ContainsAny(leaf, "/\\\x00")
}

func bindingFromStat(kind, leaf string, stat *unix.Stat_t) (contract.ResourceBinding, error) {
	binding := contract.ResourceBinding{
		Kind: kind, Leaf: leaf, Device: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: stat.Uid,
		Mode: uint32(stat.Mode & 0o7777), LinkCount: uint64(stat.Nlink),
	}
	if err := binding.Validate(); err != nil {
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}

func BindDirectory(parent, leaf, kind string) (contract.ResourceBinding, error) {
	_, parentFD, err := openPrivateDirectory(parent)
	if err != nil || !validLeaf(leaf) || (kind != "container" && kind != "workspace" && kind != "clone_app") {
		if parentFD >= 0 {
			_ = unix.Close(parentFD)
		}
		return contract.ResourceBinding{}, errors.New("direct cleanup binding input is invalid")
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return contract.ResourceBinding{}, errors.New("direct cleanup target is not an ordinary directory")
	}
	return bindingFromStat(kind, leaf, &stat)
}

func CreateExactDirectory(ctx context.Context, parent, leaf, kind string) (contract.ResourceBinding, error) {
	_, parentFD, err := openPrivateDirectory(parent)
	if err != nil || ctx == nil || !validLeaf(leaf) ||
		(kind != "container" && kind != "workspace" && kind != "clone_app") {
		if parentFD >= 0 {
			_ = unix.Close(parentFD)
		}
		return contract.ResourceBinding{}, errors.New("direct cleanup create input is invalid")
	}
	if err := ctx.Err(); err != nil {
		return contract.ResourceBinding{}, err
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, leaf, 0o700); err != nil {
		return contract.ResourceBinding{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 {
		_ = unix.Unlinkat(parentFD, leaf, unix.AT_REMOVEDIR)
		return contract.ResourceBinding{}, errors.New("direct cleanup created directory identity is invalid")
	}
	binding, err := bindingFromStat(kind, leaf, &stat)
	if err != nil {
		_ = unix.Unlinkat(parentFD, leaf, unix.AT_REMOVEDIR)
		return contract.ResourceBinding{}, err
	}
	if err := unix.Fsync(parentFD); err != nil {
		_ = unix.Unlinkat(parentFD, leaf, unix.AT_REMOVEDIR)
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}

func sameBinding(stat *unix.Stat_t, binding contract.ResourceBinding) bool {
	return uint64(stat.Dev) == binding.Device && uint64(stat.Ino) == binding.Inode && stat.Uid == binding.UID &&
		uint32(stat.Mode&0o7777) == binding.Mode && stat.Mode&unix.S_IFMT == unix.S_IFDIR
}

func removeContents(ctx context.Context, directoryFD int, device uint64, uid uint32) error {
	file := os.NewFile(uintptr(directoryFD), "shadow-cleanup-directory")
	if file == nil {
		_ = unix.Close(directoryFD)
		return errors.New("direct cleanup directory descriptor is invalid")
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !validLeaf(name) {
			return errors.New("direct cleanup observed an unsafe child name")
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			uint64(stat.Dev) != device || stat.Uid != uid {
			return errors.New("direct cleanup child identity crossed its bound owner or device")
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			childFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			var opened unix.Stat_t
			if err := unix.Fstat(childFD, &opened); err != nil || opened.Dev != stat.Dev || opened.Ino != stat.Ino {
				_ = unix.Close(childFD)
				return errors.New("direct cleanup child changed before traversal")
			}
			if err := removeContents(ctx, childFD, device, uid); err != nil {
				return err
			}
			if err := unix.Unlinkat(directoryFD, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
			continue
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1 {
			return errors.New("direct cleanup refuses a hard-linked child")
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return err
		}
	}
	return nil
}

func RemoveExactDirectory(ctx context.Context, parent string, binding contract.ResourceBinding) error {
	_, parentFD, err := openPrivateDirectory(parent)
	if err != nil || ctx == nil || binding.Validate() != nil || !validLeaf(binding.Leaf) ||
		(binding.Kind != "container" && binding.Kind != "workspace" && binding.Kind != "clone_app") {
		if parentFD >= 0 {
			_ = unix.Close(parentFD)
		}
		return errors.New("direct cleanup exact target binding is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var before unix.Stat_t
	if err := unix.Fstatat(parentFD, binding.Leaf, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameBinding(&before, binding) {
		return errors.New("direct cleanup exact target identity drifted")
	}
	targetFD, err := unix.Openat(parentFD, binding.Leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(targetFD, &opened); err != nil || !sameBinding(&opened, binding) {
		_ = unix.Close(targetFD)
		return errors.New("direct cleanup opened a different target")
	}
	if err := removeContents(ctx, targetFD, binding.Device, binding.UID); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(parentFD, binding.Leaf, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameBinding(&after, binding) {
		return errors.New("direct cleanup target changed before final removal")
	}
	if err := unix.Unlinkat(parentFD, binding.Leaf, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := unix.Fstatat(parentFD, binding.Leaf, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("direct cleanup target absence was not proven")
	}
	return unix.Fsync(parentFD)
}

type Qualification struct {
	Route               string
	NestedRemoved       bool
	ReplacementRejected bool
}

func randomLeaf() (string, error) {
	payload := make([]byte, 12)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	return "synthetic-container-" + hex.EncodeToString(payload), nil
}

// QualifyDirect creates only a synthetic same-user directory tree under the
// supplied private test root. It does not touch an application container.
func QualifyDirect(ctx context.Context, parent string) (Qualification, error) {
	parent, err := privateDirectory(parent)
	if err != nil {
		return Qualification{}, err
	}
	leaf, err := randomLeaf()
	if err != nil {
		return Qualification{}, err
	}
	target := filepath.Join(parent, leaf)
	if err := os.Mkdir(target, 0o700); err != nil {
		return Qualification{}, err
	}
	defer func() {
		if current, bindErr := BindDirectory(parent, leaf, "container"); bindErr == nil {
			_ = RemoveExactDirectory(context.Background(), parent, current)
		}
	}()
	if err := os.Mkdir(filepath.Join(target, "nested"), 0o700); err != nil {
		return Qualification{}, err
	}
	if err := os.WriteFile(filepath.Join(target, "nested", "sentinel"), []byte("synthetic"), 0o600); err != nil {
		return Qualification{}, err
	}
	binding, err := BindDirectory(parent, leaf, "container")
	if err != nil {
		return Qualification{}, err
	}
	if err := RemoveExactDirectory(ctx, parent, binding); err != nil {
		return Qualification{}, err
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return Qualification{}, errors.New("synthetic direct cleanup left its target")
	}

	// Prove that the same leaf text cannot redirect cleanup after inode drift.
	if err := os.Mkdir(target, 0o700); err != nil {
		return Qualification{}, err
	}
	stale, err := BindDirectory(parent, leaf, "container")
	if err != nil {
		return Qualification{}, err
	}
	displaced := filepath.Join(parent, leaf+"-displaced")
	if err := os.Rename(target, displaced); err != nil {
		return Qualification{}, err
	}
	defer func() {
		if current, bindErr := BindDirectory(parent, filepath.Base(displaced), "container"); bindErr == nil {
			_ = RemoveExactDirectory(context.Background(), parent, current)
		}
	}()
	if err := os.Mkdir(target, 0o700); err != nil {
		return Qualification{}, err
	}
	if err := RemoveExactDirectory(ctx, parent, stale); err == nil {
		return Qualification{}, errors.New("direct cleanup accepted a replacement inode")
	}
	if _, err := os.Stat(target); err != nil {
		return Qualification{}, errors.New("direct cleanup damaged a replacement target")
	}
	return Qualification{Route: contract.CleanupRouteDirect, NestedRemoved: true, ReplacementRejected: true}, nil
}
