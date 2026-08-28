//go:build darwin

package provider

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func livePrivateConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("macOS user home is unavailable")
	}
	return filepath.Join(home, "Library", "Application Support", "v-local", "live-regression-private", "config.json"), nil
}

func darwinLivePrivateObjectIsExclusive(path string, directory bool) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return false
	}
	wanted := os.FileMode(0o600)
	if directory {
		wanted = 0o700
	}
	if info.Mode().Perm() != wanted {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func readLivePrivateConfig() ([]byte, error) {
	path, err := livePrivateConfigPath()
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(filepath.Dir(path))
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		!darwinLivePrivateObjectIsExclusive(filepath.Dir(path), true) ||
		!darwinLivePrivateObjectIsExclusive(path, false) {
		return nil, errors.New("live private config path or permissions are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	original, originalErr := os.Lstat(path)
	if err != nil || originalErr != nil || !os.SameFile(opened, original) {
		return nil, errors.New("live private config identity changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, livePrivateConfigMaxBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > livePrivateConfigMaxBytes {
		return nil, errors.New("live private config cannot be read safely")
	}
	return payload, nil
}
