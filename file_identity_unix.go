//go:build !windows

package provider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/text/unicode/norm"
)

func platformFileIdentity(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("platform_file_identity_unavailable")
	}
	return fmt.Sprintf("unix:%d:%d", uint64(stat.Dev), uint64(stat.Ino)), nil
}

func catalogPathKey(path string) string {
	return norm.NFC.String(filepath.ToSlash(filepath.Clean(path)))
}
