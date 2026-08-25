//go:build !windows

package provider

import (
	"errors"
	"os"
	"syscall"
)

func validateDaemonDirectorySecurity(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("daemon endpoint parent must be private to the current user")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("daemon endpoint parent owner does not match the current user")
	}
	return nil
}
