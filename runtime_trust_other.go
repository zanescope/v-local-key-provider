//go:build !darwin && !windows

package provider

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func validateRuntimeComponent(role string) error {
	if role == "helper" {
		return errors.New("helper entry point is unavailable on this platform")
	}
	return nil
}

func acquisitionDaemonRuntimeContext(advertisedProviderPath string) (bool, string, error) {
	if advertisedProviderPath != "" {
		return false, "", errors.New("helper daemon is unavailable on this platform")
	}
	return false, "", nil
}

func validateAcquisitionClientPath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return "", errors.New("daemon client path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("daemon client is not a regular file")
	}
	return resolved, nil
}
