//go:build !darwin && !windows

package provider

import "errors"

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
