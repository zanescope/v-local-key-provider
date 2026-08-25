//go:build !darwin

package provider

import "errors"

func delegateToPlatformHelper(payload []byte, remaining budget) (bool, string) {
	return false, "not_applicable"
}

func runPlatformElevatedHelperClient(address, token string) error {
	return errors.New("elevated helper transport is unavailable on this platform")
}
