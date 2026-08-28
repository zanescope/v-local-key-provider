//go:build !qualification

package provider

import "io"

func applyQualificationBootstrap(string) error {
	return nil
}

func qualificationRegistryEnabled() bool {
	return false
}

func runQualificationCommand([]string, io.Reader, io.Writer) (bool, int) {
	return false, 0
}
