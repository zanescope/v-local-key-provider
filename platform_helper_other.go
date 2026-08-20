//go:build !darwin

package main

func delegateToPlatformHelper(payload []byte, remaining budget) (bool, string) {
	return false, "not_applicable"
}
