//go:build !windows && !darwin

package provider

import "errors"

func validateOneShotCaller(_ bool) error {
	if releaseBuild() {
		return errors.New("release one-shot caller verification is unavailable on this platform")
	}
	return nil
}
