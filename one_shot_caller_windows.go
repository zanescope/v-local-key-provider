//go:build windows

package provider

import (
	"errors"
	"os"

	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
)

func validateOneShotCaller(helperMode bool) error {
	if !releaseBuild() {
		return nil
	}
	if helperMode {
		return errors.New("Windows releases do not expose a helper one-shot entry point")
	}
	parentPath, err := daemonmodel.ProcessExecutablePath(uint32(os.Getppid()))
	if err != nil {
		return errors.New("one-shot caller process identity is unavailable")
	}
	if _, err := validateAcquisitionClientPath(parentPath); err != nil {
		return errors.New("one-shot caller is not the trusted CLI")
	}
	return nil
}
