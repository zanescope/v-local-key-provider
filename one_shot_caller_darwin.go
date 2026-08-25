//go:build darwin

package provider

import (
	"errors"
	"os"
	"path/filepath"
)

func validateOneShotCaller(helperMode bool) error {
	if !releaseBuild() {
		return nil
	}
	parentPath, err := darwinProcessExecutablePath(os.Getppid())
	if err != nil {
		return errors.New("one-shot caller process identity is unavailable")
	}
	parentPath, err = filepathEvalCanonical(parentPath)
	if err != nil {
		return errors.New("one-shot caller path is unavailable")
	}
	if helperMode {
		helper, helperErr := os.Executable()
		if helperErr != nil {
			return helperErr
		}
		helper, helperErr = filepathEvalCanonical(helper)
		if helperErr != nil || filepath.Base(parentPath) != "v-local-key-provider" {
			return errors.New("helper one-shot caller is not the sibling Provider")
		}
		if err := validateDarwinComponentPair(parentPath, helper); err != nil {
			return errors.New("helper one-shot caller identity is invalid")
		}
		return nil
	}
	if _, err := validateAcquisitionClientPath(parentPath); err != nil {
		return errors.New("one-shot caller is not the trusted CLI")
	}
	return nil
}
