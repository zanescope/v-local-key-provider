//go:build qualification && !windows

package provider

import (
	"errors"
	"io"
)

func applyQualificationBootstrap(string) error {
	return errors.New("qualification 构建只支持 Windows")
}

func qualificationRegistryEnabled() bool {
	return false
}

func runQualificationCommand([]string, io.Reader, io.Writer) (bool, int) {
	return false, 0
}
