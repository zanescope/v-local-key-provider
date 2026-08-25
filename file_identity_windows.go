//go:build windows

package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/text/unicode/norm"
)

func platformFileIdentity(file *os.File) (string, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("windows:%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func catalogPathKey(path string) string {
	return strings.ToLower(norm.NFC.String(filepath.ToSlash(filepath.Clean(path))))
}
